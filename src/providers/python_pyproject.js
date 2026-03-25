import fs from 'node:fs'
import path from 'node:path'

import { PackageURL } from 'packageurl-js'
import { parse as parseToml } from 'smol-toml'

import { getLicense } from '../license/license_utils.js'
import Sbom from '../sbom.js'
import { environmentVariableIsPopulated, getCustomPath, invokeCommand } from '../tools.js'

import { getParser, getPinnedVersionQuery } from './requirements_parser.js'

export default { isSupported, validateLockFile, provideComponent, provideStack, readLicenseFromManifest }

const ecosystem = 'pip'

const IGNORE_MARKERS = ['exhortignore', 'trustify-da-ignore']

const DEFAULT_ROOT_NAME = 'default-pip-root'
const DEFAULT_ROOT_VERSION = '0.0.0'

/**
 * @param {string} manifestName
 * @returns {boolean}
 */
function isSupported(manifestName) {
	return 'pyproject.toml' === manifestName
}

function validateLockFile() { return true }

/**
 * Read project license from pyproject.toml, with fallback to LICENSE file.
 * @param {string} manifestPath
 * @returns {string|null}
 */
function readLicenseFromManifest(manifestPath) {
	let fromManifest = null
	try {
		let content = fs.readFileSync(manifestPath, 'utf-8')
		let parsed = parseToml(content)
		fromManifest = parsed.project?.license
		if (typeof fromManifest === 'object' && fromManifest != null) {
			fromManifest = fromManifest.text || null
		}
		if (!fromManifest) {
			fromManifest = parsed.tool?.poetry?.license || null
		}
	} catch (_) {
		// leave fromManifest as null
	}
	return getLicense(fromManifest, manifestPath)
}

/**
 * Canonicalize a Python package name per PEP 503.
 * @param {string} name
 * @returns {string}
 */
function canonicalize(name) {
	return name.toLowerCase().replace(/[-_.]+/g, '-')
}

/** @typedef {'uv' | 'poetry'} Tool */

/**
 * Detect which tool manages this project.
 * @param {string} manifestDir
 * @param {object} parsed - parsed pyproject.toml
 * @returns {Tool|null}
 */
function detectTool(manifestDir, parsed) {
	let hasPoetry = !!(parsed.tool?.poetry)
	let uvLock = path.join(manifestDir, 'uv.lock')
	let poetryLock = path.join(manifestDir, 'poetry.lock')

	if (hasPoetry && fs.existsSync(poetryLock)) { return 'poetry' }
	if (fs.existsSync(uvLock)) { return 'uv' }
	if (fs.existsSync(poetryLock)) { return 'poetry' }

	return null
}

/**
 * Get the project name from pyproject.toml.
 * @param {object} parsed
 * @returns {string|null}
 */
function getProjectName(parsed) {
	return parsed.project?.name || parsed.tool?.poetry?.name || null
}

/**
 * Get the project version from pyproject.toml.
 * @param {object} parsed
 * @returns {string|null}
 */
function getProjectVersion(parsed) {
	return parsed.project?.version || parsed.tool?.poetry?.version || null
}

// --- uv support ---

/**
 * Get the uv export output, either from env var or by running the command.
 * @param {string} manifestDir
 * @param {import('index.js').Options} opts
 * @returns {string}
 */
function getUvExportOutput(manifestDir, opts) {
	if (environmentVariableIsPopulated('TRUSTIFY_DA_UV_EXPORT')) {
		return Buffer.from(process.env['TRUSTIFY_DA_UV_EXPORT'], 'base64').toString('ascii')
	}
	let uvBin = getCustomPath('uv', opts)
	return invokeCommand(uvBin, ['export', '--format', 'requirements.txt', '--frozen', '--no-hashes'], { cwd: manifestDir }).toString()
}

/**
 * Parse uv export output into a dependency graph using tree-sitter-requirements
 * for package/version extraction and string parsing for "# via" comments.
 *
 * @param {string} output
 * @param {string} projectName - canonical project name to identify direct deps
 * @returns {Promise<{directDeps: string[], graph: Map<string, {name: string, version: string, children: string[]}>}>}
 */
async function parseUvExport(output, projectName) {
	let [parser, pinnedVersionQuery] = await Promise.all([
		getParser(), getPinnedVersionQuery()
	])
	let tree = parser.parse(output)
	let root = tree.rootNode
	let canonProjectName = canonicalize(projectName)

	let packages = new Map() // canonical name -> {name, version, parents: Set}
	let currentPkg = null
	let collectingVia = false

	for (let child of root.children) {
		if (child.type === 'requirement') {
			let nameNode = child.children.find(c => c.type === 'package')
			if (!nameNode) { continue }

			let name = nameNode.text
			let version = null
			let versionMatches = pinnedVersionQuery.matches(child)
			if (versionMatches.length > 0) {
				version = versionMatches[0].captures.find(c => c.name === 'version').node.text
			}

			let key = canonicalize(name)
			currentPkg = { name, version, parents: new Set() }
			packages.set(key, currentPkg)
			collectingVia = false
			continue
		}

		if (child.type === 'comment' && currentPkg) {
			let text = child.text.trim()

			let viaSingle = text.match(/^# via ([A-Za-z0-9][A-Za-z0-9._-]*)$/)
			if (viaSingle) {
				currentPkg.parents.add(canonicalize(viaSingle[1]))
				collectingVia = false
				continue
			}

			if (text === '# via') {
				collectingVia = true
				continue
			}

			if (collectingVia) {
				let parentMatch = text.match(/^#\s+([A-Za-z0-9][A-Za-z0-9._-]*)$/)
				if (parentMatch) {
					currentPkg.parents.add(canonicalize(parentMatch[1]))
					continue
				}
				collectingVia = false
			}
		}
	}

	// Build forward dependency map and extract direct deps in one pass
	let graph = new Map()
	let directDeps = []

	for (let [key, pkg] of packages) {
		graph.set(key, { name: pkg.name, version: pkg.version, children: [] })
	}
	for (let [childKey, pkg] of packages) {
		for (let parentKey of pkg.parents) {
			if (parentKey === canonProjectName) {
				directDeps.push(childKey)
				continue
			}
			let parentEntry = graph.get(parentKey)
			if (parentEntry) {
				parentEntry.children.push(childKey)
			}
		}
	}

	return { directDeps, graph }
}

// --- poetry support ---

/**
 * Get poetry show --tree output.
 * @param {string} manifestDir
 * @param {import('index.js').Options} opts
 * @returns {string}
 */
function getPoetryShowTreeOutput(manifestDir, opts) {
	if (environmentVariableIsPopulated('TRUSTIFY_DA_POETRY_SHOW_TREE')) {
		return Buffer.from(process.env['TRUSTIFY_DA_POETRY_SHOW_TREE'], 'base64').toString('utf-8')
	}
	let poetryBin = getCustomPath('poetry', opts)
	return invokeCommand(poetryBin, ['show', '--tree', '--no-ansi'], { cwd: manifestDir }).toString()
}

/**
 * Get poetry show --all output (flat list with resolved versions).
 * @param {string} manifestDir
 * @param {import('index.js').Options} opts
 * @returns {string}
 */
function getPoetryShowAllOutput(manifestDir, opts) {
	if (environmentVariableIsPopulated('TRUSTIFY_DA_POETRY_SHOW_ALL')) {
		return Buffer.from(process.env['TRUSTIFY_DA_POETRY_SHOW_ALL'], 'base64').toString('utf-8')
	}
	let poetryBin = getCustomPath('poetry', opts)
	return invokeCommand(poetryBin, ['show', '--no-ansi', '--all'], { cwd: manifestDir }).toString()
}

/**
 * Parse poetry show --all output into a version map.
 * Lines look like: "name         (!) 1.2.3  Description text..."
 * or:              "name             1.2.3  Description text..."
 * @param {string} output
 * @returns {Map<string, string>} canonical name -> version
 */
function parsePoetryShowAll(output) {
	let versions = new Map()
	let lines = output.split(/\r?\n/)
	for (let line of lines) {
		let trimmed = line.trim()
		if (!trimmed) { continue }
		// match: name [(!)] version description...
		let match = trimmed.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s+(?:\(!\)\s+)?(\S+)/)
		if (match) {
			versions.set(canonicalize(match[1]), match[2])
		}
	}
	return versions
}

/**
 * Parse poetry show --tree output into a dependency graph structure.
 * Top-level lines (no indentation/tree chars) are direct deps: "name version description"
 * Indented lines are transitive deps with tree chars: "├── name >=constraint"
 *
 * @param {string} treeOutput
 * @param {Map<string, string>} versionMap - canonical name -> resolved version
 * @returns {{directDeps: string[], graph: Map<string, {name: string, version: string, children: string[]}>}}
 */
function parsePoetryTree(treeOutput, versionMap) {
	let lines = treeOutput.split(/\r?\n/)
	let graph = new Map()
	let directDeps = []

	// stack tracks the current parent at each depth
	let stack = [] // [{key, depth}]
	let currentDirectDep = null

	for (let line of lines) {
		if (!line.trim()) { continue }

		// top-level line: "name version description..."
		// these have no leading box-drawing chars or spaces
		let topMatch = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s+(\S+)\s/)
		if (topMatch) {
			let name = topMatch[1]
			let version = topMatch[2]
			let key = canonicalize(name)
			directDeps.push(key)
			if (!graph.has(key)) {
				graph.set(key, { name, version, children: [] })
			}
			currentDirectDep = key
			stack = [{ key, depth: -1 }]
			continue
		}

		if (!currentDirectDep) { continue }

		// indented line with tree chars (UTF-8 box-drawing: ├── └── │)
		// find the package name by looking for the first alphanumeric char
		let nameStart = line.search(/[A-Za-z0-9]/)
		if (nameStart < 0) { continue }

		let rest = line.substring(nameStart)
		let depMatch = rest.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/)
		if (!depMatch) { continue }

		let depName = depMatch[1]
		let depKey = canonicalize(depName)

		// determine depth from the prefix before the name
		// each tree level uses 4-char groups: "├── " / "└── " / "│   " / "    "
		let prefix = line.substring(0, nameStart)
		let depth = Math.max(1, Math.round(prefix.length / 4))

		// resolve version from the version map
		let version = versionMap.get(depKey) || null

		if (!graph.has(depKey)) {
			graph.set(depKey, { name: depName, version, children: [] })
		}

		// pop stack back to find the parent at depth-1
		while (stack.length > 0 && stack[stack.length - 1].depth >= depth) {
			stack.pop()
		}

		if (stack.length > 0) {
			let parentKey = stack[stack.length - 1].key
			let parentEntry = graph.get(parentKey)
			if (parentEntry && !parentEntry.children.includes(depKey)) {
				parentEntry.children.push(depKey)
			}
		}

		stack.push({ key: depKey, depth })
	}

	return { directDeps, graph }
}

// --- ignore markers ---

/**
 * Scan raw pyproject.toml text for dependencies with ignore markers.
 * Returns a Set of canonicalized dependency names.
 * @param {string} manifestPath
 * @returns {Set<string>}
 */
function getIgnoredDeps(manifestPath) {
	let ignored = new Set()
	let content = fs.readFileSync(manifestPath, 'utf-8')
	let lines = content.split(/\r?\n/)

	for (let line of lines) {
		if (!IGNORE_MARKERS.some(m => line.includes(m))) { continue }

		// PEP 621 style: "requests>=2.25" #exhortignore
		let pep621Match = line.match(/^\s*"([^"]+)"/)
		if (pep621Match) {
			let reqStr = pep621Match[1]
			let nameMatch = reqStr.match(/^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)/)
			if (nameMatch) {
				ignored.add(canonicalize(nameMatch[1]))
			}
			continue
		}

		// Poetry style: requests = "^2.25" #exhortignore
		let poetryMatch = line.match(/^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=/)
		if (poetryMatch) {
			ignored.add(canonicalize(poetryMatch[1]))
		}
	}

	return ignored
}

// --- tree building and SBOM ---

/**
 * Build dependency tree from graph, starting from direct deps.
 * @param {Map} graph - name -> {name, version, children: string[]}
 * @param {string[]} directDeps - canonical names of direct deps
 * @param {Set<string>} ignoredDeps
 * @param {boolean} includeTransitive
 * @returns {{name: string, version: string, dependencies: object[]}[]}
 */
function buildDependencyTree(graph, directDeps, ignoredDeps, includeTransitive) {
	let result = []

	for (let key of directDeps) {
		if (ignoredDeps.has(key)) { continue }

		let entry = graph.get(key)
		if (!entry) { continue }

		let depTree = []
		if (includeTransitive) {
			let visited = new Set()
			visited.add(key)
			collectTransitive(graph, entry.children, depTree, ignoredDeps, visited)
		}

		result.push({ name: entry.name, version: entry.version, dependencies: depTree })
	}

	result.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()))
	return result
}

/**
 * Recursively collect transitive dependencies.
 */
function collectTransitive(graph, childKeys, result, ignoredDeps, visited) {
	for (let childKey of childKeys) {
		let canonKey = canonicalize(childKey)
		if (ignoredDeps.has(canonKey)) { continue }
		if (visited.has(canonKey)) { continue }
		visited.add(canonKey)

		let entry = graph.get(canonKey)
		if (!entry) { continue }

		let childDeps = []
		collectTransitive(graph, entry.children, childDeps, ignoredDeps, visited)

		result.push({ name: entry.name, version: entry.version, dependencies: childDeps })
	}

	result.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()))
}

function toPurl(name, version) {
	return new PackageURL('pypi', undefined, name, version, undefined, undefined)
}

function addAllDependencies(source, dep, sbom) {
	let targetPurl = toPurl(dep.name, dep.version)
	sbom.addDependency(source, targetPurl)
	if (dep.dependencies && dep.dependencies.length > 0) {
		dep.dependencies.forEach(child => addAllDependencies(toPurl(dep.name, dep.version), child, sbom))
	}
}

/**
 * @param {string} manifest - path to pyproject.toml
 * @param {import('index.js').Options} [opts={}]
 * @returns {Promise<Provided>}
 */
async function provideStack(manifest, opts = {}) {
	return {
		ecosystem,
		content: await createSbom(manifest, opts, true),
		contentType: 'application/vnd.cyclonedx+json'
	}
}

/**
 * @param {string} manifest - path to pyproject.toml
 * @param {import('index.js').Options} [opts={}]
 * @returns {Promise<Provided>}
 */
async function provideComponent(manifest, opts = {}) {
	return {
		ecosystem,
		content: await createSbom(manifest, opts, false),
		contentType: 'application/vnd.cyclonedx+json'
	}
}

/**
 * Create SBOM json string for a pyproject.toml project.
 * @param {string} manifest - path to pyproject.toml
 * @param {import('index.js').Options} opts
 * @param {boolean} includeTransitive
 * @returns {Promise<string>}
 */
async function createSbom(manifest, opts, includeTransitive) {
	let manifestDir = path.dirname(manifest)
	let content = fs.readFileSync(manifest, 'utf-8')
	let parsed = parseToml(content)

	let tool = detectTool(manifestDir, parsed)
	if (!tool) {
		throw new Error('pyproject.toml requires a lock file (poetry.lock or uv.lock) in the same directory')
	}

	let directDeps
	let graph
	let projectName = getProjectName(parsed)

	if (tool === 'uv') {
		let uvOutput = getUvExportOutput(manifestDir, opts)
		let result = await parseUvExport(uvOutput, projectName)
		directDeps = result.directDeps
		graph = result.graph
	} else {
		let treeOutput = getPoetryShowTreeOutput(manifestDir, opts)
		let showAllOutput = getPoetryShowAllOutput(manifestDir, opts)
		let versionMap = parsePoetryShowAll(showAllOutput)
		let result = parsePoetryTree(treeOutput, versionMap)
		directDeps = result.directDeps
		graph = result.graph
	}

	let ignoredDeps = getIgnoredDeps(manifest)
	let dependencies = buildDependencyTree(graph, directDeps, ignoredDeps, includeTransitive)

	let sbom = new Sbom()
	let rootName = projectName || DEFAULT_ROOT_NAME
	let rootVersion = getProjectVersion(parsed) || DEFAULT_ROOT_VERSION
	let rootPurl = toPurl(rootName, rootVersion)
	let license = readLicenseFromManifest(manifest)
	sbom.addRoot(rootPurl, license)

	dependencies.forEach(dep => {
		if (includeTransitive) {
			addAllDependencies(rootPurl, dep, sbom)
		} else {
			sbom.addDependency(rootPurl, toPurl(dep.name, dep.version))
		}
	})

	return sbom.getAsJsonString(opts)
}
