import fs from 'node:fs'
import path from 'node:path'

import fg from 'fast-glob'
import { load as yamlLoad } from 'js-yaml'
import micromatch from 'micromatch'

import { getCustom, getCustomPath, getGitRootDir, getWrapperPreference, invokeCommand } from './tools.js'

/** Default paths skipped during JS workspace discovery (merged with user patterns). */
const DEFAULT_WORKSPACE_DISCOVERY_IGNORE = [
	'**/node_modules/**',
	'**/.git/**',
	'**/target/**',
]

/**
 * Resolve ignore globs for workspace discovery: defaults + `TRUSTIFY_DA_WORKSPACE_DISCOVERY_IGNORE` + `opts.workspaceDiscoveryIgnore`.
 * Patterns are fast-glob / micromatch style, relative to the workspace root (forward slashes).
 *
 * @param {{ workspaceDiscoveryIgnore?: string[], TRUSTIFY_DA_WORKSPACE_DISCOVERY_IGNORE?: string, [key: string]: unknown }} [opts={}]
 * @returns {string[]}
 */
export function resolveWorkspaceDiscoveryIgnore(opts = {}) {
	const merged = [...DEFAULT_WORKSPACE_DISCOVERY_IGNORE]
	const fromEnv = getCustom('TRUSTIFY_DA_WORKSPACE_DISCOVERY_IGNORE', null, opts)
	if (fromEnv && String(fromEnv).trim()) {
		merged.push(...String(fromEnv).split(',').map(s => s.trim()).filter(Boolean))
	}
	const extra = opts.workspaceDiscoveryIgnore
	if (Array.isArray(extra)) {
		for (const p of extra) {
			if (typeof p === 'string' && p.trim()) {
				merged.push(p.trim())
			}
		}
	}
	return [...new Set(merged)]
}

/**
 * @param {string} root - Workspace root (absolute)
 * @param {string[]} ignorePatterns
 */
function buildWorkspaceDiscoveryGlobOptions(root, ignorePatterns) {
	return {
		cwd: root,
		absolute: true,
		onlyFiles: true,
		ignore: ignorePatterns,
		followSymbolicLinks: false,
	}
}

/**
 * @param {string} filePath - Absolute path
 * @param {string} root - Workspace root (absolute)
 * @returns {string} Relative path with forward slashes
 */
function relativePathForGlobMatch(filePath, root) {
	const rel = path.relative(root, filePath)
	return rel.split(path.sep).join('/')
}

/**
 * Drop manifest paths whose location matches an ignore pattern (e.g. root unshift, Cargo paths).
 *
 * @param {string[]} manifestPaths
 * @param {string} root
 * @param {string[]} ignorePatterns
 * @returns {string[]}
 */
export function filterManifestPathsByDiscoveryIgnore(manifestPaths, root, ignorePatterns) {
	if (!ignorePatterns.length) {
		return manifestPaths
	}
	const resolvedRoot = path.resolve(root)
	return manifestPaths.filter(absPath => {
		const rel = relativePathForGlobMatch(absPath, resolvedRoot)
		if (rel === '') {
			return true
		}
		return !ignorePatterns.some(pattern => micromatch.isMatch(rel, pattern, { dot: true }))
	})
}

/**
 * @typedef {{ valid: true, name: string, version: string } | { valid: false, error: string }} ValidatePackageJsonResult
 */

/**
 * Validate a package.json has non-empty `name` and `version` (required for stable SBOM root identity in batch).
 *
 * @param {string} packageJsonPath - Absolute or relative path to package.json
 * @returns {ValidatePackageJsonResult}
 */
export function validatePackageJson(packageJsonPath) {
	let content
	try {
		const raw = fs.readFileSync(packageJsonPath, 'utf-8')
		content = JSON.parse(raw)
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err)
		return { valid: false, error: `Invalid package.json: ${msg}` }
	}
	if (!content || typeof content !== 'object') {
		return { valid: false, error: 'package.json must be a JSON object' }
	}
	const name = content.name
	const version = content.version
	if (typeof name !== 'string' || !name.trim()) {
		return { valid: false, error: 'Missing or invalid name' }
	}
	if (typeof version !== 'string' || !version.trim()) {
		return { valid: false, error: 'Missing or invalid version' }
	}
	return { valid: true, name: name.trim(), version: version.trim() }
}

/**
 * Discover all package.json paths in a JS/TS workspace.
 * Reads pnpm-workspace.yaml or package.json workspaces.
 *
 * @param {string} workspaceRoot - Absolute or relative path to workspace root
 * @param {{ workspaceDiscoveryIgnore?: string[], TRUSTIFY_DA_WORKSPACE_DISCOVERY_IGNORE?: string, [key: string]: unknown }} [opts={}] - optional `workspaceDiscoveryIgnore` globs (merged with defaults and env)
 * @returns {Promise<string[]>} Paths to package.json files (absolute)
 */
export async function discoverWorkspacePackages(workspaceRoot, opts = {}) {
	const root = path.resolve(workspaceRoot)
	const ignorePatterns = resolveWorkspaceDiscoveryIgnore(opts)
	const globOpts = buildWorkspaceDiscoveryGlobOptions(root, ignorePatterns)
	const pnpmWorkspace = path.join(root, 'pnpm-workspace.yaml')
	const packageJson = path.join(root, 'package.json')

	if (fs.existsSync(pnpmWorkspace)) {
		return discoverFromPnpmWorkspace(root, pnpmWorkspace, globOpts, ignorePatterns)
	}
	if (fs.existsSync(packageJson)) {
		return discoverFromPackageJsonWorkspaces(root, packageJson, globOpts, ignorePatterns)
	}
	return []
}

/**
 * @param {string} root
 * @param {string} pnpmWorkspacePath
 * @param {object} globOpts - fast-glob options (cwd, ignore, followSymbolicLinks, …)
 * @param {string[]} ignorePatterns - for post-filter
 * @returns {Promise<string[]>}
 */
async function discoverFromPnpmWorkspace(root, pnpmWorkspacePath, globOpts, ignorePatterns) {
	const content = fs.readFileSync(pnpmWorkspacePath, 'utf-8')
	const packages = parsePnpmPackages(content)
	if (packages.length === 0) {
		return []
	}
	const patterns = toManifestGlobPatterns(packages, 'package.json')
	const manifestPaths = await fg(patterns, globOpts)
	return filterManifestPathsByDiscoveryIgnore(manifestPaths, root, ignorePatterns)
}

/**
 * Parse the `packages` array from pnpm-workspace.yaml content.
 * @param {string} content - Raw YAML content
 * @returns {string[]}
 */
function parsePnpmPackages(content) {
	let doc
	try {
		doc = yamlLoad(content)
	} catch {
		return []
	}
	if (!doc || typeof doc !== 'object' || !Array.isArray(doc.packages)) {
		return []
	}
	return doc.packages.filter(p => typeof p === 'string' && p.trim()).map(p => p.trim())
}

/**
 * Convert workspace glob patterns to manifest-file glob patterns,
 * correctly handling negation prefixes.
 *
 * @param {string[]} patterns - Workspace glob patterns (may include negations)
 * @param {string} manifestFileName - e.g. 'package.json' or 'Cargo.toml'
 * @returns {string[]}
 */
function toManifestGlobPatterns(patterns, manifestFileName) {
	return patterns.map(p => {
		if (p.startsWith('!')) {
			return `!${p.slice(1)}/${manifestFileName}`
		}
		return `${p}/${manifestFileName}`
	})
}

/**
 * @param {string} root
 * @param {string} packageJsonPath
 * @param {object} globOpts
 * @param {string[]} ignorePatterns
 * @returns {Promise<string[]>}
 */
async function discoverFromPackageJsonWorkspaces(root, packageJsonPath, globOpts, ignorePatterns) {
	let pkg
	try {
		pkg = JSON.parse(fs.readFileSync(packageJsonPath, 'utf-8'))
	} catch {
		return []
	}
	const workspaces = pkg.workspaces
	if (!workspaces) {
		return []
	}
	const raw = Array.isArray(workspaces) ? workspaces : workspaces.packages || []
	const patterns = toManifestGlobPatterns(raw.filter(p => typeof p === 'string'), 'package.json')
	if (patterns.length === 0) {
		return []
	}
	const manifestPaths = await fg(patterns, globOpts)
	const rootPkg = path.join(root, 'package.json')
	if (fs.existsSync(rootPkg) && !manifestPaths.includes(rootPkg)) {
		manifestPaths.unshift(rootPkg)
	}
	return filterManifestPathsByDiscoveryIgnore(manifestPaths, root, ignorePatterns)
}

/**
 * Resolve the Maven binary, respecting wrapper preference.
 *
 * When `TRUSTIFY_DA_PREFER_MVNW` is truthy, traverses from `startDir` up to the
 * git root (or filesystem root) looking for an executable `mvnw` wrapper.
 * Falls back to the global `mvn` binary (or `TRUSTIFY_DA_MVN_PATH`).
 *
 * @param {string} startDir - Directory from which to start the wrapper search
 * @param {import('./index.js').Options} [opts={}]
 * @returns {string} Path to the Maven binary
 */
function resolveMavenBinary(startDir, opts = {}) {
	const localWrapper = 'mvnw' + (process.platform === 'win32' ? '.cmd' : '')
	const useWrapper = getWrapperPreference('mvn', opts)
	if (useWrapper) {
		const wrapper = traverseForWrapper(startDir, localWrapper)
		if (wrapper !== undefined) {
			return wrapper
		}
	}
	return getCustomPath('mvn', opts)
}

/**
 * Walk up from `startDir` to `repoRoot` looking for an executable wrapper script.
 *
 * @param {string} startDir - Absolute directory to start from
 * @param {string} wrapperName - Wrapper filename (e.g. `mvnw`)
 * @param {string} [repoRoot] - Stop boundary (defaults to git root or filesystem root)
 * @returns {string | undefined}
 */
function traverseForWrapper(startDir, wrapperName, repoRoot = undefined) {
	const currentDir = path.resolve(startDir)
	repoRoot = repoRoot || getGitRootDir(currentDir) || path.parse(currentDir).root
	const wrapperPath = path.join(currentDir, wrapperName)

	try {
		fs.accessSync(wrapperPath, fs.constants.X_OK)
		return wrapperPath
	} catch (err) {
		if (err.code === 'ENOENT') {
			const rootDir = path.parse(currentDir).root
			if (currentDir === repoRoot || currentDir === rootDir) {
				return undefined
			}
			const parentDir = path.dirname(currentDir)
			if (parentDir === currentDir || parentDir === rootDir) {
				return undefined
			}
			return traverseForWrapper(parentDir, wrapperName, repoRoot)
		}
		throw new Error(`failure searching for ${wrapperName}`, { cause: err })
	}
}

/**
 * Discover all pom.xml manifest paths in a Maven multi-module project.
 * Uses `mvn help:evaluate` to read `project.modules`, then recurses into
 * nested aggregator modules.
 *
 * @param {string} workspaceRoot - Absolute or relative path to workspace root (must contain pom.xml)
 * @param {import('./index.js').Options} [opts={}]
 * @returns {Promise<string[]>} Paths to pom.xml files (absolute)
 */
export async function discoverMavenModules(workspaceRoot, opts = {}) {
	const root = path.resolve(workspaceRoot)
	const rootPom = path.join(root, 'pom.xml')

	if (!fs.existsSync(rootPom)) {
		return []
	}

	const mvnBin = resolveMavenBinary(root, opts)
	const visited = new Set()
	const manifestPaths = [rootPom]

	collectMavenModules(root, mvnBin, visited, manifestPaths)

	const ignorePatterns = resolveWorkspaceDiscoveryIgnore(opts)
	return filterManifestPathsByDiscoveryIgnore(manifestPaths, root, ignorePatterns)
}

/**
 * Recursively collect Maven module pom.xml paths starting from a given directory.
 *
 * @param {string} dir - Absolute path to directory containing pom.xml
 * @param {string} mvnBin - Maven binary path
 * @param {Set<string>} visited - Already-visited directories (cycle guard)
 * @param {string[]} manifestPaths - Accumulator for discovered pom.xml paths
 */
function collectMavenModules(dir, mvnBin, visited, manifestPaths) {
	const resolvedDir = path.resolve(dir)
	if (visited.has(resolvedDir)) {
		return
	}
	visited.add(resolvedDir)

	const modules = listMavenModules(resolvedDir, mvnBin)
	for (const mod of modules) {
		const moduleDir = path.resolve(resolvedDir, mod)
		const modulePom = path.join(moduleDir, 'pom.xml')
		if (fs.existsSync(modulePom)) {
			manifestPaths.push(modulePom)
			collectMavenModules(moduleDir, mvnBin, visited, manifestPaths)
		}
	}
}

/**
 * Invoke `mvn help:evaluate` to list the `<modules>` declared in a pom.xml.
 *
 * @param {string} dir - Directory containing pom.xml
 * @param {string} mvnBin - Maven binary path
 * @returns {string[]} Module directory names (relative to `dir`)
 */
function listMavenModules(dir, mvnBin) {
	let output
	try {
		output = invokeCommand(mvnBin, [
			'help:evaluate',
			'-Dexpression=project.modules',
			'-q',
			'-DforceStdout',
			'-f', path.join(dir, 'pom.xml'),
			'--batch-mode',
		], { cwd: dir })
	} catch {
		return []
	}

	const raw = output.toString().trim()
	if (!raw || raw === 'null') {
		return []
	}
	return parseMavenModuleList(raw)
}

/**
 * Parse the `[module-a, module-b]` output from `mvn help:evaluate -Dexpression=project.modules`.
 *
 * @param {string} raw - Raw stdout from mvn (e.g. `[module-a, module-b]`)
 * @returns {string[]}
 */
function parseMavenModuleList(raw) {
	const match = raw.match(/^\[(.+)]$/)
	if (!match) {
		return []
	}
	return match[1].split(',').map(s => s.trim()).filter(Boolean)
}

/**
 * Discover all Cargo.toml manifest paths in a Cargo workspace.
 * Uses `cargo metadata` to get workspace members.
 *
 * @param {string} workspaceRoot - Absolute or relative path to workspace root (must contain Cargo.toml and Cargo.lock)
 * @param {import('./index.js').Options} [opts={}]
 * @returns {Promise<string[]>} Paths to Cargo.toml files (absolute)
 */
export async function discoverWorkspaceCrates(workspaceRoot, opts = {}) {
	const root = path.resolve(workspaceRoot)
	const cargoToml = path.join(root, 'Cargo.toml')
	const cargoLock = path.join(root, 'Cargo.lock')

	if (!fs.existsSync(cargoToml) || !fs.existsSync(cargoLock)) {
		return []
	}

	const cargoBin = getCustomPath('cargo', opts)
	let output
	try {
		output = invokeCommand(cargoBin, ['metadata', '--format-version', '1', '--no-deps'], { cwd: root })
	} catch {
		return []
	}

	let metadata
	try {
		metadata = JSON.parse(output.toString().trim())
	} catch {
		return []
	}

	const memberIds = new Set(metadata.workspace_members || [])
	const manifestPaths = []
	for (const pkg of metadata.packages || []) {
		if (memberIds.has(pkg.id) && pkg.manifest_path) {
			const manifestPath = path.resolve(pkg.manifest_path)
			if (fs.existsSync(manifestPath)) {
				manifestPaths.push(manifestPath)
			}
		}
	}
	const ignorePatterns = resolveWorkspaceDiscoveryIgnore(opts)
	return filterManifestPathsByDiscoveryIgnore(manifestPaths, root, ignorePatterns)
}
