import fs from 'node:fs'
import path from 'node:path'

import analysis from './analysis.js'
import { availableProviders, match } from './provider.js'
import { extractRemediations } from './remediation.js'
import { updateMavenVersions } from './updaters/maven_updater.js'
import { updateTomlVersions } from './updaters/toml_updater.js'

import { selectTrustifyDABackend } from './index.js'

// Mirrors DEFAULT_WORKSPACE_DISCOVERY_IGNORE in workspace.js
const SKIP_DIRS = new Set(['node_modules', '.git'])

const MANIFEST_TYPES = [
	{
		test: (basename) => basename === 'pom.xml',
		updater: updateMavenVersions,
		label: 'maven',
	},
	{
		test: (basename) => basename.endsWith('.versions.toml') || basename === 'libs.versions.toml',
		updater: updateTomlVersions,
		label: 'toml',
	},
]

/**
 * An isolated, single-dependency edit to one manifest file.
 * - `after` is the *original* manifest content with only this dependency's fix applied, so a caller
 *   can create an isolated commit by writing `after` to `path` on a branch cut from the base.
 * - `changeKey` is a stable identifier for the underlying edit site. Two remediations that share a
 *   `changeKey` are inseparable (e.g. two Maven deps whose versions resolve to the same `${property}`,
 *   or two Gradle libraries sharing one `version.ref`) and MUST land in the same commit/PR — the
 *   caller should union their CVEs/advisories.
 * @typedef {{ path: string, after: string, changeKey: string }} Change
 */

/**
 * A single applicable remediation, as produced by `extractRemediations` and enriched by
 * `runRemediation` with the originating manifest path(s) and (optionally) per-dependency changes.
 * @typedef {{
 *   purl: string,
 *   groupId: string,
 *   artifactId: string,
 *   currentVersion: string,
 *   fixedInVersion: string,
 *   fixedInPurl: string,
 *   provider: string,
 *   source: string,
 *   advisories: Array<{id: string, url: string}>,
 *   severity: string,
 *   cves: string[],
 *   files: string[],
 *   changes?: Change[]
 * }} Remediation
 */

/**
 * Builds a stable edit-site key for an applied change, so callers can detect inseparable
 * remediations (same key => same commit/PR).
 * @param {string} label - manifest type label (`'maven'` | `'toml'`)
 * @param {string} manifestPath - the manifest the change targets
 * @param {object} applied - the updater's `applied[0]` entry for a single-dependency call
 * @returns {string}
 */
function deriveChangeKey(label, manifestPath, applied) {
	if (label === 'maven') {
		return applied.type === 'property'
			? `mvn:prop:${manifestPath}:${applied.property}`
			: `mvn:direct:${manifestPath}:${applied.groupId}:${applied.artifactId}`
	}
	if (label === 'toml') {
		return applied.type === 'ref'
			? `toml:ref:${manifestPath}:${applied.versionRef}`
			: `toml:inline:${manifestPath}:${applied.alias}`
	}
	throw new Error(`Cannot derive change key for unknown manifest label: ${label}`)
}

/**
 * Returns the manifest type descriptor for a given filename, or null if unsupported.
 * @param {string} basename - the file name to check
 * @returns {{test: function, updater: function, label: string}|null}
 */
function getManifestType(basename) {
	return MANIFEST_TYPES.find(t => t.test(basename)) || null
}

/**
 * Resolves a target path to the supported manifest files it contains: the single file
 * if `targetPath` is a supported manifest, or every supported manifest discovered
 * recursively if it's a directory. This is the single source of truth for what
 * `runRemediation` will scan, so callers (e.g. the CLI) can reuse it to tell
 * "no manifests here" apart from "manifests, but nothing to fix".
 * @param {string} targetPath - path to a manifest file or directory
 * @returns {string[]} absolute paths to supported manifests (empty for an empty directory)
 * @throws if the path does not exist, or is a file of an unsupported manifest type
 */
export function findManifests(targetPath) {
	const resolvedPath = path.resolve(targetPath)

	let stat
	try {
		stat = fs.statSync(resolvedPath)
	} catch {
		throw new Error(`Path not found: ${resolvedPath}`)
	}

	// A single file must itself be a supported manifest.
	if (!stat.isDirectory()) {
		const basename = path.basename(resolvedPath)
		if (!getManifestType(basename)) {
			throw new Error(`Unsupported manifest type: ${basename}`)
		}
		return [resolvedPath]
	}

	// A directory yields every supported manifest found recursively beneath it.
	const manifests = []
	function walk(dir) {
		for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
			if (SKIP_DIRS.has(entry.name)) {
				continue
			}
			const fullPath = path.join(dir, entry.name)
			if (entry.isDirectory()) {
				walk(fullPath)
			} else if (getManifestType(entry.name)) {
				manifests.push(fullPath)
			}
		}
	}
	walk(resolvedPath)
	return manifests
}

/**
 * Orchestrates the full remediation pipeline for a single manifest or directory:
 * discover manifests → scan via DA backend → extract remediations → apply or preview.
 *
 * @param {string} targetPath - path to a manifest file or directory
 * @param {object} [options]
 * @param {boolean} [options.dryRun=false] - preview changes without modifying files (applies by default)
 * @param {string} [options.providers] - comma-separated provider list
 * @param {string} [options.sources] - comma-separated source list
 * @param {boolean} [options.perDependencyChanges=false] - when true, each remediation is populated with
 *   a `changes` array describing the isolated, single-dependency edit (see {@link Change}). This lets
 *   callers create one commit/PR per dependency without attributing diff hunks themselves.
 * @returns {Promise<{exitCode: number, remediations: Remediation[], manifests: string[]}>} exitCode is 2 for a dry-run that
 *   found remediations (nothing written), 0 otherwise. `remediations` is the structured, per-manifest
 *   list of applicable updates — each entry carries the originating manifest path(s) in `files` so
 *   callers can group and create per-dependency changes.
 */
export async function runRemediation(targetPath, options = {}) {
	const { dryRun = false, providers, sources, perDependencyChanges = false } = options

	const manifestPaths = findManifests(targetPath)
	if (manifestPaths.length === 0) {
		return { exitCode: 0, remediations: [], manifests: manifestPaths }
	}

	const opts = {}
	if (providers) {
		opts.TRUSTIFY_DA_PROVIDERS = providers
	}
	if (sources) {
		opts.TRUSTIFY_DA_SOURCES = sources
	}

	const url = selectTrustifyDABackend(opts)
	const allRemediations = []

	for (const manifestPath of manifestPaths) {
		const basename = path.basename(manifestPath)
		const manifestType = getManifestType(basename)
		if (!manifestType) {
			continue
		}

		let provider
		try {
			provider = match(manifestPath, availableProviders, opts)
		} catch {
			continue
		}

		const analysisReport = await analysis.requestStack(provider, manifestPath, url, false, opts)
		const remediations = extractRemediations(analysisReport, {
			providerPriority: providers ? providers.split(',').map(p => p.trim()).filter(Boolean) : undefined,
		})

		if (remediations.length === 0) {
			continue
		}

		// Tag each remediation with the manifest it came from so callers can group
		// changes per dependency across a multi-manifest workspace.
		for (const remediation of remediations) {
			remediation.files = [manifestPath]
		}

		// Read the pristine manifest once. Both the atomic apply and the per-dependency
		// change computation must diff against the *original* content.
		const needsContent = perDependencyChanges || !dryRun
		const originalContent = needsContent ? fs.readFileSync(manifestPath, 'utf-8') : null

		if (perDependencyChanges) {
			for (const remediation of remediations) {
				const isolated = manifestType.updater(originalContent, [{
					groupId: remediation.groupId,
					artifactId: remediation.artifactId,
					newVersion: remediation.fixedInVersion,
				}])
				if (isolated.applied.length === 0) {
					// Dependency not found, already at target, or otherwise unchangeable:
					// emit no change so the caller creates no PR for it.
					continue
				}
				remediation.changes = [{
					path: manifestPath,
					after: isolated.content,
					changeKey: deriveChangeKey(manifestType.label, manifestPath, isolated.applied[0]),
				}]
			}
		}

		allRemediations.push(...remediations)

		if (!dryRun) {
			// Disk receives the union of every dependency's fix. When
			// perDependencyChanges is also set, each remediation's `changes[].after`
			// deliberately stays isolated (single-dep) for branch-per-dep workflows.
			const result = manifestType.updater(originalContent, remediations.map(r => ({
				groupId: r.groupId,
				artifactId: r.artifactId,
				newVersion: r.fixedInVersion,
			})))
			if (result.applied.length > 0) {
				fs.writeFileSync(manifestPath, result.content, 'utf-8')
			}
		}
	}

	if (allRemediations.length === 0) {
		return { exitCode: 0, remediations: [], manifests: manifestPaths }
	}

	// Dry-run signals "changes available but not written" via exit code 2.
	return { exitCode: dryRun ? 2 : 0, remediations: allRemediations, manifests: manifestPaths }
}
