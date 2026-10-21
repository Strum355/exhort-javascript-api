import fs from 'node:fs';
import path from 'node:path';

import Base_javascript, { sriToHash } from './base_javascript.js';
import { readPnpmGraph, readPnpmLock } from './javascript_lockfile.js';

export default class Javascript_pnpm extends Base_javascript {

	_lockFileName() {
		return "pnpm-lock.yaml";
	}

	_cmdName() {
		return "pnpm";
	}

	/** Initializes the provider without resolving the pnpm executable. */
	_setUp(manifestPath) {
		this._setUpManifest(manifestPath);
	}

	/**
	 * Parses `pnpm-lock.yaml` into a hash map keyed by `name@version`. Entries in
	 * the `packages` section are keyed by `[/]<name>@<version>` (optionally
	 * followed by a `(peer@x)` suffix); the `resolution.integrity` field holds an
	 * SRI string. Handles lockfileVersion 6 (leading-slash keys) and 9, including
	 * multi-document streams (see {@link readPnpmLock}).
	 * @param {string} lockDir - Directory containing pnpm-lock.yaml
	 * @returns {Map<string, Array<{alg: string, content: string}>>} Hash map
	 * @protected
	 */
	_parseLockFileHashes(lockDir) {
		const map = new Map();
		const lockPath = path.join(lockDir, this._lockFileName());
		if (!fs.existsSync(lockPath)) {
			return map;
		}
		let lock;
		try {
			lock = readPnpmLock(lockPath);
		} catch (_) {
			return map;
		}
		const packages = lock?.packages || {};
		for (const [key, entry] of Object.entries(packages)) {
			const integrity = entry?.resolution?.integrity;
			if (!key || !integrity) {
				continue;
			}
			// Strip the v6 leading slash and any peer-dependency suffix, then split
			// name from version.
			const bare = key.startsWith('/') ? key.slice(1) : key;
			const base = bare.split('(')[0];
			const at = base.indexOf('@', 1);
			const name = entry.name ?? (at > 0 ? base.slice(0, at) : undefined);
			const version = entry.version ?? (at > 0 ? base.slice(at + 1) : undefined);
			const hash = sriToHash(integrity);
			if (name && version && hash) {
				map.set(`${name}@${version}`, [hash]);
			}
		}
		return map;
	}

	/**
	 * Builds the dependency graph directly from `pnpm-lock.yaml`, requiring a
	 * pre-existing lockfile and invoking no package manager.
	 * @param {boolean} _includeTransitive - Unused; the full graph is always read
	 * @param {Object} [opts={}] - Configuration options (may set the workspace dir)
	 * @returns {import('./javascript_lockfile.js').LockGraph} The dependency graph
	 * @protected
	 */
	_buildDependencyTree(_includeTransitive, opts = {}) {
		const manifest = this._getManifest();
		const lockDir = this._findLockFileDir(path.dirname(manifest.manifestPath), opts);
		if (!lockDir) {
			throw new Error('pnpm analysis requires a lockfile. Generate pnpm-lock.yaml before scanning.');
		}
		const lock = readPnpmLock(path.join(lockDir, this._lockFileName()));
		const graph = readPnpmGraph(lockDir, manifest.manifestPath, manifest.content, lock);
		this._loadHashes(lockDir);
		return graph;
	}

}
