import fs from 'node:fs'
import path from 'node:path'

import { parse } from 'jsonc-parser';

import Base_javascript from './base_javascript.js';

export default class Javascript_bun extends Base_javascript {

	_lockFileName() {
		return "bun.lock";
	}

	_cmdName() {
		return "bun";
	}

	_listCmdArgs() {
		throw new Error("not supported by Bun");
	}

	_updateLockFileCmdArgs() {
		return ['install', '--lockfile-only'];
	}

	_buildDependencyTree(includeTransitive, opts = {}) {
		this._version();
		const manifestDir = path.dirname(this._getManifest().manifestPath);
		const lockDir = this._findLockFileDir(manifestDir, opts) || manifestDir;
		this._createLockFile(lockDir);

		const lockContent = fs.readFileSync(path.join(lockDir, 'bun.lock'), 'utf-8');
		const lockData = parse(lockContent);

		const packages = lockData.packages || {};
		const memberName = this._getManifest().name;
		const workspaceEntry = this.#findWorkspaceEntry(lockData, lockDir, manifestDir, memberName);

		const directDeps = workspaceEntry?.dependencies || {};
		const tree = { name: memberName, version: this._getManifest().version, dependencies: {} };

		const visited = new Set();
		for (const depName of Object.keys(directDeps)) {
			const resolved = this.#resolvePackage(depName, '', packages);
			if (resolved) {
				tree.dependencies[depName] = this.#buildNode(depName, resolved, packages, includeTransitive, visited);
			}
		}

		return tree;
	}

	#findWorkspaceEntry(lockData, lockDir, manifestDir, memberName) {
		const workspaces = lockData.workspaces || {};
		const relPath = path.relative(lockDir, path.resolve(manifestDir));
		if (!relPath || relPath === '.') {
			return workspaces[''] || {};
		}
		const normalised = relPath.split(path.sep).join('/');
		if (workspaces[normalised]) {
			return workspaces[normalised];
		}
		for (const [wsPath, entry] of Object.entries(workspaces)) {
			if (entry.name === memberName && wsPath !== '') {
				return entry;
			}
		}
		return workspaces[''] || {};
	}

	#resolvePackage(depName, parentKey, packages) {
		if (parentKey) {
			const scopedKey = `${parentKey}/${depName}`;
			if (packages[scopedKey]) {
				return packages[scopedKey];
			}
		}
		return packages[depName] || null;
	}

	#buildNode(depName, resolved, packages, includeTransitive, visited) {
		const resolvedId = Array.isArray(resolved) ? resolved[0] : resolved;
		const version = this.#extractVersion(resolvedId);
		const node = { version };

		if (!includeTransitive) {
			return node;
		}

		const metadata = Array.isArray(resolved) ? (resolved[2] || {}) : {};
		const subDeps = metadata.dependencies || {};

		if (Object.keys(subDeps).length > 0) {
			const visitKey = `${depName}@${version}`;
			if (visited.has(visitKey)) {
				return node;
			}
			visited.add(visitKey);

			node.dependencies = {};
			for (const subName of Object.keys(subDeps)) {
				const subResolved = this.#resolvePackage(subName, depName, packages);
				if (subResolved) {
					node.dependencies[subName] = this.#buildNode(subName, subResolved, packages, true, visited);
				}
			}
		}

		return node;
	}

	#extractVersion(resolvedId) {
		if (typeof resolvedId !== 'string') {
			return '0.0.0';
		}
		const atIdx = resolvedId.lastIndexOf('@');
		if (atIdx > 0) {
			return resolvedId.substring(atIdx + 1);
		}
		return '0.0.0';
	}
}
