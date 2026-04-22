import Base_javascript from './base_javascript.js';

export default class Javascript_pnpm extends Base_javascript {

	_lockFileName() {
		return "pnpm-lock.yaml";
	}

	_cmdName() {
		return "pnpm";
	}

	_listCmdArgs(includeTransitive) {
		return ['ls', includeTransitive ? '--depth=Infinity' : '--depth=0', '--prod', '--json', '-r'];
	}

	_updateLockFileCmdArgs() {
		return ['install', '--frozen-lockfile'];
	}

	_buildDependencyTree(includeTransitive, opts = {}) {
		// pnpm ls --json returns an array with one entry per workspace package.
		// When analyzing a workspace member, find its entry by name instead of
		// blindly taking the first element (which is the workspace root).
		const tree = super._buildDependencyTree(includeTransitive, opts);
		if (Array.isArray(tree) && tree.length > 0) {
			const memberName = this._getManifest().name;
			return tree.find(pkg => pkg.name === memberName) || tree[0];
		}
		return {};
	}

}
