import Base_javascript from './base_javascript.js';

export default class Javascript_pnpm extends Base_javascript {

	_lockFileName() {
		return "pnpm-lock.yaml";
	}

	_cmdName() {
		return "pnpm";
	}

	_listCmdArgs(includeTransitive) {
		return ['ls', includeTransitive ? '--depth=Infinity' : '--depth=0', '--prod', '--json'];
	}

	_updateLockFileCmdArgs() {
		return ['install', '--frozen-lockfile'];
	}

	_buildDependencyTree(includeTransitive, opts = {}) {
		const tree = super._buildDependencyTree(includeTransitive, opts);
		if (Array.isArray(tree) && tree.length > 0) {
			const memberName = this._getManifest().name;
			return tree.find(pkg => pkg.name === memberName) || tree[0];
		}
		return {};
	}

}
