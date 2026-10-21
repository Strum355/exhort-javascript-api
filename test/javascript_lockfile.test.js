import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { expect } from 'chai';
import esmock from 'esmock';
import { load as yamlLoad } from 'js-yaml';
import { useFakeTimers } from 'sinon';

import { getPackageVersion } from '../src/package_version.js';
import Npm from '../src/providers/javascript_npm.js';
import Pnpm from '../src/providers/javascript_pnpm.js';
import Yarn from '../src/providers/javascript_yarn.js';

const MANAGERS = ['npm', 'pnpm', 'yarn-classic', 'yarn-berry'];
const SBOM_CASES = [
	{ method: 'provideStack', type: 'stack' },
	{ method: 'provideComponent', type: 'component' },
];

function canonical(sbom) {
	const data = typeof sbom === 'string' ? JSON.parse(sbom) : structuredClone(sbom);
	data.components.sort((a, b) => a.purl.localeCompare(b.purl));
	data.dependencies?.forEach(dep => dep.dependsOn.sort());
	data.dependencies?.sort((a, b) => a.ref.localeCompare(b.ref));
	return data;
}

function snapshot(dir) {
	return fs.readdirSync(dir, { recursive: true }).sort().map(file => {
		const full = path.join(dir, file);
		return [file, fs.statSync(full).isDirectory() ? null : fs.readFileSync(full).toString('base64')];
	});
}

suite('read-only JavaScript lockfile analysis', () => {
	let root;
	setup(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'javascript-lockfile-')); });
	teardown(() => { fs.rmSync(root, { recursive: true, force: true }); });

	function fixture(manager, manifest = { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' } },
		packages = { alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } }, shared: { version: '1.0.0' } }) {
		const manifestPath = path.join(root, 'package.json');
		fs.writeFileSync(manifestPath, JSON.stringify(manifest));
		let lock;
		if (manager === 'npm') {
			lock = { lockfileVersion: 3, packages: { '': manifest } };
			for (const [name, entry] of Object.entries(packages)) { lock.packages[`node_modules/${name}`] = entry; }
		} else if (manager === 'yarn-classic') {
			lock = {};
			for (const [name, entry] of Object.entries(packages)) { lock[`${name}@^1.0.0`] = entry; }
		} else if (manager === 'pnpm') {
			const importer = {};
			for (const section of ['dependencies', 'devDependencies', 'optionalDependencies']) {
				const group = {};
				for (const [name, spec] of Object.entries(manifest[section] ?? {})) {
					if (packages[name]) { group[name] = { specifier: spec, version: packages[name].version }; }
				}
				if (Object.keys(group).length) { importer[section] = group; }
			}
			// JSON is valid YAML, so the lockfile can be serialized the same way as
			// the other managers; the parser reads it via js-yaml loadAll.
			lock = { lockfileVersion: '9.0', importers: { '.': importer }, packages: {}, snapshots: {} };
			for (const [name, entry] of Object.entries(packages)) {
				const key = `${name}@${entry.version}`;
				lock.packages[key] = { resolution: entry.integrity ? { integrity: entry.integrity } : {} };
				const deps = Object.fromEntries(Object.entries(entry.dependencies ?? {})
					.map(([dep, spec]) => [dep, packages[dep]?.version ?? (spec.replace(/^\D+/, '') || '0.0.0')]));
				lock.snapshots[key] = Object.keys(deps).length ? { dependencies: deps } : {};
			}
		} else {
			lock = { __metadata: { version: 8 }, [`${manifest.name}@workspace:.`]: {
				version: '0.0.0-use.local', resolution: `${manifest.name}@workspace:.`,
				dependencies: Object.fromEntries(Object.entries({ ...manifest.devDependencies, ...manifest.dependencies, ...manifest.optionalDependencies }).map(([name, spec]) => [name, /^[a-z]+:/.test(spec) ? spec : `npm:${spec}`])),
				...(manifest.peerDependencies ? { peerDependencies: manifest.peerDependencies } : {}),
			} };
			for (const [name, entry] of Object.entries(packages)) {
				lock[`${name}@npm:^1.0.0`] = { ...entry, resolution: `${name}@npm:${entry.version}` };
			}
		}
		const lockPath = path.join(root, manager === 'npm' ? 'package-lock.json' : manager === 'pnpm' ? 'pnpm-lock.yaml' : 'yarn.lock');
		fs.writeFileSync(lockPath, JSON.stringify(lock));
		return { manifestPath, lockPath, manifest, lock, provider: manager === 'npm' ? new Npm() : manager === 'pnpm' ? new Pnpm() : new Yarn() };
	}

	function result(test, method = 'provideStack') {
		return JSON.parse(test.provider[method](test.manifestPath).content);
	}

	function edge(sbom, from, to) {
		return sbom.dependencies.find(dep => dep.ref === `pkg:npm/${from}`)?.dependsOn.includes(`pkg:npm/${to}`);
	}

	function pnpmWorkspaceFixture() {
		const test = fixture('pnpm', { name: 'root', version: '1.0.0', private: true });
		fs.writeFileSync(path.join(root, 'pnpm-workspace.yaml'), 'packages:\n  - packages/*\n');
		const app = { name: 'app', version: '1.0.0', dependencies: { '@example/lib': 'workspace:*' } };
		const lib = { name: '@example/lib', version: '2.3.4', dependencies: { alpha: '^1.0.0', util: 'workspace:*' } };
		const util = { name: 'util', version: '5.6.7', dependencies: { '@example/lib': 'workspace:*' } };
		for (const [location, data] of [['app', app], ['lib', lib], ['util', util]]) {
			fs.mkdirSync(path.join(root, 'packages', location), { recursive: true });
			fs.writeFileSync(path.join(root, 'packages', location, 'package.json'), JSON.stringify(data));
		}
		test.lock.importers['packages/app'] = { dependencies: { '@example/lib': { specifier: 'workspace:*', version: 'link:../lib' } } };
		test.lock.importers['packages/lib'] = { dependencies: {
			alpha: { specifier: '^1.0.0', version: '1.0.0' }, util: { specifier: 'workspace:*', version: 'link:../util' },
		} };
		test.lock.importers['packages/util'] = { dependencies: { '@example/lib': { specifier: 'workspace:*', version: 'link:../lib' } } };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		test.manifestPath = path.join(root, 'packages', 'app', 'package.json');
		return { ...test, lib, libPath: path.join(root, 'packages', 'lib', 'package.json') };
	}

	for (const manager of MANAGERS) {
		for (const { method } of SBOM_CASES) {
			test(`${manager} ${method} makes no subprocess calls and changes no project files`, async () => {
				const test = fixture(manager);
				fs.mkdirSync(path.join(root, 'node_modules', 'alpha'), { recursive: true });
				fs.writeFileSync(path.join(root, 'node_modules', 'alpha', 'package.json'), '{"version":"99.0.0"}');
				fs.writeFileSync(path.join(root, '.yarnrc.yml'), 'nodeLinker: node-modules\n');
				fs.writeFileSync(path.join(root, '.npmrc'), 'ignore-scripts=true\n');
				const before = snapshot(root);
				const fail = () => { throw new Error('Unexpected subprocess invocation'); };
				const Provider = await esmock(`../src/providers/javascript_${manager === 'npm' ? 'npm' : manager === 'pnpm' ? 'pnpm' : 'yarn'}.js`, {}, {
					'../src/tools.js': { invokeCommand: fail },
					child_process: { execFileSync: fail, spawnSync: fail },
				});
				const savedPath = process.env.PATH;
				const savedPin = process.env.COREPACK_ENABLE_AUTO_PIN;
				process.env.PATH = '/no-package-managers';
				process.env.COREPACK_ENABLE_AUTO_PIN = '1';
				try {
					const provided = new Provider()[method](test.manifestPath, { TRUSTIFY_DA_YARN_PATH: '../invalid', TRUSTIFY_DA_NPM_PATH: '' });
					expect(JSON.parse(provided.content).components.some(c => c.purl === 'pkg:npm/alpha@1.0.0')).to.be.true;
					// pnpm reports the generic npm ecosystem, like npm itself.
					expect(provided.ecosystem).to.equal(manager === 'npm' || manager === 'pnpm' ? 'npm' : manager);
					expect(snapshot(root)).to.deep.equal(before);
					expect(process.env.COREPACK_ENABLE_AUTO_PIN).to.equal('1');
				} finally {
					if (savedPath === undefined) { delete process.env.PATH; } else { process.env.PATH = savedPath; }
					if (savedPin === undefined) { delete process.env.COREPACK_ENABLE_AUTO_PIN; } else { process.env.COREPACK_ENABLE_AUTO_PIN = savedPin; }
				}
			});

			test(`${manager} ${method} rejects changed declarations without writing files`, () => {
				const test = fixture(manager);
				test.manifest.dependencies.alpha = '^2.0.0';
				fs.writeFileSync(test.manifestPath, JSON.stringify(test.manifest));
				const before = snapshot(root);
				expect(() => result(test, method)).to.throw(/Lockfile is out of date.*alpha/);
				expect(snapshot(root)).to.deep.equal(before);
			});
		}

		test(`${manager} emits direct versus transitive edges`, () => {
			const test = fixture(manager);
			const stack = result(test);
			const component = result(test, 'provideComponent');
			expect(edge(stack, 'app@1.0.0', 'alpha@1.0.0')).to.be.true;
			expect(edge(stack, 'alpha@1.0.0', 'shared@1.0.0')).to.be.true;
			expect(component.components.map(c => c.name)).to.deep.equal(['alpha']);
		});

		test(`${manager} preserves cycle edges without recursion overflow`, () => {
			const test = fixture(manager, undefined, {
				alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } },
				shared: { version: '1.0.0', dependencies: { alpha: '^1.0.0' } },
			});
			const sbom = result(test);
			expect(edge(sbom, 'alpha@1.0.0', 'shared@1.0.0')).to.be.true;
			expect(edge(sbom, 'shared@1.0.0', 'alpha@1.0.0')).to.be.true;
			expect(sbom.components).to.have.lengthOf(2);
		});

		test(`${manager} preserves declared-only peer/optional entries and excludes development branches`, () => {
			const test = fixture(manager, { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' },
				peerDependencies: { peer: '^1.0.0' }, optionalDependencies: { optional: '^1.0.0' }, devDependencies: { dev: '^1.0.0' } },
			{ alpha: { version: '1.0.0' }, dev: { version: '1.0.0' } });
			const sbom = result(test);
			expect(sbom.components.map(c => c.name).sort()).to.deep.equal(['alpha', 'optional', 'peer']);
			expect(edge(sbom, 'app@1.0.0', 'peer@%5E1.0.0')).to.be.true;
		});

		test(`${manager} refuses missing required edges`, () => {
			const test = fixture(manager, undefined, { alpha: { version: '1.0.0', dependencies: { missing: '^1.0.0' } } });
			expect(() => result(test)).to.throw(/out of date.*missing/);
		});

		test(`${manager} refuses malformed and absent lockfiles on direct provider calls`, () => {
			const test = fixture(manager);
			fs.writeFileSync(test.lockPath, '{ invalid');
			expect(() => result(test)).to.throw(/Cannot read/);
			fs.unlinkSync(test.lockPath);
			expect(() => result(test)).to.throw(/requires a lockfile/);
		});

		test(`${manager} rejects stale development declarations`, () => {
			const test = fixture(manager);
			test.manifest.devDependencies = { missingDev: '^1.0.0' };
			fs.writeFileSync(test.manifestPath, JSON.stringify(test.manifest));
			expect(() => result(test)).to.throw(/out of date.*missingDev/);
		});
	}

	for (const { method } of SBOM_CASES) {
		for (const { label, overrides, section = 'dependencies', specifier = '2.0.0' } of [
			{ label: 'plain', overrides: { alpha: '2.0.0' } },
			{ label: 'version-qualified development', overrides: { 'alpha@^1.0.0': '2.0.0' }, section: 'devDependencies' },
			{ label: 'parent-qualified optional', overrides: { 'app@^1.0.0>alpha': '2.0.0' }, section: 'optionalDependencies' },
			{ label: 'unrelated version', overrides: { 'alpha@^3.0.0': '2.0.0' }, specifier: '^1.0.0' },
			{ label: 'unrelated parent', overrides: { 'other>alpha': '2.0.0' }, specifier: '^1.0.0' },
			{ label: 'unrelated parent version', overrides: { 'app@^3.0.0>alpha': '2.0.0' }, specifier: '^1.0.0' },
			{ label: 'parent precedence', overrides: { alpha: '3.0.0', 'app>alpha': '2.0.0' } },
			{ label: 'intersecting selector precedence', overrides: { 'alpha@^1.0.0': '2.0.0', alpha: '3.0.0' }, specifier: '3.0.0' },
			{ label: 'reversed intersecting selector precedence', overrides: { alpha: '3.0.0', 'alpha@^1.0.0': '2.0.0' } },
		]) {
			test(`pnpm ${method} applies ${label} overrides without accepting unrelated declaration changes`, () => {
				const version = specifier === '^1.0.0' ? '1.0.0' : specifier;
				const test = fixture('pnpm', { name: 'app', version: '1.0.0', [section]: { alpha: '^1.0.0' }, pnpm: { overrides } },
					{ alpha: { version } });
				test.lock.overrides = overrides;
				test.lock.importers['.'][section].alpha.specifier = specifier;
				fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
				const before = snapshot(root);

				expect(result(test, method).components.map(component => component.purl)).to.deep.equal(section === 'devDependencies' ? [] : [`pkg:npm/alpha@${version}`]);
				expect(snapshot(root)).to.deep.equal(before);

				test.lock.importers['.'][section].alpha.specifier = '^9.0.0';
				fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
				expect(() => result(test, method)).to.throw(/Lockfile is out of date.*alpha/);
			});
		}

		/**
		 * Verifies pnpm's last-matching-rule precedence when several override
		 * selectors — including a disjoint one — all match a broad dependency range.
		 * The last declared matching rule must win regardless of range intersection.
		 */
		test(`pnpm ${method} applies the last matching override across selectors on a broad range`, () => {
			// Given a broad dependency range matched by three override selectors in
			// declaration order, including one (^5.0.0) disjoint from the first
			const overrides = { 'alpha@^1.0.0': '2.0.0', 'alpha@^5.0.0': '6.0.0', 'alpha@>=2.0.0': '4.0.0' };
			const test = fixture('pnpm', { name: 'app', version: '1.0.0', dependencies: { alpha: '>=1.0.0' }, pnpm: { overrides } },
				{ alpha: { version: '4.0.0' } });
			test.lock.overrides = overrides;
			test.lock.importers['.'].dependencies.alpha.specifier = '4.0.0';
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));

			// When the graph resolves the overridden dependency
			// Then the last declared matching override (4.0.0) wins, not an earlier match
			expect(result(test, method).components.map(component => component.purl)).to.deep.equal(['pkg:npm/alpha@4.0.0']);
		});

		test(`pnpm ${method} resolves override references to root dependency declarations`, () => {
			const test = fixture('pnpm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' },
				devDependencies: { reference: '2.0.0' }, pnpm: { overrides: { alpha: '$reference' } },
			}, { alpha: { version: '2.0.0' }, reference: { version: '2.0.0' } });
			test.lock.overrides = { alpha: '2.0.0' };
			test.lock.importers['.'].dependencies.alpha.specifier = '2.0.0';
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));

			expect(result(test, method).components.map(component => component.purl)).to.deep.equal(['pkg:npm/alpha@2.0.0']);
		});

		test(`pnpm ${method} rejects a locked resolution that drifted outside the declared range`, () => {
			// Given an importer whose specifier still matches the manifest but whose
			// locked version falls outside that range
			const test = fixture('pnpm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' } },
				{ alpha: { version: '2.0.0' } });

			// When the graph resolves the edge
			// Then it is rejected with an actionable staleness error rather than
			// entering the SBOM with the wrong version
			expect(test.lock.importers['.'].dependencies.alpha).to.deep.equal({ specifier: '^1.0.0', version: '2.0.0' });
			expect(() => result(test, method)).to.throw(/Lockfile is out of date.*alpha requires \^1\.0\.0 but resolves to 2\.0\.0/);
		});

		test(`pnpm ${method} accepts in-range and overridden resolutions within the effective range`, () => {
			// Given an in-range resolution (1.5.0 satisfies ^1.0.0)
			const inRange = fixture('pnpm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' } },
				{ alpha: { version: '1.5.0' } });

			// Then it resolves unchanged
			expect(result(inRange, method).components.map(component => component.purl)).to.deep.equal(['pkg:npm/alpha@1.5.0']);

			// Given an overridden resolution whose effective range is the override value
			const overridden = fixture('pnpm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' }, pnpm: { overrides: { alpha: '2.0.0' } } },
				{ alpha: { version: '2.0.0' } });
			overridden.lock.overrides = { alpha: '2.0.0' };
			overridden.lock.importers['.'].dependencies.alpha.specifier = '2.0.0';
			fs.writeFileSync(overridden.lockPath, JSON.stringify(overridden.lock));

			// Then the version satisfying the override still resolves unchanged
			expect(result(overridden, method).components.map(component => component.purl)).to.deep.equal(['pkg:npm/alpha@2.0.0']);
		});

		for (const catalog of ['', 'versions']) {
			test(`pnpm ${method} resolves overrides from the ${catalog || 'default'} catalog`, () => {
				const test = fixture('pnpm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' }, pnpm: { overrides: { alpha: `catalog:${catalog}` } } },
					{ alpha: { version: '2.0.0' } });
				fs.writeFileSync(path.join(root, 'pnpm-workspace.yaml'), JSON.stringify(catalog
					? { catalogs: { versions: { alpha: '2.0.0' } } } : { catalog: { alpha: '2.0.0' } }));
				test.lock.overrides = { alpha: '2.0.0' };
				test.lock.importers['.'].dependencies.alpha.specifier = '2.0.0';
				fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));

				expect(result(test, method).components.map(component => component.purl)).to.deep.equal(['pkg:npm/alpha@2.0.0']);
			});
		}

		test(`pnpm ${method} accepts an overridden dependency removal`, () => {
			const test = fixture('pnpm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' }, pnpm: { overrides: { alpha: '-' } } }, {});
			test.lock.overrides = { alpha: '-' };
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));

			expect(result(test, method).components).to.deep.equal([]);
		});

		test(`pnpm ${method} normalizes root-relative directory overrides`, () => {
			const test = fixture('pnpm', { name: 'app', version: '1.0.0', dependencies: { local: 'file:./old' }, pnpm: { overrides: { local: 'file:./replacement' } } },
				{ local: { version: 'file:replacement' } });
			fs.mkdirSync(path.join(root, 'replacement'));
			fs.writeFileSync(path.join(root, 'replacement', 'package.json'), JSON.stringify({ name: 'local', version: '2.0.0' }));
			test.lock.overrides = { local: 'file:./replacement' };
			test.lock.importers['.'].dependencies.local.specifier = 'file:replacement';
			test.lock.packages['local@file:replacement'] = { resolution: { directory: 'replacement', type: 'directory' } };
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));

			expect(result(test, method).components.map(component => component.purl)).to.deep.equal(['pkg:npm/local@2.0.0']);
		});

		test(`pnpm ${method} reads overrides from pnpm-workspace.yaml`, () => {
			const test = fixture('pnpm', undefined, { alpha: { version: '2.0.0' } });
			fs.writeFileSync(path.join(root, 'pnpm-workspace.yaml'), 'overrides:\n  alpha: 2.0.0\n');
			test.lock.overrides = { alpha: '2.0.0' };
			test.lock.importers['.'].dependencies.alpha.specifier = '2.0.0';
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));

			expect(result(test, method).components.map(component => component.purl)).to.deep.equal(['pkg:npm/alpha@2.0.0']);
		});

		test(`pnpm ${method} gives manifest overrides precedence over workspace settings`, () => {
			const test = fixture('pnpm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' }, pnpm: { overrides: { alpha: '2.0.0' } } },
				{ alpha: { version: '2.0.0' } });
			fs.writeFileSync(path.join(root, 'pnpm-workspace.yaml'), 'overrides:\n  alpha: 3.0.0\n');
			test.lock.overrides = { alpha: '2.0.0' };
			test.lock.importers['.'].dependencies.alpha.specifier = '2.0.0';
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));

			expect(result(test, method).components.map(component => component.purl)).to.deep.equal(['pkg:npm/alpha@2.0.0']);
		});

		test(`pnpm ${method} applies root overrides to linked workspace declarations`, () => {
			const test = pnpmWorkspaceFixture();
			fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'root', version: '1.0.0', pnpm: { overrides: { alpha: '2.0.0' } } }));
			test.lock.overrides = { alpha: '2.0.0' };
			test.lock.importers['packages/lib'].dependencies.alpha = { specifier: '2.0.0', version: '2.0.0' };
			test.lock.packages['alpha@2.0.0'] = {};
			test.lock.snapshots['alpha@2.0.0'] = {};
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));

			const sbom = result(test, method);
			expect(sbom.components.some(component => component.purl === 'pkg:npm/%40example/lib@2.3.4')).to.be.true;
			if (method === 'provideStack') { expect(edge(sbom, '%40example/lib@2.3.4', 'alpha@2.0.0')).to.be.true; }
		});

		test(`pnpm ${method} rejects stale override settings`, () => {
			const test = fixture('pnpm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' }, pnpm: { overrides: { shared: '2.0.0' } } });

			expect(() => result(test, method)).to.throw(/Lockfile is out of date.*overrides/);
		});

		test(`pnpm ${method} reads linked workspace identities and follows nested links and cycles`, () => {
			const test = pnpmWorkspaceFixture();
			const before = snapshot(root);
			const sbom = result(test, method);
			expect(sbom.components.map(component => component.purl).sort()).to.deep.equal(method === 'provideStack'
				? ['pkg:npm/%40example/lib@2.3.4', 'pkg:npm/alpha@1.0.0', 'pkg:npm/shared@1.0.0', 'pkg:npm/util@5.6.7']
				: ['pkg:npm/%40example/lib@2.3.4']);
			expect(edge(sbom, 'app@1.0.0', '%40example/lib@2.3.4')).to.be.true;
			if (method === 'provideStack') {
				expect(edge(sbom, '%40example/lib@2.3.4', 'alpha@1.0.0')).to.be.true;
				expect(edge(sbom, '%40example/lib@2.3.4', 'util@5.6.7')).to.be.true;
				expect(edge(sbom, 'util@5.6.7', '%40example/lib@2.3.4')).to.be.true;
			}
			expect(snapshot(root)).to.deep.equal(before);
		});

		/** Verifies a very deep acyclic pnpm chain is analyzed iteratively without a RangeError stack overflow. */
		test(`pnpm ${method} analyzes a very deep acyclic dependency chain without a stack overflow`, function () {
			this.timeout(30000); // building and traversing a 15k-deep chain is well past the 2s default
			// Given a lockfile whose dependency chain is far deeper than the JS call stack
			const depth = 15000;
			const packages = {};
			for (let i = 0; i < depth; i++) {
				packages[`dep${i}`] = { version: '1.0.0', ...(i < depth - 1 ? { dependencies: { [`dep${i + 1}`]: '^1.0.0' } } : {}) };
			}
			const test = fixture('pnpm', { name: 'app', version: '1.0.0', dependencies: { dep0: '^1.0.0' } }, packages);

			// When analyzing the manifest (a recursive walk would throw RangeError here)
			const sbom = result(test, method);

			// Then the chain is traversed and the SBOM is produced
			expect(sbom.components.some(component => component.purl === 'pkg:npm/dep0@1.0.0')).to.be.true;
			if (method === 'provideStack') {
				expect(sbom.components.some(component => component.purl === `pkg:npm/dep${depth - 1}@1.0.0`)).to.be.true;
			}
		});

		test(`pnpm ${method} rejects a stale linked workspace manifest`, () => {
			const test = pnpmWorkspaceFixture();
			test.lib.dependencies.alpha = '^2.0.0';
			fs.writeFileSync(test.libPath, JSON.stringify(test.lib));

			expect(() => result(test, method)).to.throw(/Lockfile is out of date.*alpha/);
		});

		test(`pnpm ${method} rejects a missing linked workspace manifest`, () => {
			const test = pnpmWorkspaceFixture();
			fs.unlinkSync(test.libPath);

			expect(() => result(test, method)).to.throw(/Cannot read .*packages[/\\]lib[/\\]package\.json/);
		});

		for (const [from, to] of [['devDependencies', 'dependencies'], ['dependencies', 'devDependencies']]) {
			test(`pnpm ${method} rejects moving ${from} to ${to} without updating the lockfile`, () => {
				const test = fixture('pnpm', { name: 'app', version: '1.0.0', [from]: { alpha: '^1.0.0' } });
				test.manifest[to] = test.manifest[from];
				delete test.manifest[from];
				fs.writeFileSync(test.manifestPath, JSON.stringify(test.manifest));
				const before = snapshot(root);

				expect(() => result(test, method)).to.throw(/Lockfile is out of date.*alpha/);
				expect(snapshot(root)).to.deep.equal(before);

				test.lock.importers['.'][to] = test.lock.importers['.'][from];
				delete test.lock.importers['.'][from];
				fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
				expect(result(test, method).components.some(component => component.name === 'alpha')).to.equal(to === 'dependencies');
			});
		}

		for (const name of ['alpha', 'shared']) {
			test(`pnpm ${method} rejects a missing required snapshot for ${name}`, () => {
				const test = fixture('pnpm');
				delete test.lock.snapshots[`${name}@1.0.0`];
				fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));

				expect(() => result(test, method)).to.throw(new RegExp(`Lockfile is out of date.*${name} has no locked resolution`));
			});
		}

		test(`pnpm ${method} requires the exact peer-context snapshot and accepts an empty snapshot`, () => {
			const test = fixture('pnpm');
			test.lock.importers['.'].dependencies.alpha.version = '1.0.0(peer@1.0.0)';
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));

			expect(() => result(test, method)).to.throw(/Lockfile is out of date.*alpha has no locked resolution/);

			test.lock.snapshots['alpha@1.0.0(peer@1.0.0)'] = {};
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			expect(result(test, method).components.map(component => component.name)).to.deep.equal(['alpha']);
		});

		test(`pnpm ${method} respects dependency section precedence for duplicate declarations`, () => {
			for (const section of ['dependencies', 'optionalDependencies']) {
				const version = section === 'optionalDependencies' ? '3.0.0' : '2.0.0';
				const test = fixture('pnpm', { name: 'app', version: '1.0.0',
					peerDependencies: { alpha: '^9.0.0' }, devDependencies: { alpha: '^1.0.0' }, dependencies: { alpha: '^2.0.0' },
					...(section === 'optionalDependencies' ? { optionalDependencies: { alpha: '^3.0.0' } } : {}),
				}, { alpha: { version } });
				delete test.lock.importers['.'].devDependencies;
				if (section === 'optionalDependencies') { delete test.lock.importers['.'].dependencies; }
				fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));

				expect(result(test, method).components.map(component => component.purl)).to.deep.equal([`pkg:npm/alpha@${version}`]);

				test.manifest[section].alpha = '^4.0.0';
				fs.writeFileSync(test.manifestPath, JSON.stringify(test.manifest));
				expect(() => result(test, method)).to.throw(/Lockfile is out of date.*alpha/);
			}
		});
	}

	for (const version of [2, 3]) {
		test(`npm supports lockfile version ${version}`, () => {
			const test = fixture('npm');
			test.lock.lockfileVersion = version;
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			expect(result(test).components).to.have.lengthOf(2);
		});
	}

	for (const version of [1, 4]) {
		test(`npm rejects unsupported lockfile version ${version}`, () => {
			const test = fixture('npm');
			test.lock.lockfileVersion = version;
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			expect(() => result(test)).to.throw(/Unsupported npm lockfile version/);
		});
	}

	test('npm honors shrinkwrap precedence, including projects without package-lock.json', () => {
		const test = fixture('npm');
		fs.copyFileSync(test.lockPath, path.join(root, 'npm-shrinkwrap.json'));
		test.lock.packages['node_modules/alpha'].version = '99.0.0';
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		expect(result(test).components.some(c => c.version === '99.0.0')).to.be.false;
		fs.unlinkSync(test.lockPath);
		expect(test.provider.validateLockFile(root)).to.be.true;
		expect(result(test).components).to.have.lengthOf(2);
	});

	test('npm resolves nested versions from their recorded locations', () => {
		const test = fixture('npm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0', other: '^1.0.0' } }, {
			alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } },
			other: { version: '1.0.0', dependencies: { shared: '^2.0.0' } }, shared: { version: '1.0.0' },
		});
		test.lock.packages['node_modules/other/node_modules/shared'] = { version: '2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'alpha@1.0.0', 'shared@1.0.0')).to.be.true;
		expect(edge(sbom, 'other@1.0.0', 'shared@2.0.0')).to.be.true;
	});

	test('npm uses canonical alias identity without supplementing a duplicate alias', () => {
		const test = fixture('npm', { name: 'app', version: '1.0.0', optionalDependencies: { alias: 'npm:real@^1.0.0' } }, {
			alias: { name: 'real', version: '1.0.0', integrity: `sha512-${Buffer.from('ab'.repeat(64), 'hex').toString('base64')}` },
		});
		for (const { method } of SBOM_CASES) {
			expect(result(test, method).components.map(c => c.name)).to.deep.equal(['real']);
			expect(result(test, method).components[0].hashes).to.deep.equal([{ alg: 'SHA-512', content: 'ab'.repeat(64) }]);
		}
	});

	test('npm checks overrides without rejecting their intentional replacement versions', () => {
		const test = fixture('npm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' }, overrides: { shared: '^2.0.0' } }, {
			alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } }, shared: { version: '2.0.0' },
		});
		expect(edge(result(test), 'alpha@1.0.0', 'shared@2.0.0')).to.be.true;
	});

	test('npm limits version-qualified overrides to matching dependency requests', () => {
		const test = fixture('npm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0', other: '^1.0.0' }, overrides: { 'shared@^1.0.0': '^3.0.0' } }, {
			alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } },
			other: { version: '1.0.0', dependencies: { shared: '^2.0.0' } }, shared: { version: '3.0.0' },
		});
		test.lock.packages['node_modules/other/node_modules/shared'] = { version: '2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'alpha@1.0.0', 'shared@3.0.0')).to.be.true;
		expect(edge(sbom, 'other@1.0.0', 'shared@2.0.0')).to.be.true;
	});

	test('npm scopes nested overrides to the declaring ancestor', () => {
		const test = fixture('npm', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0', other: '^1.0.0' }, overrides: { 'alpha@1.0.0': { shared: '^3.0.0' } } }, {
			alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } },
			other: { version: '1.0.0', dependencies: { shared: '^1.0.0' } }, shared: { version: '1.0.0' },
		});
		test.lock.packages['node_modules/alpha/node_modules/shared'] = { version: '3.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'alpha@1.0.0', 'shared@3.0.0')).to.be.true;
		expect(edge(sbom, 'other@1.0.0', 'shared@1.0.0')).to.be.true;
	});

	for (const manager of MANAGERS) {
		test(`${manager} scopes workspace-member scans and validates the workspace root`, () => {
			const test = fixture(manager);
			const memberPath = path.join(root, 'packages', 'member', 'package.json');
			const otherPath = path.join(root, 'packages', 'other', 'package.json');
			fs.mkdirSync(path.dirname(memberPath), { recursive: true });
			fs.mkdirSync(path.dirname(otherPath), { recursive: true });
			const member = { name: 'member', version: '1.0.0', dependencies: { alpha: '^1.0.0' } };
			const other = { name: 'unrelated', version: '1.0.0', dependencies: { alpha: '^1.0.0' } };
			fs.writeFileSync(memberPath, JSON.stringify(member));
			fs.writeFileSync(otherPath, JSON.stringify(other));
			test.manifest.workspaces = ['packages/*'];
			fs.writeFileSync(test.manifestPath, JSON.stringify(test.manifest));
			if (manager === 'npm') {
				test.lock.packages['packages/member'] = member;
				test.lock.packages['packages/other'] = other;
				test.lock.packages['node_modules/member'] = { link: true, resolved: 'packages/member' };
				test.lock.packages['node_modules/unrelated'] = { link: true, resolved: 'packages/other' };
			} else if (manager === 'yarn-berry') {
				for (const [location, data] of [['packages/member', member], ['packages/other', other]]) {
					test.lock[`${data.name}@workspace:${location}`] = { version: '0.0.0-use.local', resolution: `${data.name}@workspace:${location}`, dependencies: { alpha: 'npm:^1.0.0' } };
				}
			} else if (manager === 'pnpm') {
				for (const location of ['packages/member', 'packages/other']) {
					test.lock.importers[location] = { dependencies: { alpha: { specifier: '^1.0.0', version: '1.0.0' } } };
				}
			}
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			const sbom = JSON.parse(test.provider.provideStack(memberPath, { TRUSTIFY_DA_WORKSPACE_DIR: root }).content);
			expect(sbom.metadata.component.name).to.equal('member');
			expect(sbom.components.map(c => c.name).sort()).to.deep.equal(['alpha', 'shared']);
			expect(edge(sbom, 'member@1.0.0', 'alpha@1.0.0')).to.be.true;
			test.manifest.dependencies.alpha = '^2.0.0';
			fs.writeFileSync(test.manifestPath, JSON.stringify(test.manifest));
			expect(() => test.provider.provideStack(memberPath)).to.throw(/out of date.*alpha/);
		});
	}

	test('npm validates local link manifests and follows their locked dependencies', () => {
		const test = fixture('npm', { name: 'app', version: '1.0.0', dependencies: { local: 'file:local' } }, { shared: { version: '1.0.0' } });
		const local = { name: 'local', version: '1.0.0', dependencies: { shared: '^1.0.0' } };
		fs.mkdirSync(path.join(root, 'local'));
		fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify(local));
		test.lock.packages.local = local;
		test.lock.packages['node_modules/local'] = { link: true, resolved: 'local' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		expect(edge(result(test), 'local@1.0.0', 'shared@1.0.0')).to.be.true;
		local.dependencies.shared = '^2.0.0';
		fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify(local));
		expect(() => result(test)).to.throw(/out of date.*shared/);
	});

	test('npm external local links cannot borrow the project root dependency locations', () => {
		const outside = `${root}-local`;
		const location = `../${path.basename(outside)}`;
		fs.mkdirSync(outside);
		try {
			const local = { name: 'local', version: '1.0.0', dependencies: { shared: '^1.0.0' } };
			fs.writeFileSync(path.join(outside, 'package.json'), JSON.stringify(local));
			const test = fixture('npm', { name: 'app', version: '1.0.0', dependencies: { local: `file:${location}` } }, { shared: { version: '1.0.0' } });
			test.lock.packages[location] = local;
			test.lock.packages['node_modules/local'] = { link: true, resolved: location };
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			expect(() => result(test)).to.throw(/out of date.*shared.*no locked resolution/);
			test.lock.packages[`${location}/node_modules/shared`] = { version: '1.0.0' };
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			expect(edge(result(test), 'local@1.0.0', 'shared@1.0.0')).to.be.true;
		} finally { fs.rmSync(outside, { recursive: true }); }
	});

	test('Berry resolves scoped registry aliases from combined descriptors', () => {
		const test = fixture('yarn-berry', { name: 'app', version: '1.0.0', dependencies: { alias: 'npm:@scope/real@^1.0.0' } }, {});
		test.lock['alias@npm:@scope/real@^1.0.0, @scope/real@npm:^1.0.0'] = { version: '1.0.0', resolution: '@scope/real@npm:1.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		expect(result(test).components.map(c => c.purl)).to.deep.equal(['pkg:npm/%40scope/real@1.0.0']);
	});

	test('Yarn resolutions validate their intentional replacement version', () => {
		const test = fixture('yarn-classic', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0' }, resolutions: { '**/shared': '^2.0.0' } }, {
			alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } },
		});
		test.lock['shared@^2.0.0'] = { version: '2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		expect(edge(result(test), 'alpha@1.0.0', 'shared@2.0.0')).to.be.true;
	});

	test('Classic resolutions keep shared packages in distinct ancestry contexts', () => {
		const test = fixture('yarn-classic', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0', other: '^1.0.0' }, resolutions: { 'alpha/plugin/shared': '^2.0.0' } }, {
			alpha: { version: '1.0.0', dependencies: { plugin: '^1.0.0' } }, other: { version: '1.0.0', dependencies: { plugin: '^1.0.0' } },
			plugin: { version: '1.0.0', dependencies: { shared: '^1.0.0' } }, shared: { version: '1.0.0' },
		});
		test.lock['shared@^2.0.0'] = { version: '2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'plugin@1.0.0', 'shared@1.0.0')).to.be.true;
		expect(edge(sbom, 'plugin@1.0.0', 'shared@2.0.0')).to.be.true;
		test.lock['shared@^2.0.0'].dependencies = { plugin: '^1.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		expect(() => result(test)).to.throw(/Unsupported.*cyclic graph with path-dependent/);
	});

	for (const selector of ['alpha/shared', 'alpha@npm:1.0.0/shared@npm:^1.0.0']) {
		test(`Berry scopes resolution ${selector} to the declaring locator`, () => {
			const test = fixture('yarn-berry', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0', other: '^1.0.0' }, resolutions: { [selector]: '^2.0.0' } }, {
				alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } },
				other: { version: '1.0.0', dependencies: { shared: '^1.0.0' } }, shared: { version: '1.0.0' },
			});
			test.lock['shared@npm:^2.0.0'] = { version: '2.0.0', resolution: 'shared@npm:2.0.0' };
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			const sbom = result(test);
			expect(edge(sbom, 'alpha@1.0.0', 'shared@2.0.0')).to.be.true;
			expect(edge(sbom, 'other@1.0.0', 'shared@1.0.0')).to.be.true;
		});
	}

	test('Yarn chooses its format from the lockfile despite conflicting declarations', () => {
		const test = fixture('yarn-classic', { name: 'app', version: '1.0.0', packageManager: 'yarn@4.9.3', dependencies: { alpha: '^1.0.0' } });
		expect(test.provider.provideStack(test.manifestPath).ecosystem).to.equal('yarn-classic');
	});

	test('Berry reconstructs distinct peer contexts and unions their SBOM edges', () => {
		const test = fixture('yarn-berry', { name: 'app', version: '1.0.0', dependencies: { first: '^1.0.0', second: '^1.0.0' } }, {
			first: { version: '1.0.0', dependencies: { plugin: '^1.0.0', framework: '^1.0.0' } },
			second: { version: '1.0.0', dependencies: { plugin: '^1.0.0', framework: '^2.0.0' } },
			plugin: { version: '1.0.0', peerDependencies: { framework: '*' } }, framework: { version: '1.0.0' },
		});
		test.lock['framework@npm:^2.0.0'] = { version: '2.0.0', resolution: 'framework@npm:2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'plugin@1.0.0', 'framework@1.0.0')).to.be.true;
		expect(edge(sbom, 'plugin@1.0.0', 'framework@2.0.0')).to.be.true;
	});

	test('Berry retains a peer provider’s own peer context', () => {
		const test = fixture('yarn-berry', { name: 'app', version: '1.0.0', dependencies: { first: '^1.0.0', second: '^1.0.0' } }, {
			first: { version: '1.0.0', dependencies: { plugin: '^1.0.0', adapter: '^1.0.0', framework: '^1.0.0' } },
			second: { version: '1.0.0', dependencies: { plugin: '^1.0.0', adapter: '^1.0.0', framework: '^2.0.0' } },
			plugin: { version: '1.0.0', peerDependencies: { adapter: '*' } },
			adapter: { version: '1.0.0', peerDependencies: { framework: '*' } }, framework: { version: '1.0.0' },
		});
		test.lock['framework@npm:^2.0.0'] = { version: '2.0.0', resolution: 'framework@npm:2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'plugin@1.0.0', 'adapter@1.0.0')).to.be.true;
		expect(edge(sbom, 'adapter@1.0.0', 'framework@1.0.0')).to.be.true;
		expect(edge(sbom, 'adapter@1.0.0', 'framework@2.0.0')).to.be.true;
	});

	test('Berry reads local portal manifests without installing them', () => {
		const test = fixture('yarn-berry', { name: 'app', version: '1.0.0', dependencies: { local: 'portal:local' } }, { alpha: { version: '1.0.0' } });
		const local = { name: 'local', version: '2.0.0', dependencies: { alpha: '^1.0.0' } };
		fs.mkdirSync(path.join(root, 'local'));
		fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify(local));
		test.lock['local@portal:local'] = { version: '0.0.0-use.local', resolution: 'local@portal:local', dependencies: { alpha: 'npm:^1.0.0' } };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const before = snapshot(root);
		expect(edge(result(test), 'local@2.0.0', 'alpha@1.0.0')).to.be.true;
		expect(snapshot(root)).to.deep.equal(before);
		local.dependencies.alpha = '^2.0.0';
		fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify(local));
		expect(() => result(test)).to.throw(/out of date.*alpha/);
	});

	for (const manager of ['yarn-classic', 'yarn-berry']) {
		test(`${manager} validates directory file dependencies without including their development dependencies`, () => {
			const test = fixture(manager, { name: 'app', version: '1.0.0', dependencies: { local: 'file:local' } }, { alpha: { version: '1.0.0' } });
			const local = { name: 'local', version: '2.0.0', dependencies: { alpha: '^1.0.0' }, devDependencies: { dev: '^1.0.0' } };
			fs.mkdirSync(path.join(root, 'local'));
			fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify(local));
			test.lock['local@file:local'] = { version: '2.0.0', ...(manager === 'yarn-berry' ? { resolution: 'local@file:local' } : {}), dependencies: { alpha: '^1.0.0' } };
			fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
			const before = snapshot(root);
			expect(edge(result(test), 'local@2.0.0', 'alpha@1.0.0')).to.be.true;
			expect(snapshot(root)).to.deep.equal(before);
			local.dependencies.alpha = '^2.0.0';
			fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify(local));
			expect(() => result(test)).to.throw(/out of date.*alpha/);
		});
	}

	test('Classic aliases retain canonical identity and hashes', () => {
		const test = fixture('yarn-classic', { name: 'app', version: '1.0.0', dependencies: { alias: 'npm:real@^1.0.0' } }, {});
		test.lock['alias@npm:real@^1.0.0'] = { version: '1.0.0', integrity: `sha512-${Buffer.from('ab'.repeat(64), 'hex').toString('base64')}` };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		for (const { method } of SBOM_CASES) {
			const component = result(test, method).components[0];
			expect(component.purl).to.equal('pkg:npm/real@1.0.0');
			expect(component.hashes).to.deep.equal([{ alg: 'SHA-512', content: 'ab'.repeat(64) }]);
		}
	});

	test('Berry registry patches retain the original package name and checksum', () => {
		const test = fixture('yarn-berry', undefined, { alpha: { version: '1.0.0', checksum: `10c0/${'ab'.repeat(64)}` } });
		test.lock['alpha@npm:^1.0.0'].resolution = 'alpha@patch:alpha@npm%3A1.0.0#builtin<compat/alpha>';
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const alpha = result(test).components.find(c => c.name === 'alpha');
		expect(alpha.purl).to.equal('pkg:npm/alpha@1.0.0');
		expect(alpha.hashes).to.deep.equal([{ alg: 'SHA-512', content: 'ab'.repeat(64) }]);
	});

	test('Berry refuses unknown protocols and missing package identities', () => {
		const test = fixture('yarn-berry');
		test.lock['alpha@npm:^1.0.0'].resolution = 'alpha@custom:1.0.0';
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		expect(() => result(test)).to.throw(/Unsupported.*unknown resolution protocol/);
	});

	test('Classic resolves each combined selector without confusing duplicate versions', () => {
		const test = fixture('yarn-classic', { name: 'app', version: '1.0.0', dependencies: { alpha: '^1.0.0', other: '^1.0.0' } }, {
			alpha: { version: '1.0.0', dependencies: { shared: '^1.0.0' } }, other: { version: '1.0.0', dependencies: { shared: '^2.0.0' } },
		});
		test.lock['shared@^1.0.0, shared@~1.0.0'] = { version: '1.0.0' };
		test.lock['shared@^2.0.0'] = { version: '2.0.0' };
		fs.writeFileSync(test.lockPath, JSON.stringify(test.lock));
		const sbom = result(test);
		expect(edge(sbom, 'alpha@1.0.0', 'shared@1.0.0')).to.be.true;
		expect(edge(sbom, 'other@1.0.0', 'shared@2.0.0')).to.be.true;
	});
});

suite('complete JavaScript SBOM reference comparisons', () => {
	let clock;
	suiteSetup(() => { clock = useFakeTimers(new Date('2023-08-07T00:00:00.000Z')); });
	suiteTeardown(() => { clock.restore(); });
	for (const manager of MANAGERS) {
		const base = `test/providers/tst_manifests/${manager}`;
		const fixtures = ['package_json_deps_without_exhortignore_object', 'package_json_deps_with_exhortignore_object', 'package_json_deps_with_mixed_dep_types', ...(manager === 'yarn-classic' ? [] : ['workspace_member'])];
		for (const fixture of fixtures) {
			for (const { method, type } of SBOM_CASES) {
				test(`${manager} ${fixture} ${type} matches every SBOM field`, () => {
					const dir = `${base}/${fixture}`;
					const manifest = `${dir}/${fixture === 'workspace_member' ? 'packages/member-a/package.json' : 'package.json'}`;
					const provider = manager === 'npm' ? new Npm() : manager === 'pnpm' ? new Pnpm() : new Yarn();
					const actual = provider[method](manifest);
					const expected = JSON.parse(fs.readFileSync(`${dir}/expected_${type}_sbom.json`, 'utf8'));
					expected.metadata.tools.components[0].version = getPackageVersion();
					expect(actual.contentType).to.equal('application/vnd.cyclonedx+json');
					expect(canonical(actual.content)).to.deep.equal(canonical(expected));
				});
			}
		}
	}
});

suite('pnpm lockfile specifics', () => {
	const IS_ODD = 'sha512-CQpnWPrDwmP1+SMHXZhtLtJv90yiyVfluGsX5iNCVkrhQtU3TQHsUWPG9wkdk9Lgd5yNpAg9jQEo90CBaXgWMA==';
	const IS_NUMBER6 = 'sha512-Wu1VHeILBK8KAWJUAiSZQX94GmOE45Rg6/538fKwiloUu21KncEkYGPqob2oSZ5mUT73vLGrHQjKw3KMPwfDzg==';
	const IS_NUMBER7 = 'sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==';

	let root;
	setup(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'pnpm-lockfile-')); });
	teardown(() => { fs.rmSync(root, { recursive: true, force: true }); });

	/** Writes a package.json and a pnpm-lock.yaml (any string), returning the manifest path. */
	function project(manifest, lock) {
		const manifestPath = path.join(root, 'package.json');
		fs.writeFileSync(manifestPath, JSON.stringify(manifest));
		fs.writeFileSync(path.join(root, 'pnpm-lock.yaml'), typeof lock === 'string' ? lock : JSON.stringify(lock));
		return manifestPath;
	}

	function stack(manifestPath) {
		return JSON.parse(new Pnpm().provideStack(manifestPath).content);
	}

	function edge(sbom, from, to) {
		return sbom.dependencies.find(dep => dep.ref === `pkg:npm/${from}`)?.dependsOn.includes(`pkg:npm/${to}`);
	}

	for (const { method } of SBOM_CASES) {
		for (const { major, reference, name = 'archive-lib', purl = 'pkg:npm/archive-lib@2.3.4', registry = false } of [
			{ major: 6, reference: 'file:../archive.tgz' },
			{ major: 9, reference: 'file:../archive.tgz' },
			{ major: 9, reference: 'https://example.test/archive.tgz' },
			{ major: 9, reference: 'https://example.test/@example/archive.tgz', name: '@example/archive-lib', purl: 'pkg:npm/%40example/archive-lib@2.3.4' },
			{ major: 9, reference: '2.3.4', registry: true },
		]) {
			test(`pnpm ${method} preserves archive identity, edges and hashes for v${major} ${name}@${reference}`, () => {
				const id = major === 6 ? reference : `${name}@${reference}`;
				const numberId = `${major === 6 ? '/' : ''}is-number@7.0.0`;
				const archive = { resolution: { tarball: registry ? 'https://example.test/archive.tgz' : reference, integrity: IS_ODD },
					...(major === 6 || registry ? { name } : {}), ...(!registry ? { version: '2.3.4' } : {}),
					...(major === 6 ? { dependencies: { 'is-number': '7.0.0' } } : {}),
				};
				const lock = { lockfileVersion: `${major}.0`,
					importers: { '.': { dependencies: { [name]: { specifier: reference, version: reference } } } },
					packages: { [id]: archive, [numberId]: { resolution: { integrity: IS_NUMBER7 } } },
					...(major === 9 ? { snapshots: { [id]: { dependencies: { 'is-number': '7.0.0' } }, [numberId]: {} } } : {}),
				};
				const manifestPath = project({ name: 'app', version: '1.0.0', dependencies: { [name]: reference } }, lock);
				const before = snapshot(root);
				const sbom = JSON.parse(new Pnpm()[method](manifestPath).content);

				expect(sbom.components.map(component => component.purl).sort()).to.deep.equal(method === 'provideStack'
					? [purl, 'pkg:npm/is-number@7.0.0'].sort() : [purl]);
				expect(sbom.components.find(component => component.purl === purl).hashes).to.deep.equal([
					{ alg: 'SHA-512', content: Buffer.from(IS_ODD.slice('sha512-'.length), 'base64').toString('hex') },
				]);
				if (method === 'provideStack') {
					expect(sbom.dependencies.find(dependency => dependency.ref === purl).dependsOn).to.include('pkg:npm/is-number@7.0.0');
				}
				expect(snapshot(root)).to.deep.equal(before);

				if (!registry) {
					delete archive.version;
					fs.writeFileSync(path.join(root, 'pnpm-lock.yaml'), JSON.stringify(lock));
					expect(() => new Pnpm()[method](manifestPath)).to.throw(/missing or invalid locked package version/);
				}
			});
		}
	}

	/// Verifies lockfileVersion 6 graphs (leading-slash keys, inline dependencies) are read.
	test('reads lockfileVersion 6 graphs with inline dependencies and hashes', () => {
		// Given a v6 lockfile keyed by `/name@version` with dependencies inline
		const manifestPath = project({ name: 'appv6', version: '1.0.0', dependencies: { 'is-odd': '3.0.1' } }, {
			lockfileVersion: '6.0',
			dependencies: { 'is-odd': { specifier: '3.0.1', version: '3.0.1' } },
			packages: {
				'/is-odd@3.0.1': { resolution: { integrity: IS_ODD }, dependencies: { 'is-number': '6.0.0' } },
				'/is-number@6.0.0': { resolution: { integrity: IS_NUMBER6 } },
			},
		});

		// When building the SBOM
		const sbom = stack(manifestPath);

		// Then both the direct and transitive packages are present with their edge and hash
		expect(sbom.components.map(c => c.purl).sort()).to.deep.equal(['pkg:npm/is-number@6.0.0', 'pkg:npm/is-odd@3.0.1']);
		expect(edge(sbom, 'is-odd@3.0.1', 'is-number@6.0.0')).to.be.true;
		expect(sbom.components.find(c => c.name === 'is-odd').hashes).to.deep.equal([{ alg: 'SHA-512', content: Buffer.from(IS_ODD.slice('sha512-'.length), 'base64').toString('hex') }]);
	});

	/// Verifies a multi-document stream is read from its last document (pnpm 12+).
	test('reads the project graph from the last document of a multi-document stream', () => {
		// Given a two-document lockfile whose first document carries no graph
		const header = { lockfileVersion: '9.0', importers: { '.': {} } };
		const graph = {
			lockfileVersion: '9.0',
			importers: { '.': { dependencies: { 'is-odd': { specifier: '3.0.1', version: '3.0.1' } } } },
			packages: { 'is-odd@3.0.1': { resolution: { integrity: IS_ODD } }, 'is-number@6.0.0': { resolution: { integrity: IS_NUMBER6 } } },
			snapshots: { 'is-odd@3.0.1': { dependencies: { 'is-number': '6.0.0' } }, 'is-number@6.0.0': {} },
		};
		const stream = `${JSON.stringify(header)}\n---\n${JSON.stringify(graph)}`;
		const manifestPath = project({ name: 'appmd', version: '1.0.0', dependencies: { 'is-odd': '3.0.1' } }, stream);

		// When building the SBOM (and confirming a single-document parse would fail)
		expect(() => yamlLoad(stream)).to.throw();
		const sbom = stack(manifestPath);

		// Then the graph comes from the last document
		expect(sbom.components.map(c => c.purl).sort()).to.deep.equal(['pkg:npm/is-number@6.0.0', 'pkg:npm/is-odd@3.0.1']);
	});

	/// Verifies unsupported lockfile versions are rejected with an actionable error.
	test('rejects an unsupported lockfile version', () => {
		const manifestPath = project({ name: 'appold', version: '1.0.0', dependencies: {} }, {
			lockfileVersion: '5.4', dependencies: {}, packages: {},
		});
		expect(() => stack(manifestPath)).to.throw(/Unsupported pnpm lockfile version 5\.4/);
	});

	/// Verifies file: directory dependencies resolve through their local manifest.
	test('resolves a file: directory dependency through its local manifest', () => {
		// Given a file: dependency backed by an on-disk package directory
		fs.mkdirSync(path.join(root, 'local'));
		fs.writeFileSync(path.join(root, 'local', 'package.json'), JSON.stringify({ name: 'local', version: '2.0.0', dependencies: { 'is-number': '7.0.0' } }));
		const manifestPath = project({ name: 'appfl', version: '1.0.0', dependencies: { local: 'file:./local' } }, {
			lockfileVersion: '9.0',
			importers: { '.': { dependencies: { local: { specifier: 'file:./local', version: 'file:local' } } } },
			packages: { 'local@file:local': { resolution: { directory: 'local', type: 'directory' } }, 'is-number@7.0.0': { resolution: { integrity: IS_NUMBER7 } } },
			snapshots: { 'local@file:local': { dependencies: { 'is-number': '7.0.0' } }, 'is-number@7.0.0': {} },
		});

		// When building the SBOM
		const sbom = stack(manifestPath);

		// Then the local package adopts its manifest identity and its edge is kept
		expect(sbom.components.map(c => c.purl).sort()).to.deep.equal(['pkg:npm/is-number@7.0.0', 'pkg:npm/local@2.0.0']);
		expect(edge(sbom, 'local@2.0.0', 'is-number@7.0.0')).to.be.true;

		// And a missing local manifest is rejected rather than silently skipped
		fs.rmSync(path.join(root, 'local'), { recursive: true });
		expect(() => stack(manifestPath)).to.throw(/missing local package manifest/);
	});

	/// Verifies a link: dependency to a non-workspace directory is rejected.
	test('rejects a link: dependency that provides no package metadata', () => {
		const manifestPath = project({ name: 'applink', version: '1.0.0', dependencies: { linked: 'link:./linked' } }, {
			lockfileVersion: '9.0',
			importers: { '.': { dependencies: { linked: { specifier: 'link:./linked', version: 'link:./linked' } } } },
			packages: {}, snapshots: {},
		});
		expect(() => stack(manifestPath)).to.throw(/link protocol does not provide package dependency metadata/);
	});
});
