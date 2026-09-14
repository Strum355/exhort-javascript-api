import { spawn } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { expect } from 'chai'

import { loadConfig, mergeConfig, resolveConfig, CONFIG_FILENAMES } from '../src/config.js'

const [CONFIG_FILENAME] = CONFIG_FILENAMES

const testDir = path.dirname(fileURLToPath(import.meta.url))
const validDir = path.join(testDir, 'fixtures', 'config', 'valid')
const invalidDir = path.join(testDir, 'fixtures', 'config', 'invalid')
const projectRoot = path.resolve(testDir, '..')
const minimalPackageJson = '{"name":"cli-config-test","version":"1.0.0"}'
const minimalPackageLock = JSON.stringify({
	name: 'cli-config-test',
	version: '1.0.0',
	lockfileVersion: 3,
	requires: true,
	packages: { '': { name: 'cli-config-test', version: '1.0.0' } },
})
const CLI_TIMEOUT_MS = 8_000

/**
 * Creates a fresh temporary directory outside the repository tree so config
 * discovery walks up to the filesystem root without finding a real config file.
 * @returns {string} absolute path to the temp directory
 */
function makeTempDir() {
	return fs.mkdtempSync(path.join(os.tmpdir(), 'trustify-da-config-'))
}

/** Runs the CLI without inheriting configuration environment variables. */
function runCli(args, env = {}, cwd = projectRoot) {
	const childEnv = Object.fromEntries(
		Object.entries(process.env).filter(([key]) => !key.startsWith('TRUSTIFY_DA_'))
	)
	Object.assign(childEnv, env)
	return new Promise((resolve, reject) => {
		const child = spawn(process.execPath, [path.join(projectRoot, 'src', 'cli.js'), ...args], { cwd, env: childEnv })
		let stdout = ''
		let stderr = ''
		let settled = false
		const timeout = setTimeout(() => {
			if (settled) {
				return
			}
			settled = true
			child.kill('SIGTERM')
			reject(new Error(`CLI timed out after ${CLI_TIMEOUT_MS}ms: ${args.join(' ')}`))
		}, CLI_TIMEOUT_MS)
		child.stdout.on('data', data => { stdout += data })
		child.stderr.on('data', data => { stderr += data })
		child.on('error', error => {
			if (!settled) {
				settled = true
				clearTimeout(timeout)
				reject(error)
			}
		})
		child.on('close', code => {
			if (!settled) {
				settled = true
				clearTimeout(timeout)
				resolve({ code, stdout, stderr })
			}
		})
	})
}

suite('loadConfig', () => {
	test('parses a valid config file and exposes all sections', () => {
		// Given a directory containing a valid .trustify-da.yml
		// When loading the config
		const config = loadConfig(validDir)

		// Then top-level and nested sections are accessible
		expect(config['backend-url']).to.equal('https://da.example.com')
		expect(config.providers).to.deep.equal(['redhat', 'lightwell'])
		expect(config.sources).to.deep.equal(['osv'])
		expect(config.remediation['group-by']).to.equal('bundle')
		expect(config.remediation.exclude).to.deep.equal(['pkg:maven/com.example/legacy-lib'])
		expect(config.check['fail-on']).to.deep.equal({ critical: 0, high: 10, 'license-conflicts': 0 })
		expect(config.sbom).to.deep.equal({ format: 'cyclonedx', targets: ['artifact', 'trustify'] })
	})

	test('parses nested remediation, check, and sbom sections correctly', () => {
		// Given a valid config file
		const config = loadConfig(validDir)

		// Then each nested section retains its structure
		expect(config.remediation.labels).to.deep.equal(['trustify-da', 'security'])
		expect(config.remediation['branch-prefix']).to.equal('trustify-da/')
		expect(config.check['fail-on'].high).to.equal(10)
		expect(config.sbom.targets).to.deep.equal(['artifact', 'trustify'])
	})

	test('returns an empty object when no config file is found', () => {
		// Given a temp directory with no config file anywhere up the tree
		const tmp = makeTempDir()
		try {
			// When loading the config
			// Then an empty object (defaults) is returned instead of throwing
			expect(loadConfig(tmp)).to.deep.equal({})
		} finally {
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})

	test('returns an empty object for a non-existent path', () => {
		// Given a path that does not exist
		const tmp = makeTempDir()
		try {
			// When loading the config from a missing child path
			// Then discovery still walks up gracefully and returns defaults
			expect(loadConfig(path.join(tmp, 'does', 'not', 'exist'))).to.deep.equal({})
		} finally {
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})

	test('accepts a file path and discovers the config in its directory', () => {
		// Given the config file path itself (a file, not a directory)
		const filePath = path.join(validDir, CONFIG_FILENAME)

		// When loading the config
		// Then discovery starts from the containing directory and finds it
		expect(loadConfig(filePath).providers).to.deep.equal(['redhat', 'lightwell'])
	})

	test('throws a descriptive error for malformed YAML', () => {
		// Given a directory with a malformed .trustify-da.yml
		// When loading the config
		// Then a descriptive error naming the file is thrown
		expect(() => loadConfig(invalidDir)).to.throw(/Failed to parse config file/)
	})

	const invalidSchemaConfigs = [
		['a sequence root', '- redhat\n', 'root must be a mapping'],
		['a timestamp root', '2026-09-10\n', 'root must be a mapping'],
		['a non-string backend URL', 'backend-url: 42\n', 'backend-url must be a string'],
		['a non-string provider', 'providers: [redhat, 42]\n', 'providers must be an array of strings'],
		['a scalar remediation section', 'remediation: invalid\n', 'remediation must be a mapping'],
		['an invalid grouping strategy', 'remediation:\n  group-by: invalid\n', 'remediation.group-by must be dependency or bundle'],
		['a non-string remediation exclusion', 'remediation:\n  exclude: [pkg:maven/example, 42]\n', 'remediation.exclude must be an array of strings'],
		['a sequence check section', 'check: []\n', 'check must be a mapping'],
		['a scalar fail-on section', 'check:\n  fail-on: invalid\n', 'check.fail-on must be a mapping'],
		['a non-numeric failure threshold', 'check:\n  fail-on:\n    critical: invalid\n', 'check.fail-on.critical must be a finite number'],
		['a scalar SBOM section', 'sbom: invalid\n', 'sbom must be a mapping'],
		['a non-string SBOM format', 'sbom:\n  format: 42\n', 'sbom.format must be a string'],
		['a non-string SBOM target', 'sbom:\n  targets: [artifact, 42]\n', 'sbom.targets must be an array of strings'],
	]
	invalidSchemaConfigs.forEach(([scenario, content, message]) => {
		test(`rejects ${scenario}`, () => {
			const tmp = makeTempDir()
			try {
				fs.writeFileSync(path.join(tmp, CONFIG_FILENAME), content)
				expect(() => loadConfig(tmp)).to.throw(message)
			} finally {
				fs.rmSync(tmp, { recursive: true, force: true })
			}
		})
	})

	test('discovers a config file in a parent directory (walks up)', () => {
		// Given a config file at the top of a nested temp tree
		const tmp = makeTempDir()
		try {
			fs.writeFileSync(path.join(tmp, CONFIG_FILENAME), 'providers: [redhat]\n')
			const deep = path.join(tmp, 'a', 'b', 'c')
			fs.mkdirSync(deep, { recursive: true })

			// When loading from a deeply nested subdirectory
			// Then discovery walks up and finds the ancestor config
			expect(loadConfig(deep).providers).to.deep.equal(['redhat'])
		} finally {
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})

	test('skips a config path that is not a regular file', () => {
		const tmp = makeTempDir()
		try {
			fs.writeFileSync(path.join(tmp, CONFIG_FILENAME), 'providers: [redhat]\n')
			const child = path.join(tmp, 'child')
			fs.mkdirSync(path.join(child, CONFIG_FILENAME), { recursive: true })

			expect(loadConfig(child).providers).to.deep.equal(['redhat'])
		} finally {
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})
})

suite('mergeConfig', () => {
	const fileConfig = {
		'backend-url': 'https://file.example.com',
		providers: ['redhat', 'lightwell'],
		sources: ['osv'],
		remediation: { 'group-by': 'bundle' },
		check: { 'fail-on': { critical: 0 } },
		sbom: { format: 'cyclonedx' },
	}

	test('uses file config values when no CLI flags or env vars are set', () => {
		// Given only a file config
		const merged = mergeConfig(fileConfig, {}, {})

		// Then file values are used and normalized to arrays
		expect(merged.providers).to.deep.equal(['redhat', 'lightwell'])
		expect(merged.sources).to.deep.equal(['osv'])
		expect(merged.groupBy).to.equal('bundle')
		expect(merged.backendUrl).to.equal('https://file.example.com')
		expect(merged.backendUrlSource).to.equal('file')
	})

	test('CLI flags override config file values', () => {
		// Given a file config and a CLI flag for providers
		const merged = mergeConfig(fileConfig, {
			backendUrl: 'https://cli.example.com',
			providers: 'snyk,osv',
			groupBy: 'dependency',
		}, {})

		// Then the CLI flag wins over the file value
		expect(merged.providers).to.deep.equal(['snyk', 'osv'])
		expect(merged.groupBy).to.equal('dependency')
		expect(merged.backendUrl).to.equal('https://cli.example.com')
		expect(merged.backendUrlSource).to.equal('cli')
	})

	test('CLI flags override environment variables and config file', () => {
		// Given a file config, environment variables, and CLI flags
		const env = { TRUSTIFY_DA_PROVIDERS: 'env-provider', TRUSTIFY_DA_SOURCES: 'env-source' }

		// When only environment variables are set, they override the file value
		const envOnly = mergeConfig(fileConfig, {}, env)
		expect(envOnly.providers).to.deep.equal(['env-provider'])
		expect(envOnly.sources).to.deep.equal(['env-source'])

		// When both a CLI flag and environment variable are set, the CLI flag wins
		const withCli = mergeConfig(fileConfig, { providers: 'cli-provider' }, env)
		expect(withCli.providers).to.deep.equal(['cli-provider'])
		expect(withCli.sources).to.deep.equal(['env-source'])
	})

	test('falls back to hardcoded defaults with empty inputs', () => {
		// Given no config at all
		const merged = mergeConfig()

		// Then empty collections and the default group-by are returned
		expect(merged.providers).to.deep.equal([])
		expect(merged.sources).to.deep.equal([])
		expect(merged.groupBy).to.equal('dependency')
		expect(merged.backendUrl).to.equal(null)
		expect(merged.backendUrlSource).to.equal('default')
	})

	test('rejects an invalid group-by value', () => {
		// Given a group-by value outside the supported strategies
		// When merging configuration
		// Then a descriptive validation error is thrown
		expect(() => mergeConfig({}, { groupBy: 'invalid' }, {}))
			.to.throw('Invalid group-by value "invalid"')
	})

	test('rejects an invalid file config passed directly', () => {
		expect(() => mergeConfig({ check: [] }, {}, {}))
			.to.throw('check must be a mapping')
	})

	test('CLI empty string overrides environment variable for providers', () => {
		// Given an environment variable and an explicitly empty CLI flag
		const env = { TRUSTIFY_DA_PROVIDERS: 'env-provider' }
		const merged = mergeConfig({}, { providers: '' }, env)

		// Then the empty CLI value wins over the environment value
		expect(merged.providers).to.deep.equal([])
	})

	test('CLI empty string overrides environment variable for backendUrl', () => {
		// Given an environment variable and an explicitly empty CLI flag
		const env = { TRUSTIFY_DA_BACKEND_URL: 'https://env.example.com' }
		const merged = mergeConfig({}, { backendUrl: '' }, env)

		// Then the empty CLI value wins over the environment value
		expect(merged.backendUrl).to.equal('')
		expect(merged.backendUrlSource).to.equal('cli')
	})
})

suite('resolveConfig', () => {
	test('loads project config and returns resolved command values', () => {
		// Given a project path containing .trustify-da.yml
		// When resolving command configuration
		const resolved = resolveConfig(validDir, {}, {})

		// Then supported command values are available in their runtime form
		expect(resolved.providers).to.deep.equal(['redhat', 'lightwell'])
		expect(resolved.sources).to.deep.equal(['osv'])
		expect(resolved.groupBy).to.equal('bundle')
	})

	test('applies environment overrides while resolving project config', () => {
		// Given project defaults and environment overrides
		const env = {
			TRUSTIFY_DA_PROVIDERS: 'env-provider',
			TRUSTIFY_DA_GROUP_BY: 'dependency',
		}

		// When resolving command configuration
		const resolved = resolveConfig(validDir, {}, env)

		// Then environment values override the project defaults
		expect(resolved.providers).to.deep.equal(['env-provider'])
		expect(resolved.groupBy).to.equal('dependency')
	})

	test('does not fall back to the file when an environment value is empty', () => {
		// Given a file backend URL and an explicitly empty environment override
		const env = { TRUSTIFY_DA_BACKEND_URL: '' }

		// When resolving command configuration
		const resolved = resolveConfig(validDir, {}, env)

		// Then the explicit empty value is retained
		expect(resolved.backendUrl).to.equal('')
		expect(resolved.backendUrlSource).to.equal('environment')
	})
})

suite('CLI configuration', function () {
	this.timeout(10_000)

	test('applies backend, providers, and sources from .trustify-da.yml', async () => {
		const tmp = makeTempDir()
		const requests = []
		const server = http.createServer((request, response) => {
			requests.push(new URL(request.url, `http://${request.headers.host}`))
			request.resume()
			response.writeHead(200, { 'content-type': 'application/json' })
			response.end(JSON.stringify({ providers: {} }))
		})
		try {
			await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
			const { port } = server.address()
			fs.writeFileSync(path.join(tmp, CONFIG_FILENAME), [
				`backend-url: http://127.0.0.1:${port}`,
				'providers: [redhat, osv]',
				'sources: [osv]',
			].join('\n'))
			fs.writeFileSync(path.join(tmp, 'package.json'), minimalPackageJson)
			fs.writeFileSync(path.join(tmp, 'package-lock.json'), minimalPackageLock)

			const result = await runCli(['stack', path.join(tmp, 'package.json')])

			expect(result.code, result.stderr).to.equal(0)
			expect(requests).to.have.length(1)
			expect(requests[0].pathname).to.equal('/api/v5/analysis')
			expect(requests[0].searchParams.get('providers')).to.equal('redhat,osv')
			expect(requests[0].searchParams.get('sources')).to.equal('osv')
		} finally {
			await new Promise(resolve => server.close(resolve))
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})

	test('applies backend, providers, and sources from .trustify-da.yml for component', async () => {
		const tmp = makeTempDir()
		const requests = []
		const server = http.createServer((request, response) => {
			requests.push(new URL(request.url, `http://${request.headers.host}`))
			request.resume()
			response.writeHead(200, { 'content-type': 'application/json' })
			response.end(JSON.stringify({ providers: {} }))
		})
		try {
			await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
			const { port } = server.address()
			fs.writeFileSync(path.join(tmp, CONFIG_FILENAME), [
				`backend-url: http://127.0.0.1:${port}`,
				'providers: [redhat, osv]',
				'sources: [osv]',
			].join('\n'))
			fs.writeFileSync(path.join(tmp, 'package.json'), minimalPackageJson)
			fs.writeFileSync(path.join(tmp, 'package-lock.json'), minimalPackageLock)

			const result = await runCli(['component', path.join(tmp, 'package.json')])

			expect(result.code, result.stderr).to.equal(0)
			expect(requests).to.have.length(1)
			expect(requests[0].searchParams.get('providers')).to.equal('redhat,osv')
			expect(requests[0].searchParams.get('sources')).to.equal('osv')
		} finally {
			await new Promise(resolve => server.close(resolve))
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})

	test('applies backend, providers, and sources from .trustify-da.yml for stack-batch', async () => {
		const tmp = makeTempDir()
		const requests = []
		const server = http.createServer((request, response) => {
			requests.push(new URL(request.url, `http://${request.headers.host}`))
			request.resume()
			response.writeHead(200, { 'content-type': 'application/json' })
			response.end('{}')
		})
		try {
			await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
			const { port } = server.address()
			fs.writeFileSync(path.join(tmp, CONFIG_FILENAME), [
				`backend-url: http://127.0.0.1:${port}`,
				'providers: [redhat, osv]',
				'sources: [osv]',
			].join('\n'))
			fs.writeFileSync(path.join(tmp, 'package.json'), minimalPackageJson)
			fs.writeFileSync(path.join(tmp, 'package-lock.json'), minimalPackageLock)

			const result = await runCli(['stack-batch', tmp])

			expect(result.code, result.stderr).to.equal(0)
			expect(requests).to.have.length(1)
			expect(requests[0].pathname).to.equal('/api/v5/batch-analysis')
			expect(requests[0].searchParams.get('providers')).to.equal('redhat,osv')
			expect(requests[0].searchParams.get('sources')).to.equal('osv')
		} finally {
			await new Promise(resolve => server.close(resolve))
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})

	test('discovers image command configuration from the current working directory', async () => {
		const tmp = makeTempDir()
		const requests = []
		const server = http.createServer((request, response) => {
			requests.push(new URL(request.url, `http://${request.headers.host}`))
			request.resume()
			response.writeHead(200, { 'content-type': 'application/json' })
			response.end('{}')
		})
		try {
			await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
			const { port } = server.address()
			const syftPath = path.join(tmp, 'fake-syft.mjs')
			fs.writeFileSync(syftPath, [
				'#!/usr/bin/env node',
				"process.stdout.write(JSON.stringify({ metadata: { component: {} } }))",
			].join('\n'))
			fs.chmodSync(syftPath, 0o755)
			fs.writeFileSync(path.join(tmp, CONFIG_FILENAME), [
				`backend-url: http://127.0.0.1:${port}`,
				'providers: [redhat, osv]',
				'sources: [osv]',
			].join('\n'))
			const digest = 'a'.repeat(64)

			const result = await runCli(
				['image', `example@sha256:${digest}`],
				{ TRUSTIFY_DA_SYFT_PATH: syftPath },
				tmp
			)

			expect(result.code, result.stderr).to.equal(0)
			expect(requests).to.have.length(1)
			expect(requests[0].pathname).to.equal('/api/v5/batch-analysis')
			expect(requests[0].searchParams.get('providers')).to.equal('redhat,osv')
			expect(requests[0].searchParams.get('sources')).to.equal('osv')
		} finally {
			await new Promise(resolve => server.close(resolve))
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})

	test('an explicitly empty CLI provider value overrides the environment', async () => {
		const tmp = makeTempDir()
		const requests = []
		const server = http.createServer((request, response) => {
			requests.push(new URL(request.url, `http://${request.headers.host}`))
			request.resume()
			response.writeHead(200, { 'content-type': 'application/json' })
			response.end(JSON.stringify({ providers: {} }))
		})
		try {
			await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
			const { port } = server.address()
			fs.writeFileSync(path.join(tmp, CONFIG_FILENAME), `backend-url: http://127.0.0.1:${port}\n`)
			fs.writeFileSync(path.join(tmp, 'package.json'), minimalPackageJson)
			fs.writeFileSync(path.join(tmp, 'package-lock.json'), minimalPackageLock)

			const result = await runCli(['stack', path.join(tmp, 'package.json'), '--providers', ''], {
				TRUSTIFY_DA_PROVIDERS: 'env-provider',
			})

			expect(result.code, result.stderr).to.equal(0)
			expect(requests).to.have.length(1)
			expect(requests[0].searchParams.has('providers')).to.equal(false)
		} finally {
			await new Promise(resolve => server.close(resolve))
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})

	test('rejects a token when the backend is selected by project configuration', async () => {
		const tmp = makeTempDir()
		const requests = []
		const server = http.createServer((request, response) => {
			requests.push(request)
			request.resume()
			response.writeHead(200, { 'content-type': 'application/json' })
			response.end(JSON.stringify({ providers: {} }))
		})
		try {
			await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
			const { port } = server.address()
			fs.writeFileSync(path.join(tmp, CONFIG_FILENAME), `backend-url: http://127.0.0.1:${port}\n`)
			fs.writeFileSync(path.join(tmp, 'package.json'), minimalPackageJson)
			fs.writeFileSync(path.join(tmp, 'package-lock.json'), minimalPackageLock)

			const result = await runCli(['stack', path.join(tmp, 'package.json')], {
				TRUSTIFY_DA_TOKEN: 'secret-token',
			})

			expect(result.code).to.equal(1)
			expect(result.stderr).to.include('Refusing to send TRUSTIFY_DA_TOKEN')
			expect(requests).to.have.length(0)
		} finally {
			await new Promise(resolve => server.close(resolve))
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})

	test('allows a token when the backend is explicitly selected by environment', async () => {
		const tmp = makeTempDir()
		const requests = []
		const server = http.createServer((request, response) => {
			requests.push(request)
			request.resume()
			response.writeHead(200, { 'content-type': 'application/json' })
			response.end(JSON.stringify({ providers: {} }))
		})
		try {
			await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
			const { port } = server.address()
			fs.writeFileSync(path.join(tmp, CONFIG_FILENAME), 'backend-url: https://untrusted.example.com\n')
			fs.writeFileSync(path.join(tmp, 'package.json'), minimalPackageJson)
			fs.writeFileSync(path.join(tmp, 'package-lock.json'), minimalPackageLock)

			const result = await runCli(['stack', path.join(tmp, 'package.json')], {
				TRUSTIFY_DA_BACKEND_URL: `http://127.0.0.1:${port}`,
				TRUSTIFY_DA_TOKEN: 'secret-token',
			})

			expect(result.code, result.stderr).to.equal(0)
			expect(requests).to.have.length(1)
			expect(requests[0].headers['trust-da-token']).to.equal('secret-token')
		} finally {
			await new Promise(resolve => server.close(resolve))
			fs.rmSync(tmp, { recursive: true, force: true })
		}
	})

})
