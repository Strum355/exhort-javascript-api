/**
 * Report generator that transforms remediation extractor output into structured
 * markdown for PR bodies, CLI dry-run output, and JSON.
 */

import { SEVERITY_ORDER, maxSeverity } from './remediation.js'

/**
 * Generates a formatted report from an array of remediation entries.
 *
 * @param {import('./remediation.js').Remediation[]} remediations
 * @param {object} [options]
 * @param {'dependency'|'bundle'} [options.groupBy='dependency'] - grouping strategy
 * @param {'markdown'|'json'} [options.format='markdown'] - output format
 * @param {boolean} [options.dryRun=false] - when true, produces tabular summary
 * @returns {string}
 */
export function generateReport(remediations, options = {}) {
	const { groupBy = 'dependency', format = 'markdown', dryRun = false } = options

	if (!remediations || remediations.length === 0) {
		return format === 'json' ? '[]' : 'No remediations found.'
	}

	if (format === 'json') {
		return JSON.stringify(remediations, null, '\t')
	}

	if (dryRun) {
		return generateDryRunReport(remediations)
	}

	if (groupBy === 'bundle') {
		return generateBundledReport(remediations)
	}

	return generatePerDependencyReport(remediations)
}

/**
 * Generates a per-dependency markdown report with one section per remediation entry.
 *
 * Each vulnerability row is rendered from its own per-CVE severity and advisories
 * (from `rem.vulnerabilities`), so a Moderate CVE is no longer inflated to the
 * dependency's max severity.
 * @param {import('./remediation.js').Remediation[]} remediations
 * @returns {string}
 */
function generatePerDependencyReport(remediations) {
	const sections = remediations.map(rem => {
		const depName = rem.groupId
			? `${rem.groupId}:${rem.artifactId}`
			: rem.artifactId

		const lines = [
			`## Security Update: ${depName} ${rem.currentVersion} → ${rem.fixedInVersion}`,
			'',
			`**Provider:** ${rem.provider} | **Source:** ${rem.source}`,
			'',
		]

		const vulnerabilities = rem.vulnerabilities || []
		if (vulnerabilities.length > 0) {
			lines.push('### Vulnerabilities resolved')
			lines.push('')
			lines.push('| CVE | Severity | Advisory |')
			lines.push('| --- | --- | --- |')
			for (const v of vulnerabilities) {
				lines.push(`| ${v.id} | ${v.severity} | ${formatAdvisoryLinks(v.advisories)} |`)
			}
		}

		return lines.join('\n')
	})

	return sections.join('\n\n')
}

/**
 * Generates a bundled markdown report grouping all remediations by severity.
 * @param {import('./remediation.js').Remediation[]} remediations
 * @returns {string}
 */
function generateBundledReport(remediations) {
	const lines = ['# Security Update Summary', '']

	const bySeverity = groupBySeverity(remediations)

	for (const severity of [...SEVERITY_ORDER].reverse()) {
		const group = bySeverity.get(severity)
		if (!group || group.length === 0) {
			continue
		}

		lines.push(`## ${severity}`)
		lines.push('')
		lines.push('| Dependency | Current | Fixed | Provider | CVEs | Advisory |')
		lines.push('| --- | --- | --- | --- | --- | --- |')

		for (const rem of group) {
			const depName = rem.groupId
				? `${rem.groupId}:${rem.artifactId}`
				: rem.artifactId
			const vulnerabilities = rem.vulnerabilities || []
			const cves = vulnerabilities.map(v => v.id).join(', ')
			const advisoryLinks = formatAdvisoryLinks(collectAdvisories(vulnerabilities))
			lines.push(
				`| ${depName} | ${rem.currentVersion} | ${rem.fixedInVersion}`
				+ ` | ${rem.provider} | ${cves} | ${advisoryLinks} |`
			)
		}

		lines.push('')
	}

	return lines.join('\n').trimEnd()
}

/**
 * Generates a tabular dry-run summary of proposed changes.
 * @param {import('./remediation.js').Remediation[]} remediations
 * @returns {string}
 */
function generateDryRunReport(remediations) {
	const lines = [
		'Proposed dependency updates:',
		'',
		'| Dependency | Current | Fixed | Severity | Provider |',
		'| --- | --- | --- | --- | --- |',
	]

	for (const rem of remediations) {
		const depName = rem.groupId
			? `${rem.groupId}:${rem.artifactId}`
			: rem.artifactId
		lines.push(
			`| ${depName} | ${rem.currentVersion} | ${rem.fixedInVersion}`
			+ ` | ${maxSeverity(rem.vulnerabilities)} | ${rem.provider} |`
		)
	}

	return lines.join('\n')
}

/**
 * Groups remediations by their severity.
 * @param {import('./remediation.js').Remediation[]} remediations
 * @returns {Map<string, Array<object>>}
 */
function groupBySeverity(remediations) {
	const map = new Map()
	for (const severity of SEVERITY_ORDER) {
		map.set(severity, [])
	}
	for (const rem of remediations) {
		const sev = maxSeverity(rem.vulnerabilities)
		if (!map.has(sev)) {
			map.set(sev, [])
		}
		map.get(sev).push(rem)
	}
	return map
}

/**
 * Collects the de-duplicated union of advisories across a list of vulnerabilities.
 * @param {Array<{advisories: Array<{id: string, url: string}>}>} vulnerabilities
 * @returns {Array<{id: string, url: string}>}
 */
function collectAdvisories(vulnerabilities) {
	const merged = []
	const seen = new Set()
	for (const v of vulnerabilities) {
		for (const adv of v.advisories || []) {
			if (!seen.has(adv.id)) {
				seen.add(adv.id)
				merged.push(adv)
			}
		}
	}
	return merged
}

/**
 * Formats advisory entries into markdown links or plain text.
 * @param {Array<{id: string, url: string}>} advisories
 * @returns {string}
 */
function formatAdvisoryLinks(advisories) {
	if (!advisories || advisories.length === 0) {
		return '-'
	}
	return advisories
		.map(adv => adv.url ? `[${adv.id}](${adv.url})` : adv.id)
		.join(', ')
}

/**
 * Generates a deterministic deduplication key for a remediation entry.
 * Suitable for checking existing PR titles or branch names.
 *
 * @param {object} remediation - a single remediation entry
 * @returns {string} stable key in the form `groupId:artifactId:newVersion`
 */
export function generateDeduplicationKey(remediation) {
	const group = remediation.groupId || ''
	const artifact = remediation.artifactId || ''
	const version = remediation.fixedInVersion || ''
	return `${group}:${artifact}:${version}`
}
