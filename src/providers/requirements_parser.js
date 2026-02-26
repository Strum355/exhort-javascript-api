import { createRequire } from 'node:module';

import { Language, Parser, Query } from 'web-tree-sitter';

const require = createRequire(import.meta.url);

async function init() {
	await Parser.init({
		locateFile() {
			return require.resolve('web-tree-sitter/web-tree-sitter.wasm')
		}
	});
	return await Language.load(require.resolve('tree-sitter-requirements/tree-sitter-requirements.wasm'));
}

export async function getParser() {
	const language = await init();
	return new Parser().setLanguage(language);
}

export async function getRequirementQuery() {
	const language = await init();
	return new Query(language, '(requirement (package) @name) @req');
}

export async function getIgnoreQuery() {
	const language = await init();
	return new Query(language, '((requirement (package) @name) @req . (comment) @comment (#match? @comment "^#[\\t ]*exhortignore"))');
}

export async function getPinnedVersionQuery() {
	const language = await init();
	return new Query(language, '(version_spec (version_cmp) @cmp (version) @version (#eq? @cmp "=="))');
}
