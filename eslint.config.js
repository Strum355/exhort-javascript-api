import js from "@eslint/js";
import importPlugin from "eslint-plugin-import-x";
import globals from "globals";

export default [
	js.configs.recommended,
	{
		plugins: {
			"import-x": importPlugin,
		},
		languageOptions: {
			ecmaVersion: 2022,
			sourceType: "module",
			globals: {
				...globals.node,
				...globals.mocha,
				...globals.es2021,
			},
		},
		rules: {
			...importPlugin.configs.recommended.rules,
			"no-unused-vars": ["error", { "caughtErrors": "none" }],
			"preserve-caught-error": "off",
			// editorconfig enforcement (replaces eslint-plugin-editorconfig)
			"eol-last": ["error", "always"],
			"indent": ["error", "tab"],
			"linebreak-style": ["error", "unix"],
			"no-trailing-spaces": "error",
			"unicode-bom": ["error", "never"],
			"curly": "warn",
			"eqeqeq": ["warn", "always", {"null": "never"}],
			"no-throw-literal": "warn",
			"import-x/order": ["warn", {
				"groups": ["builtin", "external", "internal", "parent", "sibling", "index"],
				"newlines-between": "always",
				"alphabetize": {
					"order": "asc",
					"caseInsensitive": true,
				},
			}],
		},
		settings: {
			"typescript": {},
			"import-x/resolver": {
				"typescript": {
					"extensions": [".js"],
				},
			},
		},
	},
	{
		ignores: ["index.js", "dist/**"],
	},
];
