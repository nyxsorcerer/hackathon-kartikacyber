import js from "@eslint/js";
import tseslint from "typescript-eslint";
export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      globals: {
        window: "readonly",
        document: "readonly",
        fetch: "readonly",
        FormData: "readonly",
        Headers: "readonly",
        RequestInit: "readonly",
        URL: "readonly",
        AbortController: "readonly",
        crypto: "readonly",
        File: "readonly",
        setTimeout: "readonly",
        clearTimeout: "readonly",
        setInterval: "readonly",
        clearInterval: "readonly",
        CustomEvent: "readonly",
        process: "readonly",
      },
    },
    rules: {
      // A15: diffs, reports, agent output and Transcripts render as escaped text, never raw HTML.
      "no-restricted-syntax": [
        "error",
        {
          // The JSX attribute, a props object key (createElement, spreads) or a member access.
          selector:
            ":matches(JSXIdentifier, Identifier)[name='dangerouslySetInnerHTML'], Literal[value='dangerouslySetInnerHTML']",
          message:
            "A15: render as escaped text; dangerouslySetInnerHTML is not allowed.",
        },
        {
          selector:
            "AssignmentExpression[left.property.name=/^(innerHTML|outerHTML)$/]",
          message:
            "A15: render as escaped text; writing innerHTML or outerHTML is not allowed.",
        },
        {
          selector: "CallExpression[callee.property.name='insertAdjacentHTML']",
          message:
            "A15: render as escaped text; insertAdjacentHTML is not allowed.",
        },
      ],
    },
  },
);
