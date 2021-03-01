import { wasm } from "@rollup/plugin-wasm";
import { terser } from "rollup-plugin-terser";

let plugins = [
  wasm({ maxFileSize: 1000000000 }),
  {
    name: "requireToGlobal",
    transform(code, id) {
      let matches = code.match(/require\((['"`])([^\1\n\r]*)(\1)\)/gi);
      if (matches) {
        matches.forEach((m) => {
          let mm = m.match(/require\((['"`])([^\1\n\r]*)(\1)\)/);
          code = code.replace(mm[0], `globalThis.${mm[2]}`);
        });
      }
      code = code.replace("var ENVIRONMENT_IS_NODE", "ENVIRONMENT_IS_NODE");
      return code;
    },
  },
];
export default [
  {
    input: "./src/js/index.mjs",
    output: {
      intro: "let ENVIRONMENT_IS_NODE = typeof process === 'object' && typeof process.versions === 'object' && typeof process.versions.node === 'string';",
      file: "dist/index.mjs",
      format: "esm",
    },
    external: ["fs", "path", "crypto"],
    plugins,
  },
  {
    input: "./src/js/index.mjs",
    output: {
      intro: "let ENVIRONMENT_IS_NODE = typeof process === 'object' && typeof process.versions === 'object' && typeof process.versions.node === 'string';",
      file: "dist/index.min.mjs",
      format: "esm",
    },
    external: ["fs", "path", "crypto"],
    plugins: plugins.concat(terser()),
  },
];
