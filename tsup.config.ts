import { defineConfig } from "tsup";

export default defineConfig({
  entry: { authkit: "src/authkit.ts" },
  format: ["iife"],
  splitting: false,
  sourcemap: true,
  dts: false,
  minify: false,
  outExtension: () => ({ js: ".js" }),
  clean: true,
  outDir: "dist",
});
