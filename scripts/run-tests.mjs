import { spawnSync } from "node:child_process"
import { readdirSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const root = join(dirname(fileURLToPath(import.meta.url)), "..")
const testDirectory = join(root, "test")
const testFiles = readdirSync(testDirectory)
  .filter(name => name.endsWith(".test.mjs"))
  .sort()
  .map(name => join(testDirectory, name))

if (testFiles.length === 0) {
  console.error("No test files found in test/")
  process.exit(1)
}

const result = spawnSync(process.execPath, ["--test", "--test-reporter=spec", ...testFiles], {
  cwd: root,
  stdio: "inherit"
})

process.exit(result.status ?? 1)
