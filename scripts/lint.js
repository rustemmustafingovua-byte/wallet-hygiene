import { readdirSync, statSync } from "node:fs"
import { spawnSync } from "node:child_process"
import { join } from "node:path"

const roots = ["bin", "src", "test", "scripts"]
const files = []

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name)
    if (statSync(path).isDirectory()) walk(path)
    else if (name.endsWith(".js")) files.push(path)
  }
}

for (const root of roots) walk(root)

let failed = false
for (const file of files) {
  const result = spawnSync(process.execPath, ["--check", file], { stdio: "inherit" })
  if (result.status !== 0) failed = true
}

if (failed) process.exit(1)
