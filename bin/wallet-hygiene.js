#!/usr/bin/env node
import { redact } from "../src/privacy.js"
import { run } from "../src/cli.js"

const bad = (s) => `\x1b[31m${s}\x1b[0m`

try {
  const code = await run(process.argv.slice(2))
  if (code) process.exit(code)
} catch (err) {
  console.error(bad(redact(err?.message || err)))
  process.exit(1)
}
