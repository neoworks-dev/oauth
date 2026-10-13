import { expect, test } from "bun:test"
import { Glob } from "bun"
import { readFileSync } from "node:fs"
import { join } from "node:path"

// The CSP allows Svelte's own Trusted Types policy; {@html} would route runtime data through it.
test("the vault views never render raw HTML", () => {
  const uiDirectory = join(import.meta.dir, "..", "ui")
  const offenders: string[] = []
  for (const file of new Glob("**/*.svelte").scanSync(uiDirectory)) {
    if (readFileSync(join(uiDirectory, file), "utf8").includes("{@html")) {
      offenders.push(file)
    }
  }
  expect(offenders).toEqual([])
})
