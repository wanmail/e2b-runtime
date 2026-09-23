import { Template } from 'e2b'

const apiUrl = process.env.E2B_API_URL
const apiKey = process.env.E2B_API_KEY
const alias = process.env.TEMPLATE_ALIAS
if (!apiUrl || !apiKey || !alias) {
  console.error('need E2B_API_URL E2B_API_KEY TEMPLATE_ALIAS')
  process.exit(2)
}

const force = process.env.FORCE_REBUILD === '1'
const res = await fetch(`${apiUrl}/templates`, { headers: { 'X-API-Key': apiKey } })
if (!res.ok) throw new Error(`GET /templates ${res.status}`)
const templates = await res.json()
const existing = templates.find(
  (t) => [...(t.aliases ?? []), ...(t.names ?? [])].includes(alias) && t.buildStatus === 'ready',
)
if (existing && !force) {
  console.log(
    JSON.stringify({
      reused: true,
      alias,
      templateID: existing.templateID,
      buildID: existing.buildID,
    }),
  )
  process.exit(0)
}

const started = Date.now()
const tpl = await Template.build(Template().fromBaseImage(), alias, {
  memoryMB: Number(process.env.TEMPLATE_MEMORY_MB || 512),
  cpuCount: Number(process.env.TEMPLATE_CPU_COUNT || 2),
  onBuildLogs: (entry) => console.error(String(entry)),
})
console.log(
  JSON.stringify({
    reused: false,
    alias,
    templateID: tpl.templateId ?? tpl.templateID,
    buildID: tpl.buildId ?? tpl.buildID,
    doneInSec: Math.round((Date.now() - started) / 1000),
  }),
)
