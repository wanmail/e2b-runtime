import { Sandbox } from 'e2b'

const apiUrl = process.env.E2B_API_URL
const apiKey = process.env.E2B_API_KEY
const sandboxId = process.env.SANDBOX_ID
const sandboxUrl = process.env.E2B_SANDBOX_URL
const marker = process.env.MARKER || 'e2e'
const path = process.env.GUEST_PATH || '/'
const dest = process.env.GUEST_DEST || 'http://203.0.113.80'
const host = process.env.GUEST_HOST || 'api.github.com'
const method = (process.env.GUEST_METHOD || 'GET').toUpperCase()
if (!apiUrl || !apiKey || !sandboxId || !sandboxUrl) {
  console.error('need E2B_API_URL E2B_API_KEY SANDBOX_ID E2B_SANDBOX_URL')
  process.exit(2)
}

const sbx = await Sandbox.connect(sandboxId, { apiUrl, apiKey, sandboxUrl })
await sbx.commands.run('echo guest-ready', { timeoutMs: 30_000 })

let cmd
if (method === 'GET') {
  cmd = `curl -sS -m 20 -X GET '${dest}${path}' -H 'Host: ${host}' -H 'X-Smoke: egresstunnel' -H 'X-E2E-Marker: ${marker}'`
} else {
  cmd = `curl -sS -m 20 -X ${method} '${dest}${path}' -H 'Host: ${host}' -H 'X-Smoke: egresstunnel' -d '${marker}'`
}
const r = await sbx.commands.run(cmd, { timeoutMs: 60_000 })
console.log(JSON.stringify({ exitCode: r.exitCode, stdout: r.stdout, stderr: r.stderr }))
if (r.exitCode !== 0) process.exit(1)
