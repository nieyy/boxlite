/*
 * Copyright 2025 BoxLite AI
 * SPDX-License-Identifier: AGPL-3.0
 */

import * as http from 'http'
import { AddressInfo } from 'net'
import { RunnerAdapterV2 } from './runnerAdapter.v2'
import { Runner } from '../entities/runner.entity'

function buildAdapter(): RunnerAdapterV2 {
  // boxRepository/jobRepository/jobService are unused by init/enableSSHAccess/
  // disableSSHAccess, so plain stubs are sufficient for this test's scope.
  return new RunnerAdapterV2({} as any, {} as any, {} as any)
}

describe('RunnerAdapterV2 direct SSH runner call retry', () => {
  it('enableSSHAccess retries after a transient connection reset and eventually succeeds', async () => {
    // Reproducer: the runner connection resets (ECONNRESET) on the first two
    // attempts, then succeeds. Without axios-retry configured on the direct
    // axios instance, enableSSHAccess would reject on the first reset instead
    // of retrying — a real difference in behavior an assertion can observe.
    let attempts = 0
    const server = http.createServer((req, res) => {
      attempts += 1
      if (attempts <= 2) {
        // Forcibly reset the connection without responding — the client sees
        // ECONNRESET, the same class of transient error a real network blip
        // between the API and a runner would produce.
        req.socket.destroy()
        return
      }
      let body = ''
      req.on('data', (chunk) => (body += chunk))
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ ok: true, body: JSON.parse(body || '{}') }))
      })
    })

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const port = (server.address() as AddressInfo).port

    try {
      const adapter = buildAdapter()
      const runner = { id: 'runner-1', apiUrl: `http://127.0.0.1:${port}`, apiKey: 'test-key' } as Runner
      await adapter.init(runner)

      await adapter.enableSSHAccess('box-1', 'boxlite')

      expect(attempts).toBeGreaterThanOrEqual(3)
    } finally {
      server.close()
    }
  })
})
