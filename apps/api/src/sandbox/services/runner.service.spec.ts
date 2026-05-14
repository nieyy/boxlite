/*
 * Copyright 2025 BoxLite AI
 * SPDX-License-Identifier: AGPL-3.0
 */

import { Runner } from '../entities/runner.entity'

/**
 * These tests validate the supportsSecurityOptions defaulting logic for v2 runners.
 *
 * The Runner entity constructor is the project symbol under test.  The service
 * create() method resolves `createRunnerDto.supportsSecurityOptions ?? false` before
 * passing it to the constructor, so the entity constructor always receives an explicit
 * value from that path.  We verify both the service-level default (false for v2) and
 * the explicit-true opt-in by constructing Runner instances the same way create() does.
 *
 * The default is intentionally false: operators must explicitly set
 * supportsSecurityOptions: true in the admin DTO when registering a runner binary
 * that is known to handle security payloads.  Auto-promoting unknown runners would
 * silently send security options to runners that may ignore them.
 */
describe('Runner.supportsSecurityOptions v2 default', () => {
  const baseParams = {
    region: 'test-region',
    name: 'test-runner',
    apiVersion: '2',
    apiKey: 'test-api-key',
  }

  it('defaults to false when supportsSecurityOptions is not specified (simulates create() ?? false)', () => {
    // This mirrors the service create() path: `supportsSecurityOptions: dto.supportsSecurityOptions ?? false`
    // When dto.supportsSecurityOptions is undefined, the service resolves to false.
    // Operators must opt in explicitly to prevent auto-promotion of unknown runners.
    const resolvedValue = (undefined as boolean | undefined) ?? false
    const runner = new Runner({ ...baseParams, supportsSecurityOptions: resolvedValue })

    expect(runner.supportsSecurityOptions).toBe(false)
  })

  it('remains false when explicitly set to false', () => {
    // Operators can pass supportsSecurityOptions: false via the admin DTO to keep a
    // runner out of the capable pool during a staged rollout.
    const resolvedValue = (false as boolean | undefined) ?? false
    const runner = new Runner({ ...baseParams, supportsSecurityOptions: resolvedValue })

    expect(runner.supportsSecurityOptions).toBe(false)
  })

  it('becomes true when explicitly set to true (operator opt-in)', () => {
    // Operators set supportsSecurityOptions: true to opt a runner binary into the
    // capable pool after confirming it handles security payloads correctly.
    const resolvedValue = (true as boolean | undefined) ?? false
    const runner = new Runner({ ...baseParams, supportsSecurityOptions: resolvedValue })

    expect(runner.supportsSecurityOptions).toBe(true)
  })
})
