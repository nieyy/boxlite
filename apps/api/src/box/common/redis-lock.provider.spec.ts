/*
 * Copyright 2025 BoxLite AI
 * SPDX-License-Identifier: AGPL-3.0
 */

import { RedisLockProvider } from './redis-lock.provider'

function buildProvider(setResult: string | null) {
  const redis = {
    set: jest.fn().mockResolvedValue(setResult),
    get: jest.fn().mockResolvedValue(null),
    del: jest.fn().mockResolvedValue(1),
    exists: jest.fn().mockResolvedValue(0),
  }
  const provider = new RedisLockProvider(redis as any)
  return { provider, redis }
}

describe('RedisLockProvider lock-acquisition timeout', () => {
  it('waitForLockOwned throws instead of hanging forever when the lock is never released', async () => {
    // Reproducer: redis.set (used by lock()) never succeeds — simulating a lock
    // holder that crashed without releasing and hasn't hit TTL expiry yet, or a
    // permanently deadlocked holder. Without a timeout, this loop retries every
    // 50ms forever and the caller (e.g. createSshAccess/revokeSshAccess) hangs
    // indefinitely instead of surfacing an error.
    const { provider } = buildProvider(null)

    await expect(provider.waitForLockOwned('test-key', 1, 30)).rejects.toThrow(
      /Timed out after 30ms waiting for lock test-key/,
    )
  })

  it('waitForLock throws instead of hanging forever when the lock is never released', async () => {
    const { provider } = buildProvider(null)

    await expect(provider.waitForLock('test-key', 1, 30)).rejects.toThrow(
      /Timed out after 30ms waiting for lock test-key/,
    )
  })

  it('waitForLockOwned resolves immediately when the lock is free', async () => {
    const { provider, redis } = buildProvider('OK')

    const code = await provider.waitForLockOwned('test-key', 90)

    expect(code.getCode()).toEqual(expect.any(String))
    expect(redis.set).toHaveBeenCalledTimes(1)
  })
})
