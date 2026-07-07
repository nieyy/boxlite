/*
 * Copyright 2025 Daytona Platforms Inc.
 * Modified by BoxLite AI, 2025-2026
 * SPDX-License-Identifier: AGPL-3.0
 */

import { InjectRedis } from '@nestjs-modules/ioredis'
import { Injectable } from '@nestjs/common'
import { Redis } from 'ioredis'

type Acquired = boolean

export class LockCode {
  constructor(private readonly code: string) {}

  public getCode(): string {
    return this.code
  }
}

@Injectable()
export class RedisLockProvider {
  constructor(@InjectRedis() private readonly redis: Redis) {}

  async lock(key: string, ttl: number, code?: LockCode | null): Promise<Acquired> {
    const keyValue = code ? code.getCode() : '1'
    const acquired = await this.redis.set(key, keyValue, 'EX', ttl, 'NX')
    return !!acquired
  }

  async getCode(key: string): Promise<LockCode | null> {
    const keyValue = await this.redis.get(key)
    return keyValue ? new LockCode(keyValue) : null
  }

  async unlock(key: string): Promise<void> {
    await this.redis.del(key)
  }

  async isLocked(key: string): Promise<boolean> {
    const exists = await this.redis.exists(key)
    return exists === 1
  }

  // timeoutMs defaults to 2x ttl (in ms): a well-behaved holder releases within
  // ttl seconds, and TTL-expiry is the backstop for a crashed holder, so a
  // waiter should tolerate up to roughly one full TTL window of legitimate
  // contention before giving up. Without a bound, a holder that never releases
  // (bug, deadlock) hangs every waiter forever instead of surfacing an error.
  async waitForLock(key: string, ttl: number, timeoutMs: number = ttl * 1000 * 2): Promise<void> {
    const startedAt = Date.now()
    while (true) {
      const acquired = await this.lock(key, ttl)
      if (acquired) return
      if (Date.now() - startedAt > timeoutMs) {
        throw new Error(`Timed out after ${timeoutMs}ms waiting for lock ${key}`)
      }
      await new Promise((resolve) => setTimeout(resolve, 50))
    }
  }

  // Acquires the lock identified by key, returning the LockCode needed to release it.
  // The caller must pass the returned LockCode to unlockOwned or the lock will remain
  // held until TTL expiry. See waitForLock for the timeoutMs default rationale.
  async waitForLockOwned(key: string, ttl: number, timeoutMs: number = ttl * 1000 * 2): Promise<LockCode> {
    const code = new LockCode(`${Date.now()}-${Math.random().toString(36).slice(2)}`)
    const startedAt = Date.now()
    while (true) {
      const acquired = await this.lock(key, ttl, code)
      if (acquired) return code
      if (Date.now() - startedAt > timeoutMs) {
        throw new Error(`Timed out after ${timeoutMs}ms waiting for lock ${key}`)
      }
      await new Promise((resolve) => setTimeout(resolve, 50))
    }
  }

  // Compare-and-delete: only removes the key if its current value matches code.
  // Prevents an expired lock holder from deleting a concurrent caller's lock.
  async unlockOwned(key: string, code: LockCode): Promise<void> {
    const script = `
      if redis.call('get',KEYS[1]) == ARGV[1] then
        return redis.call('del',KEYS[1])
      else
        return 0
      end`
    await (this.redis as any).eval(script, 1, key, code.getCode())
  }

  // Returns true if key currently holds the value encoded in code.
  async isLockOwned(key: string, code: LockCode): Promise<boolean> {
    const val = await this.redis.get(key)
    return val === code.getCode()
  }
}
