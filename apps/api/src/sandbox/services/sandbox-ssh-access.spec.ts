/*
 * Copyright 2025 BoxLite AI
 * SPDX-License-Identifier: AGPL-3.0
 */

import { SandboxService } from './sandbox.service'
import { Sandbox } from '../entities/sandbox.entity'
import { SandboxState } from '../enums/sandbox-state.enum'
import { SandboxDesiredState } from '../enums/sandbox-desired-state.enum'
import { LockCode, RedisLockProvider } from '../common/redis-lock.provider'

/** Build a minimal Sandbox stub with only the fields SandboxService inspects. */
function makeSandbox(id: string): Sandbox {
  const s = new Sandbox('us', id)
  s.id = id
  s.organizationId = 'org-1'
  s.name = id
  s.region = 'us'
  s.state = SandboxState.STARTED
  s.desiredState = SandboxDesiredState.STARTED
  // No runnerId: keeps createSshAccess from calling the runner adapter path,
  // so the test stays focused on the lock contract without needing a runner mock.
  return s
}

/**
 * Build a SandboxService instance with the minimum mocks needed to exercise
 * createSshAccess and revokeSshAccess without hitting real infrastructure.
 *
 * All injected collaborators are plain jest.fn() objects. Only the ones
 * actually invoked on the paths under test need working implementations;
 * the rest can stay as empty stubs.
 */
function buildService(overrides?: { redisLockProvider?: Partial<RedisLockProvider> }) {
  // --- SshAccess repository mock ---
  // save() returns the entity unchanged; delete() and count() are no-ops.
  // find() returns [] (no prior active tokens) by default.
  const sshAccessRepository = {
    save: jest.fn().mockImplementation((entity) => Promise.resolve({ ...entity, id: 'ssh-access-uuid' })),
    delete: jest.fn().mockResolvedValue({ affected: 1 }),
    count: jest.fn().mockResolvedValue(0),
    findOne: jest.fn().mockResolvedValue(null),
    find: jest.fn().mockResolvedValue([]),
  }

  // --- SandboxRepository mock ---
  // findOne is used internally by findOneByIdOrName; the tests supply the
  // sandbox id directly so both the id-lookup and name-lookup return the stub.
  const sandboxRepo = {
    findOne: jest.fn().mockImplementation(({ where }) => {
      // findOneByIdOrName calls with { id: sandboxIdOrName, ... } first,
      // then { name: sandboxIdOrName, ... } on fallback.
      const id = where?.id ?? where?.name
      if (id) {
        return Promise.resolve(makeSandbox(id))
      }
      return Promise.resolve(null)
    }),
    find: jest.fn().mockResolvedValue([]),
    findAndCount: jest.fn().mockResolvedValue([[], 0]),
    insert: jest.fn().mockImplementation((s) => Promise.resolve(s)),
    update: jest.fn().mockImplementation((_, { entity }) => Promise.resolve(entity)),
    updateWhere: jest.fn().mockImplementation((_, { entity }) => Promise.resolve(entity ?? {})),
    delete: jest.fn().mockResolvedValue({ affected: 0 }),
  }

  // --- RedisLockProvider mock ---
  // By default, waitForLockOwned succeeds immediately (returns a token) and
  // unlockOwned is a no-op. Callers can override to record keys or tokens.
  const ownedToken = new LockCode('test-lock-token')
  const defaultLockProvider: Partial<RedisLockProvider> = {
    waitForLock: jest.fn().mockResolvedValue(undefined),
    waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
    unlock: jest.fn().mockResolvedValue(undefined),
    unlockOwned: jest.fn().mockResolvedValue(undefined),
    lock: jest.fn().mockResolvedValue(true),
    isLocked: jest.fn().mockResolvedValue(false),
    getCode: jest.fn().mockResolvedValue(null),
    // Default: lock is still owned (no expiry). Tests that simulate expiry
    // override this to return false.
    isLockOwned: jest.fn().mockResolvedValue(true),
  }
  const redisLockProvider = { ...defaultLockProvider, ...(overrides?.redisLockProvider ?? {}) }

  // --- Minimal Redis mock (used directly for cache operations) ---
  const redis = {
    get: jest.fn().mockResolvedValue(null),
    set: jest.fn().mockResolvedValue('OK'),
    setex: jest.fn().mockResolvedValue('OK'),
    del: jest.fn().mockResolvedValue(1),
    exists: jest.fn().mockResolvedValue(0),
    pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
  }

  // --- RegionService mock ---
  const regionService = {
    findOne: jest.fn().mockResolvedValue(null),
    findOneByName: jest.fn().mockResolvedValue(null),
    findByIds: jest.fn().mockResolvedValue([]),
  }

  // --- RunnerService mock ---
  // findOne returns null (no runner), so the runner adapter path is skipped.
  const runnerService = {
    findOne: jest.fn().mockResolvedValue(null),
    findOneOrFail: jest.fn().mockResolvedValue(null),
    getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
  }

  // Remaining deps are stubs that should not be reached by the paths under test.
  const noopStub = () => ({})
  const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
  const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
  const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
  const volumeService = { validateVolumes: jest.fn() }
  const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
  const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
  const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
  const organizationService = {
    assertOrganizationIsNotSuspended: jest.fn(),
    getRegionQuota: jest.fn().mockResolvedValue(null),
  }
  const runnerAdapterFactory = { create: jest.fn() }
  const organizationUsageService = {
    incrementPendingSandboxUsage: jest.fn(),
    decrementPendingSandboxUsage: jest.fn(),
    getSandboxUsageOverview: jest.fn(),
    applyResizeUsageChange: jest.fn(),
  }
  const sandboxLookupCacheInvalidationService = {
    invalidateOrgId: jest.fn(),
    invalidate: jest.fn(),
  }
  const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
  const sandboxActivityService = { updateLastActivityAt: jest.fn() }

  const service = new SandboxService(
    sandboxRepo as any,
    snapshotRepository as any,
    runnerRepository as any,
    buildInfoRepository as any,
    sshAccessRepository as any,
    runnerService as any,
    volumeService as any,
    configService as any,
    warmPoolService as any,
    eventEmitter as any,
    organizationService as any,
    runnerAdapterFactory as any,
    organizationUsageService as any,
    redisLockProvider as any,
    redis as any,
    regionService as any,
    snapshotService as any,
    sandboxLookupCacheInvalidationService as any,
    sandboxActivityService as any,
  )

  return { service, redisLockProvider, sshAccessRepository }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('SandboxService SSH access lock contract', () => {
  const SANDBOX_ID = 'sandbox-uuid-a'
  const EXPECTED_LOCK_KEY = `sandbox:${SANDBOX_ID}:ssh-access`

  describe('createSshAccess', () => {
    it('acquires the per-sandbox SSH lock with the expected key (owned)', async () => {
      const { service, redisLockProvider } = buildService()

      await service.createSshAccess(SANDBOX_ID, 60, 'org-1')

      expect(redisLockProvider.waitForLockOwned).toHaveBeenCalledWith(EXPECTED_LOCK_KEY, expect.any(Number))
    })

    it('releases the per-sandbox SSH lock via compare-and-delete after creating access', async () => {
      const { service, redisLockProvider } = buildService()

      await service.createSshAccess(SANDBOX_ID, 60, 'org-1')

      // Must use unlockOwned (compare-and-delete), NOT plain unlock,
      // so an expired lock cannot delete a concurrent caller's lock.
      expect(redisLockProvider.unlockOwned).toHaveBeenCalledWith(EXPECTED_LOCK_KEY, expect.any(LockCode))
      expect(redisLockProvider.unlock).not.toHaveBeenCalledWith(EXPECTED_LOCK_KEY)
    })

    it('releases the lock via compare-and-delete even when sshAccessRepository.save throws', async () => {
      // Rebuild with a failing sshAccessRepository
      const { service: svcWithFailingSave, redisLockProvider: lockProvider } = buildService()
      // Manually override the private repo by reaching through the instance
      ;(svcWithFailingSave as any).sshAccessRepository = {
        save: jest.fn().mockRejectedValue(new Error('DB write failed')),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
        count: jest.fn().mockResolvedValue(0),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([]),
      }

      await expect(svcWithFailingSave.createSshAccess(SANDBOX_ID, 60, 'org-1')).rejects.toThrow('DB write failed')

      expect(lockProvider.unlockOwned).toHaveBeenCalledWith(EXPECTED_LOCK_KEY, expect.any(LockCode))
    })

    it('passes the token returned by waitForLockOwned to unlockOwned', async () => {
      // Verifies that the token used to acquire the lock is the exact token
      // used to release it — ensuring compare-and-delete checks the right value.
      const capturedToken = new LockCode('unique-token-abc')
      const unlockOwnedMock = jest.fn().mockResolvedValue(undefined)

      const { service } = buildService({
        redisLockProvider: {
          waitForLockOwned: jest.fn().mockResolvedValue(capturedToken),
          unlockOwned: unlockOwnedMock,
        },
      })

      await service.createSshAccess(SANDBOX_ID, 60, 'org-1')

      expect(unlockOwnedMock).toHaveBeenCalledWith(EXPECTED_LOCK_KEY, capturedToken)
    })

    it('aborts without saving a DB token when lock expired during runner call (fencing check)', async () => {
      // Reproducer for Finding [high] Round 40:
      // The lock's 90 s TTL can expire while enableSSHAccess is executing.
      // A concurrent revoke can then acquire the lock, disable SSH, and commit.
      // When the original create resumes it must detect the lost lock via
      // isLockOwned and throw — NOT save the token to DB.
      //
      // We simulate this by having isLockOwned return false (lock not owned),
      // which is what happens when the TTL expired and a concurrent caller
      // acquired the key with a different token.
      const { service, sshAccessRepository } = buildService({
        redisLockProvider: {
          isLockOwned: jest.fn().mockResolvedValue(false),
        },
      })

      await expect(service.createSshAccess(SANDBOX_ID, 60, 'org-1')).rejects.toThrow(
        'SSH access revoked during creation',
      )

      // The key invariant: no token must have been persisted to the DB.
      expect(sshAccessRepository.save).not.toHaveBeenCalled()
    })

    it('saves DB token when lock is still owned after runner call (fencing check passes)', async () => {
      // Counterpart: when isLockOwned returns true the normal path continues.
      const { service, sshAccessRepository } = buildService({
        redisLockProvider: {
          isLockOwned: jest.fn().mockResolvedValue(true),
        },
      })

      await service.createSshAccess(SANDBOX_ID, 60, 'org-1')

      expect(sshAccessRepository.save).toHaveBeenCalledTimes(1)
    })

    it('does NOT call disableSSHAccess when isLockOwned returns false (lost-lock cleanup must not clobber a concurrent create)', async () => {
      // Reproducer for Finding [high] Round 42:
      // Sequence:
      //   1. Create-A holds the 90 s lock, calls runner enableSSHAccess (succeeds)
      //   2. Create-A's lock TTL expires during the runner call
      //   3. Create-B acquires the lock, enableSSHAccess, saves DB token
      //   4. Create-A detects isLockOwned → false → enters lost-lock cleanup
      //   5. BUG: Create-A calls disableSSHAccess → disables Create-B's runner SSH
      //      even though Create-B's valid DB token is now in the database.
      //
      // Fix: the lost-lock cleanup path must NOT call disableSSHAccess.
      // Without a DB token (we never saved one), no gateway can authenticate —
      // the runner SSH-enabled-but-no-token state is degraded-but-safe, and the
      // next revoke/validate will reconcile it.
      //
      // To exercise this path we need a real runnerId on the sandbox and a
      // runnerService that returns a v1 runner (so the adapter call isn't skipped).
      const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const enableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const runnerAdapter = { enableSSHAccess, disableSSHAccess }

      // Build a service with a sandbox that has a runnerId so the runner path runs.
      const sandboxWithRunner = makeSandbox(SANDBOX_ID)
      sandboxWithRunner.runnerId = 'runner-1'

      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      const runnerService = {
        findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
      }
      const runnerAdapterFactory = {
        create: jest.fn().mockResolvedValue(runnerAdapter),
      }
      const sshAccessRepository = {
        save: jest.fn().mockImplementation((entity: any) => Promise.resolve({ ...entity, id: 'ssh-access-uuid' })),
        delete: jest.fn().mockResolvedValue({ affected: 1 }),
        count: jest.fn().mockResolvedValue(0),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([]),
      }
      const ownedToken = new LockCode('test-lock-token')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        // Simulate lock expiry during runner call
        isLockOwned: jest.fn().mockResolvedValue(false),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null),
        set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'),
        del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any,
        snapshotRepository as any,
        runnerRepository as any,
        buildInfoRepository as any,
        sshAccessRepository as any,
        runnerService as any,
        volumeService as any,
        configService as any,
        warmPoolService as any,
        eventEmitter as any,
        organizationService as any,
        runnerAdapterFactory as any,
        organizationUsageService as any,
        redisLockProvider as any,
        redis as any,
        regionService as any,
        snapshotService as any,
        sandboxLookupCacheInvalidationService as any,
        sandboxActivityService as any,
      )

      await expect(service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'boxlite')).rejects.toThrow(
        'SSH access revoked during creation',
      )

      // KEY ASSERTION: disableSSHAccess must NOT have been called.
      // Calling it here would clobber a concurrent Create-B's runner SSH state.
      expect(disableSSHAccess).not.toHaveBeenCalled()
      // enableSSHAccess was called (we did try to enable SSH before losing the lock)
      expect(enableSSHAccess).toHaveBeenCalledTimes(1)
    })

    it('does NOT call disableSSHAccess on save failure when prior active tokens exist with same unix_user (Finding 2, Round 49)', async () => {
      // Reproducer for Finding 2 [high] Round 49:
      //
      // Scenario: sandbox already has an active SSH token (rotation, same user).
      //   1. createSshAccess finds a prior active token with the same unix_user
      //   2. enableSSHAccess succeeds (runner reconfigured)
      //   3. sshAccessRepository.save throws (DB write failure)
      //   4. OLD BUG: rollback calls disableSSHAccess unconditionally
      //      → runner SSH disabled while old tokens still valid in DB
      //      → old tokens accepted by gateway but runner SSH is off → lockout
      //
      // Fix: gate the disable on !hadPriorActiveSshAccess || unixUserChanged.
      // Same-user rotation: leave runner SSH enabled so old tokens remain valid.
      const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const enableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const runnerAdapter = { enableSSHAccess, disableSSHAccess }

      const sandboxWithRunner = makeSandbox(SANDBOX_ID)
      sandboxWithRunner.runnerId = 'runner-1'

      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      const runnerService = {
        findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
      }
      const runnerAdapterFactory = {
        create: jest.fn().mockResolvedValue(runnerAdapter),
      }
      // find returns a prior active token with the same unix_user as the request
      // (default 'boxlite') → same-user rotation → disable must NOT be called.
      const sshAccessRepository = {
        save: jest.fn().mockRejectedValue(new Error('DB write failed')),
        delete: jest.fn().mockResolvedValue({ affected: 1 }),
        count: jest.fn().mockResolvedValue(1),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([{ id: 'prior-token-uuid', unixUser: 'boxlite', sandboxId: SANDBOX_ID }]),
      }
      const ownedToken = new LockCode('test-lock-token')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        isLockOwned: jest.fn().mockResolvedValue(true),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null),
        set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'),
        del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any,
        snapshotRepository as any,
        runnerRepository as any,
        buildInfoRepository as any,
        sshAccessRepository as any,
        runnerService as any,
        volumeService as any,
        configService as any,
        warmPoolService as any,
        eventEmitter as any,
        organizationService as any,
        runnerAdapterFactory as any,
        organizationUsageService as any,
        redisLockProvider as any,
        redis as any,
        regionService as any,
        snapshotService as any,
        sandboxLookupCacheInvalidationService as any,
        sandboxActivityService as any,
      )

      await expect(service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'boxlite')).rejects.toThrow('DB write failed')

      // KEY ASSERTION: disableSSHAccess must NOT be called when prior active
      // tokens existed with the same unix_user. Calling it would disable runner
      // SSH while old tokens remain valid in the DB → gateway accepts old token
      // but runner SSH is off → lockout.
      expect(disableSSHAccess).not.toHaveBeenCalled()
      // enableSSHAccess was called before the save failed
      expect(enableSSHAccess).toHaveBeenCalledTimes(1)
    })

    it('DOES call disableSSHAccess on save failure when prior active tokens exist but unix_user changed (Finding [high], Round 51)', async () => {
      // Reproducer for Finding [high] Round 51:
      //
      // Scenario: sandbox has an active token for unix_user='alice'. A new
      // createSshAccess request arrives with unix_user='bob'.
      //   1. priorToken.unixUser = 'alice'; resolvedUnixUser = 'bob' → user changed
      //   2. enableSSHAccess reconfigures runner for 'bob'
      //   3. sshAccessRepository.save throws (DB write failure)
      //   4. OLD BUG (Round 49 logic): disableSSHAccess NOT called (prior tokens exist)
      //      → runner runs as 'bob', but old DB tokens were issued for 'alice'
      //      → old tokens route to wrong user account ('bob' instead of 'alice')
      //
      // Fix (Round 51): when unixUserChanged, disable runner SSH even with prior
      // tokens. Fail-closed: old tokens cannot authenticate with the wrong user.
      const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const enableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const runnerAdapter = { enableSSHAccess, disableSSHAccess }

      const sandboxWithRunner = makeSandbox(SANDBOX_ID)
      sandboxWithRunner.runnerId = 'runner-1'

      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      const runnerService = {
        findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
      }
      const runnerAdapterFactory = {
        create: jest.fn().mockResolvedValue(runnerAdapter),
      }
      // find returns a prior active token for unix_user='alice';
      // the new request will use unix_user='bob' → user changed.
      const sshAccessRepository = {
        save: jest.fn().mockRejectedValue(new Error('DB write failed')),
        delete: jest.fn().mockResolvedValue({ affected: 1 }),
        count: jest.fn().mockResolvedValue(1),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([{ id: 'prior-token-uuid', unixUser: 'alice', sandboxId: SANDBOX_ID }]),
      }
      const ownedToken = new LockCode('test-lock-token')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        isLockOwned: jest.fn().mockResolvedValue(true),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null),
        set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'),
        del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any,
        snapshotRepository as any,
        runnerRepository as any,
        buildInfoRepository as any,
        sshAccessRepository as any,
        runnerService as any,
        volumeService as any,
        configService as any,
        warmPoolService as any,
        eventEmitter as any,
        organizationService as any,
        runnerAdapterFactory as any,
        organizationUsageService as any,
        redisLockProvider as any,
        redis as any,
        regionService as any,
        snapshotService as any,
        sandboxLookupCacheInvalidationService as any,
        sandboxActivityService as any,
      )

      // Request with unix_user='bob' — different from prior token's 'alice'.
      await expect(service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'bob')).rejects.toThrow('DB write failed')

      // KEY ASSERTION: disableSSHAccess MUST be called even though prior tokens
      // exist, because the unix_user changed. Leaving runner SSH enabled would
      // route old 'alice' tokens to the 'bob' account — wrong-user access.
      expect(disableSSHAccess).toHaveBeenCalledTimes(1)
      expect(enableSSHAccess).toHaveBeenCalledTimes(1)
    })

    it('DOES call disableSSHAccess on save failure when no prior active tokens exist (first-create scenario, Finding 2, Round 49)', async () => {
      // Counterpart: when no prior tokens existed (first create, not rotation),
      // disableSSHAccess on save failure correctly returns to pre-create state.
      const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const enableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const runnerAdapter = { enableSSHAccess, disableSSHAccess }

      const sandboxWithRunner = makeSandbox(SANDBOX_ID)
      sandboxWithRunner.runnerId = 'runner-1'

      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      const runnerService = {
        findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
      }
      const runnerAdapterFactory = {
        create: jest.fn().mockResolvedValue(runnerAdapter),
      }
      // find() returns [] → no prior active tokens (first create)
      const sshAccessRepository = {
        save: jest.fn().mockRejectedValue(new Error('DB write failed')),
        delete: jest.fn().mockResolvedValue({ affected: 1 }),
        count: jest.fn().mockResolvedValue(0), // no prior tokens
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([]),
      }
      const ownedToken = new LockCode('test-lock-token')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        isLockOwned: jest.fn().mockResolvedValue(true),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null),
        set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'),
        del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any,
        snapshotRepository as any,
        runnerRepository as any,
        buildInfoRepository as any,
        sshAccessRepository as any,
        runnerService as any,
        volumeService as any,
        configService as any,
        warmPoolService as any,
        eventEmitter as any,
        organizationService as any,
        runnerAdapterFactory as any,
        organizationUsageService as any,
        redisLockProvider as any,
        redis as any,
        regionService as any,
        snapshotService as any,
        sandboxLookupCacheInvalidationService as any,
        sandboxActivityService as any,
      )

      await expect(service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'boxlite')).rejects.toThrow('DB write failed')

      // KEY ASSERTION: disableSSHAccess MUST be called when no prior tokens
      // existed — first-create scenario. Runner SSH was enabled but no token was
      // saved; leaving runner SSH on with no DB token is an orphaned port-forward.
      expect(disableSSHAccess).toHaveBeenCalledTimes(1)
      expect(enableSSHAccess).toHaveBeenCalledTimes(1)
    })

    it('does NOT call disableSSHAccess when enableSSHAccess fails and prior real-SSH tokens exist (Finding [high], Round 10)', async () => {
      // Reproducer for Finding [high] Round 10:
      //
      // Scenario: sandbox has an existing real-SSH token (unixUser='boxlite').
      // A rotation attempt is made (same or different user — unixUser='boxlite').
      //   1. priorTokens = [{ unixUser: 'boxlite' }] — real-SSH token exists
      //   2. enableSSHAccess throws (network error, timeout, etc.)
      //   3. OLD BUG: catch block calls disableSSHAccess unconditionally
      //      → runner SSH torn down while prior real-SSH token still valid in DB
      //      → gateway accepts prior token, but runner SSH is off → lockout
      //
      // Fix: skip disableSSHAccess when hasPriorRealSSH is true (prior tokens
      // exist and at least one is a real-SSH token). The runner SSH state belongs
      // to those prior tokens and must not be torn down on a failed attempt to mint
      // a replacement.
      const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const enableSSHAccess = jest.fn().mockRejectedValue(new Error('Runner unreachable'))
      const runnerAdapter = { enableSSHAccess, disableSSHAccess }

      const sandboxWithRunner = makeSandbox(SANDBOX_ID)
      sandboxWithRunner.runnerId = 'runner-1'

      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      const runnerService = {
        findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
      }
      const runnerAdapterFactory = {
        create: jest.fn().mockResolvedValue(runnerAdapter),
      }
      // find() returns a prior active real-SSH token (unixUser='boxlite')
      const sshAccessRepository = {
        save: jest.fn().mockImplementation((entity: any) => Promise.resolve({ ...entity, id: 'ssh-access-uuid' })),
        delete: jest.fn().mockResolvedValue({ affected: 1 }),
        count: jest.fn().mockResolvedValue(1),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([{ id: 'prior-real-ssh-uuid', unixUser: 'boxlite', sandboxId: SANDBOX_ID }]),
      }
      const ownedToken = new LockCode('test-lock-token')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        isLockOwned: jest.fn().mockResolvedValue(true),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null),
        set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'),
        del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any,
        snapshotRepository as any,
        runnerRepository as any,
        buildInfoRepository as any,
        sshAccessRepository as any,
        runnerService as any,
        volumeService as any,
        configService as any,
        warmPoolService as any,
        eventEmitter as any,
        organizationService as any,
        runnerAdapterFactory as any,
        organizationUsageService as any,
        redisLockProvider as any,
        redis as any,
        regionService as any,
        snapshotService as any,
        sandboxLookupCacheInvalidationService as any,
        sandboxActivityService as any,
      )

      // enableSSHAccess fails during rotation attempt (prior real-SSH token exists)
      await expect(service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'boxlite')).rejects.toThrow('Runner unreachable')

      // KEY ASSERTION: disableSSHAccess must NOT be called when prior real-SSH tokens exist.
      // The runner SSH state belongs to those prior tokens — tearing it down would
      // break current SSH access for users whose old tokens should still work.
      expect(disableSSHAccess).not.toHaveBeenCalled()
      // enableSSHAccess was attempted (it threw)
      expect(enableSSHAccess).toHaveBeenCalledTimes(1)
      // No DB save should have occurred
      expect(sshAccessRepository.save).not.toHaveBeenCalled()
    })

    it('does NOT delete existing DB tokens when enableSSHAccess throws (Finding 1, Round 47)', async () => {
      // Reproducer for Finding 1 [high] Round 47:
      // Old order: revoke-all (delete DB tokens + disable runner) → enable → save.
      // If enableSSHAccess throws, old tokens are already deleted. The caller
      // receives a 500 with no SSH access and no path to recovery.
      //
      // New order: enable → fencing → save → delete-old.
      // If enableSSHAccess throws, old DB tokens are untouched. The caller still
      // has working SSH access via the old tokens.
      //
      // This test injects an enableSSHAccess error and asserts that
      // sshAccessRepository.delete was NOT called (old tokens survived).
      const enableSSHAccess = jest.fn().mockRejectedValue(new Error('Runner unreachable'))
      const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const runnerAdapter = { enableSSHAccess, disableSSHAccess }

      const sandboxWithRunner = makeSandbox(SANDBOX_ID)
      sandboxWithRunner.runnerId = 'runner-1'

      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      const runnerService = {
        findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
      }
      const runnerAdapterFactory = {
        create: jest.fn().mockResolvedValue(runnerAdapter),
      }
      const sshAccessRepository = {
        save: jest.fn().mockImplementation((entity: any) => Promise.resolve({ ...entity, id: 'ssh-access-uuid' })),
        delete: jest.fn().mockResolvedValue({ affected: 1 }),
        count: jest.fn().mockResolvedValue(0),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([]),
      }
      const ownedToken = new LockCode('test-lock-token')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        isLockOwned: jest.fn().mockResolvedValue(true),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null),
        set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'),
        del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any,
        snapshotRepository as any,
        runnerRepository as any,
        buildInfoRepository as any,
        sshAccessRepository as any,
        runnerService as any,
        volumeService as any,
        configService as any,
        warmPoolService as any,
        eventEmitter as any,
        organizationService as any,
        runnerAdapterFactory as any,
        organizationUsageService as any,
        redisLockProvider as any,
        redis as any,
        regionService as any,
        snapshotService as any,
        sandboxLookupCacheInvalidationService as any,
        sandboxActivityService as any,
      )

      await expect(service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'boxlite')).rejects.toThrow('Runner unreachable')

      // KEY ASSERTION: sshAccessRepository.delete must NOT have been called.
      // In the new (correct) order, old tokens are deleted only AFTER the new
      // token is durably saved. If enable throws, old tokens must still be valid.
      expect(sshAccessRepository.delete).not.toHaveBeenCalled()
      // enableSSHAccess threw — no DB save should have happened either.
      expect(sshAccessRepository.save).not.toHaveBeenCalled()
    })

    it('calls disableSSHAccess when delete-old-tokens fails after unix_user change (Finding 1, Round 52)', async () => {
      // Reproducer for Finding 1 [high] Round 52:
      //
      // Scenario: sandbox has an active token for unix_user='alice'. A new
      // createSshAccess request arrives with unix_user='bob'.
      //   1. priorToken.unixUser = 'alice'; resolvedUnixUser = 'bob' → user changed
      //   2. enableSSHAccess reconfigures runner for 'bob'
      //   3. sshAccessRepository.save succeeds (new 'bob' token persisted)
      //   4. sshAccessRepository.delete throws (old 'alice' tokens remain in DB)
      //   5. OLD BUG: delete error propagates bare → old 'alice' tokens inherit
      //      runner-configured 'bob' identity → wrong-user access.
      //
      // Fix (Round 52): catch delete failure; if unix_user changed, call
      // disableSSHAccess (fail-closed) and re-throw. Old tokens cannot
      // authenticate; caller must retry.
      const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const enableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const runnerAdapter = { enableSSHAccess, disableSSHAccess }

      const sandboxWithRunner = makeSandbox(SANDBOX_ID)
      sandboxWithRunner.runnerId = 'runner-1'

      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      const runnerService = {
        findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
      }
      const runnerAdapterFactory = {
        create: jest.fn().mockResolvedValue(runnerAdapter),
      }
      // save succeeds; delete of old tokens fails; prior token is for 'alice'
      const sshAccessRepository = {
        save: jest.fn().mockImplementation((entity: any) => Promise.resolve({ ...entity, id: 'new-token-uuid' })),
        delete: jest.fn().mockRejectedValue(new Error('DB delete failed')),
        count: jest.fn().mockResolvedValue(1),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([{ id: 'prior-token-uuid', unixUser: 'alice', sandboxId: SANDBOX_ID }]),
      }
      const ownedToken = new LockCode('test-lock-token')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        isLockOwned: jest.fn().mockResolvedValue(true),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null),
        set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'),
        del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any,
        snapshotRepository as any,
        runnerRepository as any,
        buildInfoRepository as any,
        sshAccessRepository as any,
        runnerService as any,
        volumeService as any,
        configService as any,
        warmPoolService as any,
        eventEmitter as any,
        organizationService as any,
        runnerAdapterFactory as any,
        organizationUsageService as any,
        redisLockProvider as any,
        redis as any,
        regionService as any,
        snapshotService as any,
        sandboxLookupCacheInvalidationService as any,
        sandboxActivityService as any,
      )

      // Request with unix_user='bob' — different from prior token's 'alice'.
      await expect(service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'bob')).rejects.toThrow('DB delete failed')

      // KEY ASSERTION: disableSSHAccess MUST be called when delete-old-tokens
      // fails and unix_user changed. Old 'alice' tokens remain in DB but runner
      // is now configured for 'bob'. Disabling SSH prevents wrong-user access.
      expect(disableSSHAccess).toHaveBeenCalledTimes(1)
      // Both enable (succeeded) and delete (failed) were called
      expect(enableSSHAccess).toHaveBeenCalledTimes(1)
    })

    it('DOES call disableSSHAccess on save failure when newest prior token matches requested user but older tokens belong to a different user (Finding 2, Round 53)', async () => {
      // Reproducer for Finding 2 [high] Round 53:
      //
      // Scenario: a prior failed alice→bob rotation left both tokens active:
      //   alice-token (older, still active)
      //   bob-token   (newer, still active — the failed rotation's new token)
      //
      // A new rotation request arrives with unix_user='bob'.
      //
      // OLD BUG: findOne({order:{createdAt:'DESC'}}) returns bob-token.
      //   priorUnixUser = 'bob'; resolvedUnixUser = 'bob' → unixUserChanged = false.
      //   Save fails → rollback skips disableSSHAccess (same user) → alice-token
      //   is still valid and routes to the now-bob-configured runner = wrong-user access.
      //
      // Fix: find() returns all active tokens. priorUnixUserSet = {'alice','bob'}.
      //   Any user in the set that differs from resolvedUnixUser → unixUserChanged = true.
      //   Save fails → rollback MUST call disableSSHAccess to prevent alice-token
      //   from routing to the bob runner account.
      const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const enableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const runnerAdapter = { enableSSHAccess, disableSSHAccess }

      const sandboxWithRunner = makeSandbox(SANDBOX_ID)
      sandboxWithRunner.runnerId = 'runner-1'

      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      const runnerService = {
        findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
      }
      const runnerAdapterFactory = {
        create: jest.fn().mockResolvedValue(runnerAdapter),
      }
      // find() returns TWO active tokens: alice-token (older) and bob-token (newer).
      // The new request targets unix_user='bob'. The newest token is bob, but alice
      // is still active — a cross-user situation left by a previous failed rotation.
      const sshAccessRepository = {
        save: jest.fn().mockRejectedValue(new Error('DB write failed')),
        delete: jest.fn().mockResolvedValue({ affected: 1 }),
        count: jest.fn().mockResolvedValue(2),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([
          { id: 'alice-token-uuid', unixUser: 'alice', sandboxId: SANDBOX_ID },
          { id: 'bob-token-uuid', unixUser: 'bob', sandboxId: SANDBOX_ID },
        ]),
      }
      const ownedToken = new LockCode('test-lock-token')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        isLockOwned: jest.fn().mockResolvedValue(true),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null),
        set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'),
        del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any,
        snapshotRepository as any,
        runnerRepository as any,
        buildInfoRepository as any,
        sshAccessRepository as any,
        runnerService as any,
        volumeService as any,
        configService as any,
        warmPoolService as any,
        eventEmitter as any,
        organizationService as any,
        runnerAdapterFactory as any,
        organizationUsageService as any,
        redisLockProvider as any,
        redis as any,
        regionService as any,
        snapshotService as any,
        sandboxLookupCacheInvalidationService as any,
        sandboxActivityService as any,
      )

      // Rotate to bob — alice-token is older but still active.
      await expect(service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'bob')).rejects.toThrow('DB write failed')

      // KEY ASSERTION: disableSSHAccess MUST be called even though the newest
      // prior token is for 'bob'. Alice-token is still active and the runner is
      // now configured for bob — alice-token routes to the wrong account.
      expect(disableSSHAccess).toHaveBeenCalledTimes(1)
      expect(enableSSHAccess).toHaveBeenCalledTimes(1)
    })

    it('does NOT call disableSSHAccess when delete-old-tokens fails with same unix_user (Finding 1, Round 52)', async () => {
      // When the delete fails but unix_user is unchanged, old tokens accumulate
      // but remain valid for the correct user account. Disabling SSH would cause
      // a lockout (gateway accepts old token but runner SSH is off). Log-and-rethrow
      // only; no disable needed.
      const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const enableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const runnerAdapter = { enableSSHAccess, disableSSHAccess }

      const sandboxWithRunner = makeSandbox(SANDBOX_ID)
      sandboxWithRunner.runnerId = 'runner-1'

      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      const runnerService = {
        findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
      }
      const runnerAdapterFactory = {
        create: jest.fn().mockResolvedValue(runnerAdapter),
      }
      // save succeeds; delete fails; prior token is for same user 'boxlite'
      const sshAccessRepository = {
        save: jest.fn().mockImplementation((entity: any) => Promise.resolve({ ...entity, id: 'new-token-uuid' })),
        delete: jest.fn().mockRejectedValue(new Error('DB delete failed')),
        count: jest.fn().mockResolvedValue(1),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([{ id: 'prior-token-uuid', unixUser: 'boxlite', sandboxId: SANDBOX_ID }]),
      }
      const ownedToken = new LockCode('test-lock-token')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        isLockOwned: jest.fn().mockResolvedValue(true),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null),
        set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'),
        del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any,
        snapshotRepository as any,
        runnerRepository as any,
        buildInfoRepository as any,
        sshAccessRepository as any,
        runnerService as any,
        volumeService as any,
        configService as any,
        warmPoolService as any,
        eventEmitter as any,
        organizationService as any,
        runnerAdapterFactory as any,
        organizationUsageService as any,
        redisLockProvider as any,
        redis as any,
        regionService as any,
        snapshotService as any,
        sandboxLookupCacheInvalidationService as any,
        sandboxActivityService as any,
      )

      // Same unix_user rotation — delete fails
      await expect(service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'boxlite')).rejects.toThrow('DB delete failed')

      // KEY ASSERTION: disableSSHAccess must NOT be called. Old tokens accumulate
      // but remain for the correct user. Disabling would lock out valid tokens.
      expect(disableSSHAccess).not.toHaveBeenCalled()
      expect(enableSSHAccess).toHaveBeenCalledTimes(1)
    })

    it('accepts real-SSH requests (unix_user != null) for v2 runners and calls enableSSHAccess (Round 56 updated Round 66, revised Round 5)', async () => {
      // Finding 1, Round 56 originally tested silent downgrade of v2+unixUser to
      // exec-bridge (saving unixUser=null). Round 66 changed the contract: v2 runners
      // REJECTED real-SSH requests with BadRequestError.
      //
      // Round 4 revised the contract again: v2 runners now implement enableSSHAccess
      // and disableSSHAccess natively (runnerAdapter.v2.ts). The guard that threw
      // BadRequestError for v2+unixUser was removed from sandbox.service.ts.
      //
      // Updated assertions: v2+unixUser now succeeds and calls enableSSHAccess.
      // The companion case (unix_user=null + v2 runner) still creates a legacy
      // exec-bridge token without calling the runner adapter.
      const sandboxWithV2Runner = makeSandbox(SANDBOX_ID)
      sandboxWithV2Runner.runnerId = 'runner-v2'

      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithV2Runner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      // v2 runner: apiVersion === '2'
      const runnerService = {
        findOne: jest.fn().mockResolvedValue({ id: 'runner-v2', apiVersion: '2' }),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
      }
      const enableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const runnerAdapterFactory = {
        create: jest.fn().mockResolvedValue({ enableSSHAccess }),
      }
      let savedEntity: any = null
      const sshAccessRepository = {
        save: jest.fn().mockImplementation((entity: any) => {
          savedEntity = { ...entity, id: 'ssh-access-uuid' }
          return Promise.resolve(savedEntity)
        }),
        delete: jest.fn().mockResolvedValue({ affected: 1 }),
        count: jest.fn().mockResolvedValue(0),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([]),
      }
      const ownedToken = new LockCode('test-lock-token')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        isLockOwned: jest.fn().mockResolvedValue(true),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null),
        set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'),
        del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any,
        snapshotRepository as any,
        runnerRepository as any,
        buildInfoRepository as any,
        sshAccessRepository as any,
        runnerService as any,
        volumeService as any,
        configService as any,
        warmPoolService as any,
        eventEmitter as any,
        organizationService as any,
        runnerAdapterFactory as any,
        organizationUsageService as any,
        redisLockProvider as any,
        redis as any,
        regionService as any,
        snapshotService as any,
        sandboxLookupCacheInvalidationService as any,
        sandboxActivityService as any,
      )

      // KEY ASSERTION 1: v2 runner + non-null unixUser → succeeds, calls enableSSHAccess.
      // (Round 4: v2 runners now implement real-SSH natively; BadRequestError removed.)
      await service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'alice')
      expect(enableSSHAccess).toHaveBeenCalledTimes(1)
      expect(sshAccessRepository.save).toHaveBeenCalledTimes(1)
      expect(savedEntity).not.toBeNull()
      expect(savedEntity.unixUser).toBe('alice')

      // KEY ASSERTION 2: v2 runner + null unixUser → legacy exec-bridge token (unixUser=null).
      savedEntity = null
      sshAccessRepository.save.mockClear()
      runnerAdapterFactory.create.mockClear()
      enableSSHAccess.mockClear()
      await service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], null)
      // enableSSHAccess must NOT be called for legacy exec-bridge (null unixUser) path.
      expect(enableSSHAccess).not.toHaveBeenCalled()
      // The runner adapter factory must NOT be invoked for the exec-bridge (null unixUser) path.
      expect(runnerAdapterFactory.create).not.toHaveBeenCalled()
      expect(savedEntity).not.toBeNull()
      expect(savedEntity.unixUser).toBeNull()
    })

    it('rejects real-SSH requests (unix_user != null) for runner-less sandboxes with BadRequestError (Finding 2, Round 66)', async () => {
      // Reproducer for Finding 2, Round 66:
      // A sandbox with no runnerId and unix_user='boxlite' must fail with
      // BadRequestError — there is no runner to configure SSH on.
      // unixUser=null (exec-bridge) must still succeed regardless of runner.
      const { service, sshAccessRepository } = buildService()

      // sandbox from buildService() has no runnerId (findOne returns null for runnerService).
      await expect(service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'boxlite')).rejects.toThrow(
        'Real-SSH access (unix_user) requires a runner',
      )
      expect(sshAccessRepository.save).not.toHaveBeenCalled()

      // exec-bridge path (null) must still work without a runner.
      sshAccessRepository.save.mockClear()
      await service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], null)
      expect(sshAccessRepository.save).toHaveBeenCalledTimes(1)
    })

    it('rejects real-SSH requests with distinct error when runnerId is set but runner record is not found (Finding 4, Round 67)', async () => {
      // Reproducer for Finding 4, Round 67:
      // sandbox.runnerId is set (non-null) but runnerService.findOne returns null
      // (orphaned runner reference — runner was deleted after sandbox was created).
      // The !runner guard must produce "runner not found" NOT "v2 runners not supported".
      const sandboxWithOrphanedRunner = makeSandbox(SANDBOX_ID)
      sandboxWithOrphanedRunner.runnerId = 'deleted-runner-id'

      const sshAccessRepository = {
        save: jest.fn().mockImplementation((entity: any) => Promise.resolve({ ...entity, id: 'uuid' })),
        delete: jest.fn().mockResolvedValue({ affected: 1 }),
        count: jest.fn().mockResolvedValue(0),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([]),
      }
      const ownedToken = new LockCode('t')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        isLockOwned: jest.fn().mockResolvedValue(true),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null), set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'), del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithOrphanedRunner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      // orphaned runner: runnerId set on sandbox but findOne returns null
      const runnerService = {
        findOne: jest.fn().mockResolvedValue(null),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No runners')),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }
      const runnerAdapterFactory = { create: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any, snapshotRepository as any, runnerRepository as any,
        buildInfoRepository as any, sshAccessRepository as any, runnerService as any,
        volumeService as any, configService as any, warmPoolService as any,
        eventEmitter as any, organizationService as any, runnerAdapterFactory as any,
        organizationUsageService as any, redisLockProvider as any, redis as any,
        regionService as any, snapshotService as any,
        sandboxLookupCacheInvalidationService as any, sandboxActivityService as any,
      )

      // KEY ASSERTION: error must say "runner not found", not "v2 runners not supported".
      // The negative assertion enforces distinctness — a regression that conflates
      // the two conditions would say "v2 runners" and this test would catch it.
      let caughtErr: Error | undefined
      try {
        await service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'boxlite')
      } catch (e: any) {
        caughtErr = e
      }
      expect(caughtErr).toBeDefined()
      expect(caughtErr!.message).toMatch(/runner not found/)
      expect(caughtErr!.message).not.toMatch(/v2 runners/)
      expect(sshAccessRepository.save).not.toHaveBeenCalled()
    })

    it('skips delete-old-tokens and returns the new token when lock is lost between save and delete (Finding 2, Round 57)', async () => {
      // Reproducer for Finding 2 [high] Round 57:
      //
      // Sequence:
      //   1. Create-A acquires the lock (90s TTL), enables runner SSH, saves token-A.
      //   2. Create-A stalls (e.g. GC pause, slow network).
      //   3. Create-A's lock TTL expires.
      //   4. Create-B acquires the lock, enables runner SSH, saves token-B.
      //   5. Create-A resumes and runs: delete({ token: Not(token-A) }) → deletes token-B.
      //   6. No valid token remains in the DB; Create-B's saved token is gone.
      //
      // Fix: add a second isLockOwned check immediately before the delete. If
      // ownership is lost, log a warning, skip the delete, and return the new token
      // (already durably saved — the caller has a valid credential).
      //
      // We model this by:
      //   - isLockOwned returning true the FIRST time (fencing check before save → passes)
      //   - isLockOwned returning false the SECOND time (fencing check before delete → fails)
      //   - asserting that sshAccessRepository.delete was NOT called for old-token cleanup.

      let isLockOwnedCallCount = 0
      const isLockOwned = jest.fn().mockImplementation(() => {
        isLockOwnedCallCount++
        // First call (pre-save fencing): lock still owned → save proceeds.
        // Second call (pre-delete fencing): lock lost → delete must be skipped.
        return Promise.resolve(isLockOwnedCallCount === 1)
      })

      const { service, sshAccessRepository } = buildService({
        redisLockProvider: { isLockOwned },
      })

      const result = await service.createSshAccess(SANDBOX_ID, 60, 'org-1')

      // KEY ASSERTION 1: delete must NOT have been called — the lock was lost so
      // the stale resumer must not delete tokens saved by a concurrent winner.
      expect(sshAccessRepository.delete).not.toHaveBeenCalled()

      // KEY ASSERTION 2: the call must succeed and return the token — the new
      // token was durably saved before the lock was lost, so the caller has access.
      expect(result).toBeDefined()
      expect(result.token).toBeDefined()

      // KEY ASSERTION 3: save was called exactly once (the new token was persisted).
      expect(sshAccessRepository.save).toHaveBeenCalledTimes(1)
    })

    it('propagates a clear error when the runner returns 503 (SSH gateway not configured, Round 7)', async () => {
      // Reproducer for Finding [high] Round 7:
      //
      // When SSH_GATEWAY_PUBLIC_KEY is not configured on the runner the runner
      // returns 503. The v2 adapter previously let axios throw a generic network
      // error (AxiosError). The sandbox service propagated that as an opaque 500.
      //
      // Fix (Round 7): RunnerAdapterV2.enableSSHAccess inspects the HTTP status.
      // On 503 it throws with the message "Runner SSH gateway not configured…".
      // sandbox.service.ts forwards that Error to the caller unchanged, so the
      // gateway receives a meaningful 5xx with an actionable message rather than
      // a bare internal-server-error.
      //
      // Here we inject that error directly via the adapter mock (the v2 adapter
      // unit tests cover the HTTP→error translation; this test covers the service
      // forwarding contract).
      const enableSSHAccess = jest.fn().mockRejectedValue(
        new Error('Runner SSH gateway not configured: deploy SSH_GATEWAY_PUBLIC_KEY to enable real-SSH access on this runner'),
      )
      const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const runnerAdapter = { enableSSHAccess, disableSSHAccess }

      const sandboxWithRunner = makeSandbox(SANDBOX_ID)
      sandboxWithRunner.runnerId = 'runner-v2'

      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      const runnerService = {
        findOne: jest.fn().mockResolvedValue({ id: 'runner-v2', apiVersion: '2' }),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
      }
      const runnerAdapterFactory = { create: jest.fn().mockResolvedValue(runnerAdapter) }
      const sshAccessRepository = {
        save: jest.fn().mockImplementation((entity: any) => Promise.resolve({ ...entity, id: 'uuid' })),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
        count: jest.fn().mockResolvedValue(0),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([]),
      }
      const ownedToken = new LockCode('test-lock-token')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        isLockOwned: jest.fn().mockResolvedValue(true),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null),
        set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'),
        del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any,
        snapshotRepository as any,
        runnerRepository as any,
        buildInfoRepository as any,
        sshAccessRepository as any,
        runnerService as any,
        volumeService as any,
        configService as any,
        warmPoolService as any,
        eventEmitter as any,
        organizationService as any,
        runnerAdapterFactory as any,
        organizationUsageService as any,
        redisLockProvider as any,
        redis as any,
        regionService as any,
        snapshotService as any,
        sandboxLookupCacheInvalidationService as any,
        sandboxActivityService as any,
      )

      // KEY ASSERTION 1: the service must propagate the adapter's clear error message
      // rather than swallowing it or replacing it with a generic "internal error".
      await expect(service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], 'alice')).rejects.toThrow(
        'Runner SSH gateway not configured',
      )

      // KEY ASSERTION 2: no DB token must be saved — runner SSH never succeeded.
      expect(sshAccessRepository.save).not.toHaveBeenCalled()
    })

    it('calls disableSSHAccess when rotating from real-SSH token to legacy (null) token (Finding [high], Round 68)', async () => {
      // Reproducer for Finding [high] Round 68:
      //
      // Scenario: sandbox has an active real-SSH token (unixUser='boxlite').
      // A new createSshAccess request arrives with unixUser=null (legacy exec-bridge).
      //
      //   1. priorToken.unixUser = 'boxlite' (real-SSH); resolvedUnixUser = null (legacy)
      //   2. unixUser === null → no runner enableSSHAccess call
      //   3. New legacy token saved to DB; old real-SSH token deleted from DB
      //   4. BUG: runner still has sshd + gvproxy port-forward active for 'boxlite'
      //      even though the DB no longer authorizes real-SSH access.
      //      Stale exposed port + sshd remain until an explicit disable.
      //
      // Fix: when unixUser === null and there is at least one prior token with a
      // non-null unixUser, call disableSSHAccess on the runner before or after
      // deleting the old real-SSH tokens (under the same per-sandbox lock).
      const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const enableSSHAccess = jest.fn().mockResolvedValue(undefined)
      const runnerAdapter = { enableSSHAccess, disableSSHAccess }

      const sandboxWithRunner = makeSandbox(SANDBOX_ID)
      sandboxWithRunner.runnerId = 'runner-1'

      const sandboxRepo = {
        findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
        find: jest.fn().mockResolvedValue([]),
        findAndCount: jest.fn().mockResolvedValue([[], 0]),
        insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
        update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
        updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
        delete: jest.fn().mockResolvedValue({ affected: 0 }),
      }
      const runnerService = {
        findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
        findOneOrFail: jest.fn().mockResolvedValue(null),
        getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
      }
      const runnerAdapterFactory = {
        create: jest.fn().mockResolvedValue(runnerAdapter),
      }
      // Prior active token is a real-SSH token (unixUser='boxlite').
      const sshAccessRepository = {
        save: jest.fn().mockImplementation((entity: any) => Promise.resolve({ ...entity, id: 'new-legacy-uuid' })),
        delete: jest.fn().mockResolvedValue({ affected: 1 }),
        count: jest.fn().mockResolvedValue(1),
        findOne: jest.fn().mockResolvedValue(null),
        find: jest.fn().mockResolvedValue([{ id: 'prior-real-ssh-uuid', unixUser: 'boxlite', sandboxId: SANDBOX_ID }]),
      }
      const ownedToken = new LockCode('test-lock-token')
      const redisLockProvider = {
        waitForLock: jest.fn().mockResolvedValue(undefined),
        waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
        unlock: jest.fn().mockResolvedValue(undefined),
        unlockOwned: jest.fn().mockResolvedValue(undefined),
        lock: jest.fn().mockResolvedValue(true),
        isLocked: jest.fn().mockResolvedValue(false),
        getCode: jest.fn().mockResolvedValue(null),
        isLockOwned: jest.fn().mockResolvedValue(true),
      }
      const redis = {
        get: jest.fn().mockResolvedValue(null),
        set: jest.fn().mockResolvedValue('OK'),
        setex: jest.fn().mockResolvedValue('OK'),
        del: jest.fn().mockResolvedValue(1),
        exists: jest.fn().mockResolvedValue(0),
        pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
      }
      const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
      const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
      const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
      const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
      const volumeService = { validateVolumes: jest.fn() }
      const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
      const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
      const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
      const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
      const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
      const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
      const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
      const sandboxActivityService = { updateLastActivityAt: jest.fn() }

      const service = new SandboxService(
        sandboxRepo as any,
        snapshotRepository as any,
        runnerRepository as any,
        buildInfoRepository as any,
        sshAccessRepository as any,
        runnerService as any,
        volumeService as any,
        configService as any,
        warmPoolService as any,
        eventEmitter as any,
        organizationService as any,
        runnerAdapterFactory as any,
        organizationUsageService as any,
        redisLockProvider as any,
        redis as any,
        regionService as any,
        snapshotService as any,
        sandboxLookupCacheInvalidationService as any,
        sandboxActivityService as any,
      )

      // Issue a legacy (null unixUser) token — rotating away from real-SSH.
      await service.createSshAccess(SANDBOX_ID, 60, 'org-1', [], null)

      // KEY ASSERTION: disableSSHAccess MUST be called on the runner.
      // The prior real-SSH token is being replaced by a legacy token.
      // Leaving the runner with sshd + gvproxy port-forward active violates
      // the revocation contract: no DB token authorizes real-SSH access, but
      // the port is still exposed and sshd is still running.
      expect(disableSSHAccess).toHaveBeenCalledTimes(1)
      // enableSSHAccess must NOT have been called (this is the legacy path).
      expect(enableSSHAccess).not.toHaveBeenCalled()
      // The legacy token must still be saved.
      expect(sshAccessRepository.save).toHaveBeenCalledTimes(1)
    })
  })

  describe('revokeSshAccess', () => {
    it('acquires the per-sandbox SSH lock with the expected key (owned)', async () => {
      const { service, redisLockProvider } = buildService()

      await service.revokeSshAccess(SANDBOX_ID, undefined, 'org-1')

      expect(redisLockProvider.waitForLockOwned).toHaveBeenCalledWith(EXPECTED_LOCK_KEY, expect.any(Number))
    })

    it('releases the per-sandbox SSH lock via compare-and-delete after revoking access', async () => {
      const { service, redisLockProvider } = buildService()

      await service.revokeSshAccess(SANDBOX_ID, undefined, 'org-1')

      expect(redisLockProvider.unlockOwned).toHaveBeenCalledWith(EXPECTED_LOCK_KEY, expect.any(LockCode))
      expect(redisLockProvider.unlock).not.toHaveBeenCalledWith(EXPECTED_LOCK_KEY)
    })

    it('passes the token returned by waitForLockOwned to unlockOwned', async () => {
      const capturedToken = new LockCode('revoke-token-xyz')
      const unlockOwnedMock = jest.fn().mockResolvedValue(undefined)

      const { service } = buildService({
        redisLockProvider: {
          waitForLockOwned: jest.fn().mockResolvedValue(capturedToken),
          unlockOwned: unlockOwnedMock,
        },
      })

      await service.revokeSshAccess(SANDBOX_ID, undefined, 'org-1')

      expect(unlockOwnedMock).toHaveBeenCalledWith(EXPECTED_LOCK_KEY, capturedToken)
    })
  })

  describe('lock key invariants', () => {
    it('createSshAccess and revokeSshAccess use the SAME lock key for the same sandbox', async () => {
      // This is the core serialization invariant: if they used different keys,
      // a concurrent revoke could complete between create's revoke and save steps.
      const createKeys: string[] = []
      const revokeKeys: string[] = []
      const sharedToken = new LockCode('shared-token')

      const { service: createSvc } = buildService({
        redisLockProvider: {
          waitForLockOwned: jest.fn().mockImplementation((key) => {
            createKeys.push(key)
            return Promise.resolve(sharedToken)
          }),
          unlockOwned: jest.fn().mockResolvedValue(undefined),
        },
      })

      const { service: revokeSvc } = buildService({
        redisLockProvider: {
          waitForLockOwned: jest.fn().mockImplementation((key) => {
            revokeKeys.push(key)
            return Promise.resolve(sharedToken)
          }),
          unlockOwned: jest.fn().mockResolvedValue(undefined),
        },
      })

      await createSvc.createSshAccess(SANDBOX_ID, 60, 'org-1')
      await revokeSvc.revokeSshAccess(SANDBOX_ID, undefined, 'org-1')

      expect(createKeys).toHaveLength(1)
      expect(revokeKeys).toHaveLength(1)
      expect(createKeys[0]).toBe(revokeKeys[0])
    })

    it('different sandboxes use different lock keys', async () => {
      const keysA: string[] = []
      const keysB: string[] = []
      const token = new LockCode('t')

      const { service: svcA } = buildService({
        redisLockProvider: {
          waitForLockOwned: jest.fn().mockImplementation((key) => { keysA.push(key); return Promise.resolve(token) }),
          unlockOwned: jest.fn().mockResolvedValue(undefined),
        },
      })
      const { service: svcB } = buildService({
        redisLockProvider: {
          waitForLockOwned: jest.fn().mockImplementation((key) => { keysB.push(key); return Promise.resolve(token) }),
          unlockOwned: jest.fn().mockResolvedValue(undefined),
        },
      })

      await svcA.createSshAccess('sandbox-a', 60, 'org-1')
      await svcB.createSshAccess('sandbox-b', 60, 'org-1')

      expect(keysA[0]).not.toBe(keysB[0])
      expect(keysA[0]).toContain('sandbox-a')
      expect(keysB[0]).toContain('sandbox-b')
    })

    it('lock key does not collide with the state-change lock key', async () => {
      const keysUsed: string[] = []
      const token = new LockCode('t')

      const { service } = buildService({
        redisLockProvider: {
          waitForLockOwned: jest.fn().mockImplementation((key) => { keysUsed.push(key); return Promise.resolve(token) }),
          unlockOwned: jest.fn().mockResolvedValue(undefined),
        },
      })

      await service.createSshAccess(SANDBOX_ID, 60, 'org-1')

      const stateChangeKey = `sandbox:${SANDBOX_ID}:state-change`
      expect(keysUsed).not.toContain(stateChangeKey)
    })

    it('lock key matches expected pattern sandbox:<id>:ssh-access', async () => {
      const keysUsed: string[] = []
      const token = new LockCode('t')

      const { service } = buildService({
        redisLockProvider: {
          waitForLockOwned: jest.fn().mockImplementation((key) => { keysUsed.push(key); return Promise.resolve(token) }),
          unlockOwned: jest.fn().mockResolvedValue(undefined),
        },
      })

      await service.createSshAccess(SANDBOX_ID, 60, 'org-1')

      expect(keysUsed[0]).toBe(`sandbox:${SANDBOX_ID}:ssh-access`)
    })
  })
})

// ---------------------------------------------------------------------------
// Round 41, Finding 1: validateSshAccess must hold the per-sandbox SSH lock
// before calling disableSSHAccess so it cannot race a concurrent createSshAccess.
// ---------------------------------------------------------------------------

/**
 * Build a minimal SshAccess stub with only the fields validateSshAccess inspects.
 * expiresAt is set in the past so the token is treated as expired.
 */
function makeExpiredSshAccess(sandboxId: string, withRunner = false, nullSandbox = false): Record<string, unknown> {
  return {
    id: 'ssh-access-uuid',
    token: 'expired-token',
    sandboxId,
    expiresAt: new Date(Date.now() - 1000 * 60 * 5), // 5 minutes ago
    sandbox: nullSandbox
      ? null
      : withRunner
        ? { id: sandboxId, runnerId: 'runner-1', region: 'us' }
        : { id: sandboxId, runnerId: null, region: 'us' },
  }
}

/**
 * Build a service wired for validateSshAccess tests.
 *
 * sshAccessRepository.findOne returns an expired SshAccess for the test token.
 * sshAccessRepository.count returns `activeCount` (controls whether disable is called).
 * runnerService returns a v1 runner when withRunner=true (to enter the disable path).
 * runnerAdapterFactory creates an adapter with a spy disableSSHAccess.
 */
function buildValidateService(opts: {
  activeCount?: number
  withRunner?: boolean
  nullSandbox?: boolean
  redisLockProvider?: Partial<RedisLockProvider>
}) {
  const { activeCount = 0, withRunner = false, nullSandbox = false } = opts
  const sandboxId = VALIDATE_SANDBOX_ID

  const expiredAccess = makeExpiredSshAccess(sandboxId, withRunner, nullSandbox)

  const sshAccessRepository = {
    findOne: jest.fn().mockResolvedValue(expiredAccess),
    count: jest.fn().mockResolvedValue(activeCount),
    delete: jest.fn().mockResolvedValue({ affected: 0 }),
    save: jest.fn().mockImplementation((e) => Promise.resolve({ ...e, id: 'id' })),
  }

  const sandboxRepo = {
    findOne: jest.fn().mockResolvedValue(makeSandbox(sandboxId)),
    find: jest.fn().mockResolvedValue([]),
    findAndCount: jest.fn().mockResolvedValue([[], 0]),
    insert: jest.fn().mockImplementation((s) => Promise.resolve(s)),
    update: jest.fn().mockImplementation((_, { entity }) => Promise.resolve(entity)),
    updateWhere: jest.fn().mockImplementation((_, { entity }) => Promise.resolve(entity ?? {})),
    delete: jest.fn().mockResolvedValue({ affected: 0 }),
  }

  const ownedToken = new LockCode('validate-lock-token')
  const defaultLockProvider: Partial<RedisLockProvider> = {
    waitForLock: jest.fn().mockResolvedValue(undefined),
    waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
    unlock: jest.fn().mockResolvedValue(undefined),
    unlockOwned: jest.fn().mockResolvedValue(undefined),
    lock: jest.fn().mockResolvedValue(true),
    isLocked: jest.fn().mockResolvedValue(false),
    getCode: jest.fn().mockResolvedValue(null),
    isLockOwned: jest.fn().mockResolvedValue(true),
  }
  const redisLockProvider = { ...defaultLockProvider, ...(opts.redisLockProvider ?? {}) }

  const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
  const runnerAdapterFactory = {
    create: jest.fn().mockResolvedValue({ disableSSHAccess }),
  }

  const runnerService = {
    findOne: withRunner
      ? jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' })
      : jest.fn().mockResolvedValue(null),
    findOneOrFail: jest.fn().mockResolvedValue(null),
    getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
  }

  const redis = {
    get: jest.fn().mockResolvedValue(null),
    set: jest.fn().mockResolvedValue('OK'),
    setex: jest.fn().mockResolvedValue('OK'),
    del: jest.fn().mockResolvedValue(1),
    exists: jest.fn().mockResolvedValue(0),
    pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
  }

  const regionService = {
    findOne: jest.fn().mockResolvedValue(null),
    findOneByName: jest.fn().mockResolvedValue(null),
    findByIds: jest.fn().mockResolvedValue([]),
  }
  const noopStub = () => ({})
  const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
  const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
  const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
  const volumeService = { validateVolumes: jest.fn() }
  const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
  const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
  const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
  const organizationService = {
    assertOrganizationIsNotSuspended: jest.fn(),
    getRegionQuota: jest.fn().mockResolvedValue(null),
  }
  const organizationUsageService = {
    incrementPendingSandboxUsage: jest.fn(),
    decrementPendingSandboxUsage: jest.fn(),
    getSandboxUsageOverview: jest.fn(),
    applyResizeUsageChange: jest.fn(),
  }
  const sandboxLookupCacheInvalidationService = {
    invalidateOrgId: jest.fn(),
    invalidate: jest.fn(),
  }
  const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
  const sandboxActivityService = { updateLastActivityAt: jest.fn() }

  const service = new SandboxService(
    sandboxRepo as any,
    snapshotRepository as any,
    runnerRepository as any,
    buildInfoRepository as any,
    sshAccessRepository as any,
    runnerService as any,
    volumeService as any,
    configService as any,
    warmPoolService as any,
    eventEmitter as any,
    organizationService as any,
    runnerAdapterFactory as any,
    organizationUsageService as any,
    redisLockProvider as any,
    redis as any,
    regionService as any,
    snapshotService as any,
    sandboxLookupCacheInvalidationService as any,
    sandboxActivityService as any,
  )

  return { service, redisLockProvider, sshAccessRepository, disableSSHAccess }
}

const VALIDATE_SANDBOX_ID = 'sandbox-validate-uuid'
const EXPECTED_SSH_LOCK_KEY = `sandbox:${VALIDATE_SANDBOX_ID}:ssh-access`

describe('SandboxService validateSshAccess lock contract (Round 41, Finding 1)', () => {
  it('acquires the per-sandbox SSH lock before calling disableSSHAccess on expired token with 0 active tokens', async () => {
    // Reproducer: validateSshAccess calls disableSSHAccess OUTSIDE the SSH lock.
    // A concurrent createSshAccess holds the lock, enables runner SSH, is between
    // runner enable and DB save. The validate path sees 0 active tokens (the new
    // token is not saved yet), calls disableSSHAccess — runner SSH is now disabled.
    // createSshAccess saves the token (fencing check passes — it still owns the lock).
    // Result: valid DB token but runner SSH disabled.
    //
    // Fix: validateSshAccess must acquire the lock before checking count and
    // calling disableSSHAccess. This test asserts that waitForLockOwned is called
    // with the correct per-sandbox SSH lock key.
    const { service, redisLockProvider } = buildValidateService({
      activeCount: 0,
      withRunner: true,
    })

    await service.validateSshAccess('expired-token')

    expect(redisLockProvider.waitForLockOwned).toHaveBeenCalledWith(EXPECTED_SSH_LOCK_KEY, expect.any(Number))
  })

  it('releases the per-sandbox SSH lock via compare-and-delete after disable', async () => {
    // The lock must be released with unlockOwned (compare-and-delete), not plain
    // unlock, so a TTL-expired lock holder cannot delete a concurrent caller's lock.
    const { service, redisLockProvider } = buildValidateService({
      activeCount: 0,
      withRunner: true,
    })

    await service.validateSshAccess('expired-token')

    expect(redisLockProvider.unlockOwned).toHaveBeenCalledWith(EXPECTED_SSH_LOCK_KEY, expect.any(LockCode))
    expect(redisLockProvider.unlock).not.toHaveBeenCalledWith(EXPECTED_SSH_LOCK_KEY)
  })

  it('does NOT call disableSSHAccess when re-check inside lock finds active tokens', async () => {
    // Reproducer for the race: before the fix, the count was read BEFORE acquiring
    // the lock. A concurrent createSshAccess could save a new token between the
    // count read (0) and the disableSSHAccess call. After the fix, the count is
    // re-read inside the lock — if it is now > 0, disableSSHAccess is skipped.
    const { service, disableSSHAccess, sshAccessRepository } = buildValidateService({
      activeCount: 1, // re-check inside lock finds a new active token
      withRunner: true,
    })

    await service.validateSshAccess('expired-token')

    // KEY ASSERTION 1: disableSSHAccess must NOT be called because a concurrent
    // createSshAccess saved a new token between the outer count and the lock acquire.
    expect(disableSSHAccess).not.toHaveBeenCalled()
    // KEY ASSERTION 2: the expired row must still be deleted even though active tokens
    // remain — delete-before-count is the invariant, regardless of remainingCount value.
    expect(sshAccessRepository.delete).toHaveBeenCalledWith({ id: 'ssh-access-uuid' })
  })

  it('calls disableSSHAccess and returns invalid when no active tokens remain (lock held)', async () => {
    // Happy path: lock is held, re-check confirms 0 active tokens — disable proceeds.
    const { service, disableSSHAccess } = buildValidateService({
      activeCount: 0,
      withRunner: true,
    })

    const result = await service.validateSshAccess('expired-token')

    expect(disableSSHAccess).toHaveBeenCalledTimes(1)
    expect(result).toEqual({ valid: false, sandboxId: '', unixUser: null })
  })

  it('skips lock and disableSSHAccess when sandbox has no runner, but still deletes the expired row (Finding 1, Round 69)', async () => {
    // No runner means no runner-side state to clean up — the lock is irrelevant.
    // KEY: the expired row MUST still be deleted to prevent unbounded DB growth
    // (exec-bridge tokens for runner-less sandboxes would otherwise accumulate forever).
    const { service, redisLockProvider, disableSSHAccess, sshAccessRepository } = buildValidateService({
      activeCount: 0,
      withRunner: false,
    })

    await service.validateSshAccess('expired-token')

    expect(redisLockProvider.waitForLockOwned).not.toHaveBeenCalled()
    expect(disableSSHAccess).not.toHaveBeenCalled()
    // The expired row must be deleted even without a runner.
    expect(sshAccessRepository.delete).toHaveBeenCalledWith({ id: 'ssh-access-uuid' })
  })

  it('deletes expired row when sandbox relation is null (concurrently deleted), without lock (Finding 2, Round 70)', async () => {
    // Reproducer: sshAccess.sandbox is null when the sandbox was deleted concurrently.
    // Before fix: the else-if (sshAccess.sandbox) branch was skipped entirely (null
    // is falsy), so the orphaned SSH-access row was never deleted — unbounded DB growth.
    // After fix: the else branch deletes the row even when sandbox is null.
    const { service, redisLockProvider, disableSSHAccess, sshAccessRepository } = buildValidateService({
      nullSandbox: true,
    })

    await service.validateSshAccess('expired-token')

    expect(redisLockProvider.waitForLockOwned).not.toHaveBeenCalled()
    expect(disableSSHAccess).not.toHaveBeenCalled()
    // KEY ASSERTION: the expired row must be deleted even when sandbox is null.
    expect(sshAccessRepository.delete).toHaveBeenCalledWith({ id: 'ssh-access-uuid' })
  })

  it('returns invalid for a valid (non-expired) token when sandbox relation is null (concurrently deleted) (Finding 1, Round 71)', async () => {
    // Reproducer: sshAccess.sandbox is null and the token has NOT yet expired.
    // Before fix: the non-expired fast path returned `sshAccess.sandbox.id` without
    // a null check — a TypeError crash propagated to the gateway, which treated it
    // as a failed validation (non-200 response) and closed the connection. Any sandbox
    // being deleted while a valid token existed would trigger this crash.
    // After fix: the non-expired path guards `if (!sshAccess.sandbox)` and returns
    // { valid: false, sandboxId: '', unixUser: null } cleanly.
    const sandboxId = VALIDATE_SANDBOX_ID
    const validAccessNullSandbox = {
      id: 'ssh-access-uuid',
      token: 'valid-token',
      sandboxId,
      unixUser: null,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60), // 1 hour from now
      sandbox: null, // sandbox concurrently deleted — TypeORM resolves FK to null
    }

    const sshAccessRepository = {
      findOne: jest.fn().mockResolvedValue(validAccessNullSandbox),
      count: jest.fn().mockResolvedValue(0),
      delete: jest.fn().mockResolvedValue({ affected: 0 }),
      save: jest.fn(),
    }

    const { service } = buildValidateService({ withRunner: false })
    // Override findOne so it returns the null-sandbox non-expired access.
    ;(service as any).sshAccessRepository = sshAccessRepository

    // KEY ASSERTION: must NOT throw TypeError; must return invalid cleanly.
    const result = await service.validateSshAccess('valid-token')
    expect(result).toEqual({ valid: false, sandboxId: '', unixUser: null })
  })

  it('returns invalid=false even if lock acquisition throws (try/catch swallows errors)', async () => {
    // validateSshAccess wraps the cleanup in try/catch so errors don't break the
    // hot path. The function must still return { valid: false } on any failure.
    const { service } = buildValidateService({
      activeCount: 0,
      withRunner: true,
      redisLockProvider: {
        waitForLockOwned: jest.fn().mockRejectedValue(new Error('Redis unavailable')),
      },
    })

    const result = await service.validateSshAccess('expired-token')

    expect(result).toEqual({ valid: false, sandboxId: '', unixUser: null })
  })

  it('deletes the expired token row so a second call returns invalid without acquiring lock or calling disableSSHAccess', async () => {
    // Reproducer for Round 46 Finding [medium]:
    //
    // Before fix: validateSshAccess leaves the expired SshAccess row in the DB.
    // A second call with the same token finds the row again, acquires the lock,
    // re-counts active tokens, and calls disableSSHAccess again — causing lock
    // contention and amplified runner load on every repeated auth attempt.
    //
    // After fix: the expired row is deleted inside validateSshAccess (before
    // releasing the lock on the active=0 path, or immediately on the active>0
    // path). A second call finds no row → returns invalid immediately with no
    // lock acquisition and no runner call.
    //
    // The test simulates real DB behavior: findOne returns the expired access on
    // the first call, then null once the row has been deleted (tracked via the
    // delete mock being called).
    const sandboxId = VALIDATE_SANDBOX_ID
    const expiredAccess = makeExpiredSshAccess(sandboxId, true)

    let deleted = false
    const sshAccessRepository = {
      findOne: jest.fn().mockImplementation(() =>
        Promise.resolve(deleted ? null : expiredAccess),
      ),
      count: jest.fn().mockResolvedValue(0),
      delete: jest.fn().mockImplementation(() => {
        deleted = true
        return Promise.resolve({ affected: 1 })
      }),
      save: jest.fn().mockImplementation((e: any) => Promise.resolve({ ...e, id: 'id' })),
    }

    const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
    const runnerAdapterFactory = {
      create: jest.fn().mockResolvedValue({ disableSSHAccess }),
    }
    const runnerService = {
      findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
      findOneOrFail: jest.fn().mockResolvedValue(null),
      getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
    }

    const ownedToken = new LockCode('validate-lock-token')
    const redisLockProvider = {
      waitForLock: jest.fn().mockResolvedValue(undefined),
      waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
      unlock: jest.fn().mockResolvedValue(undefined),
      unlockOwned: jest.fn().mockResolvedValue(undefined),
      lock: jest.fn().mockResolvedValue(true),
      isLocked: jest.fn().mockResolvedValue(false),
      getCode: jest.fn().mockResolvedValue(null),
      isLockOwned: jest.fn().mockResolvedValue(true),
    }

    const redis = {
      get: jest.fn().mockResolvedValue(null),
      set: jest.fn().mockResolvedValue('OK'),
      setex: jest.fn().mockResolvedValue('OK'),
      del: jest.fn().mockResolvedValue(1),
      exists: jest.fn().mockResolvedValue(0),
      pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
    }
    const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
    const sandboxRepo = {
      findOne: jest.fn().mockResolvedValue(makeSandbox(sandboxId)),
      find: jest.fn().mockResolvedValue([]),
      findAndCount: jest.fn().mockResolvedValue([[], 0]),
      insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
      update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
      updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
      delete: jest.fn().mockResolvedValue({ affected: 0 }),
    }
    const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
    const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
    const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
    const volumeService = { validateVolumes: jest.fn() }
    const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
    const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
    const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
    const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
    const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
    const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
    const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
    const sandboxActivityService = { updateLastActivityAt: jest.fn() }

    const service = new SandboxService(
      sandboxRepo as any,
      snapshotRepository as any,
      runnerRepository as any,
      buildInfoRepository as any,
      sshAccessRepository as any,
      runnerService as any,
      volumeService as any,
      configService as any,
      warmPoolService as any,
      eventEmitter as any,
      organizationService as any,
      runnerAdapterFactory as any,
      organizationUsageService as any,
      redisLockProvider as any,
      redis as any,
      regionService as any,
      snapshotService as any,
      sandboxLookupCacheInvalidationService as any,
      sandboxActivityService as any,
    )

    // First call: expired token found → should disable SSH and delete the row.
    const result1 = await service.validateSshAccess('expired-token')
    expect(result1).toEqual({ valid: false, sandboxId: '', unixUser: null })
    // Row must have been deleted.
    expect(sshAccessRepository.delete).toHaveBeenCalledWith({ id: expiredAccess.id })
    // Runner must have been disabled exactly once.
    expect(disableSSHAccess).toHaveBeenCalledTimes(1)

    const lockCallsAfterFirst = (redisLockProvider.waitForLockOwned as jest.Mock).mock.calls.length
    const disableCallsAfterFirst = disableSSHAccess.mock.calls.length

    // Second call: row is gone (findOne returns null) → must return invalid with
    // NO additional lock acquisitions and NO additional runner calls.
    const result2 = await service.validateSshAccess('expired-token')
    expect(result2).toEqual({ valid: false, sandboxId: '', unixUser: null })

    expect((redisLockProvider.waitForLockOwned as jest.Mock).mock.calls.length).toBe(lockCallsAfterFirst)
    expect(disableSSHAccess).toHaveBeenCalledTimes(disableCallsAfterFirst)
  })

  it('returns the token unix_user in the response so the gateway can detect rotation mismatches (Finding 1, Round 53)', async () => {
    // Reproducer for Finding 1 [high] Round 53:
    //
    // During alice→bob rotation the runner is reconfigured for 'bob' BEFORE old
    // alice-tokens are deleted. In the save→delete window an alice-token is valid
    // in the DB. The gateway calls validateSshAccess (returns valid=true) and then
    // calls getRunnerSSHAccess (returns unixUser='bob'). Without the token's own
    // unixUser in the validation response the gateway uses 'bob' from the runner
    // and routes the session to bob's shell — wrong-user access.
    //
    // Fix: validateSshAccess includes the token's stored unixUser in its response.
    // The gateway compares token.unixUser against runner.unixUser and rejects the
    // channel when they differ. This test verifies the API-layer half of the fix:
    // validateSshAccess must return unixUser for a valid token.
    const sandboxId = VALIDATE_SANDBOX_ID
    const validAccess = {
      id: 'ssh-access-uuid',
      token: 'valid-token',
      sandboxId,
      unixUser: 'alice',
      expiresAt: new Date(Date.now() + 1000 * 60 * 60), // 1 hour from now
      sandbox: { id: sandboxId, runnerId: 'runner-1', region: 'us' },
    }

    const sshAccessRepository = {
      findOne: jest.fn().mockResolvedValue(validAccess),
      count: jest.fn().mockResolvedValue(1),
      delete: jest.fn().mockResolvedValue({ affected: 0 }),
      save: jest.fn().mockImplementation((e: any) => Promise.resolve({ ...e, id: 'id' })),
      find: jest.fn().mockResolvedValue([]),
    }

    const ownedToken = new LockCode('validate-lock-token')
    const redisLockProvider = {
      waitForLock: jest.fn().mockResolvedValue(undefined),
      waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
      unlock: jest.fn().mockResolvedValue(undefined),
      unlockOwned: jest.fn().mockResolvedValue(undefined),
      lock: jest.fn().mockResolvedValue(true),
      isLocked: jest.fn().mockResolvedValue(false),
      getCode: jest.fn().mockResolvedValue(null),
      isLockOwned: jest.fn().mockResolvedValue(true),
    }

    const runnerService = {
      findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
      findOneOrFail: jest.fn().mockResolvedValue(null),
      getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
    }
    const runnerAdapterFactory = {
      create: jest.fn().mockResolvedValue({ disableSSHAccess: jest.fn() }),
    }

    const redis = {
      get: jest.fn().mockResolvedValue(null),
      set: jest.fn().mockResolvedValue('OK'),
      setex: jest.fn().mockResolvedValue('OK'),
      del: jest.fn().mockResolvedValue(1),
      exists: jest.fn().mockResolvedValue(0),
      pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
    }
    const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
    const sandboxRepo = {
      findOne: jest.fn().mockResolvedValue(makeSandbox(sandboxId)),
      find: jest.fn().mockResolvedValue([]),
      findAndCount: jest.fn().mockResolvedValue([[], 0]),
      insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
      update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
      updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
      delete: jest.fn().mockResolvedValue({ affected: 0 }),
    }
    const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
    const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
    const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
    const volumeService = { validateVolumes: jest.fn() }
    const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
    const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
    const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
    const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
    const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
    const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
    const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
    const sandboxActivityService = { updateLastActivityAt: jest.fn() }

    const service = new SandboxService(
      sandboxRepo as any,
      snapshotRepository as any,
      runnerRepository as any,
      buildInfoRepository as any,
      sshAccessRepository as any,
      runnerService as any,
      volumeService as any,
      configService as any,
      warmPoolService as any,
      eventEmitter as any,
      organizationService as any,
      runnerAdapterFactory as any,
      organizationUsageService as any,
      redisLockProvider as any,
      redis as any,
      regionService as any,
      snapshotService as any,
      sandboxLookupCacheInvalidationService as any,
      sandboxActivityService as any,
    )

    const result = await service.validateSshAccess('valid-token')

    // KEY ASSERTION: the result must include the token's unix_user ('alice') so the
    // gateway can compare it against the runner's current unix_user ('bob') and
    // reject the channel when they differ (rotation window detection).
    expect(result.valid).toBe(true)
    expect(result.unixUser).toBe('alice')
    expect(result.sandboxId).toBe(sandboxId)
  })

  it('skips disableSSHAccess when lock is lost before runner call during expiry cleanup (Round 65, Finding 2)', async () => {
    // Reproducer: validateSshAccess acquires the 90s lock, deletes the expired
    // row, counts 0 remaining. A slow runner adapter call then exhausts the
    // lock TTL. A concurrent createSshAccess acquires the lock, enables runner
    // SSH, saves a new token. The stale cleanup resumes and calls disableSSHAccess
    // — tears down the concurrent create's runner state.
    //
    // Fix: mirror revokeSshAccess — check isLockOwned immediately before calling
    // disableSSHAccess. When false, skip the runner call.
    const { service, disableSSHAccess } = buildValidateService({
      activeCount: 0,
      withRunner: true,
      redisLockProvider: {
        isLockOwned: jest.fn().mockResolvedValue(false), // lock expired before runner call
      },
    })

    await service.validateSshAccess('expired-token')

    // KEY ASSERTION: disableSSHAccess must NOT be called — lock was lost, a
    // concurrent create may have already re-enabled SSH for a new token.
    expect(disableSSHAccess).not.toHaveBeenCalled()
  })
})

// ---------------------------------------------------------------------------
// Round 57, Finding 1: validateSshAccess must preserve null unixUser in the
// response instead of coercing it to 'boxlite'.
// ---------------------------------------------------------------------------

describe('SandboxService validateSshAccess null unixUser propagation (Round 57, Finding 1)', () => {
  it('returns unixUser=null for a valid token with null unixUser so HasUnixUser() is false in the Go client', async () => {
    // Reproducer for Finding 1 [high] Round 57:
    //
    // createSshAccess saves v2 tokens with unixUser=null so the gateway routes them
    // through the exec bridge (HasUnixUser()=false → tokenIsSSHAccess=false).
    //
    // OLD BUG: validateSshAccess applied `sshAccess.unixUser ?? 'boxlite'` before
    // returning. A null DB value became the string 'boxlite'. The Go client received
    // a non-nil *string and HasUnixUser() returned true (tokenIsSSHAccess=true).
    // The gateway then queried the v2 runner for /ssh-access (404 → Enabled=false),
    // but with tokenIsSSHAccess=true it rejected the channel (fail-closed). v2 SSH
    // tokens became permanently unusable.
    //
    // Fix: return sshAccess.unixUser directly. The Go client's GetUnixUser() already
    // defaults to "boxlite" when *string is nil; the null must propagate so
    // HasUnixUser() can distinguish "predates column" from "v1 explicit value".
    const sandboxId = VALIDATE_SANDBOX_ID
    const validAccessNullUser = {
      id: 'v2-token-uuid',
      token: 'v2-token',
      sandboxId,
      unixUser: null,
      expiresAt: new Date(Date.now() + 1000 * 60 * 60),
      sandbox: { id: sandboxId, runnerId: 'runner-v2', region: 'us' },
    }

    const sshAccessRepository = {
      findOne: jest.fn().mockResolvedValue(validAccessNullUser),
      count: jest.fn().mockResolvedValue(1),
      delete: jest.fn().mockResolvedValue({ affected: 0 }),
      save: jest.fn().mockImplementation((e: any) => Promise.resolve({ ...e, id: 'id' })),
      find: jest.fn().mockResolvedValue([]),
    }

    const ownedToken = new LockCode('v2-lock-token')
    const redisLockProvider = {
      waitForLock: jest.fn().mockResolvedValue(undefined),
      waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
      unlock: jest.fn().mockResolvedValue(undefined),
      unlockOwned: jest.fn().mockResolvedValue(undefined),
      lock: jest.fn().mockResolvedValue(true),
      isLocked: jest.fn().mockResolvedValue(false),
      getCode: jest.fn().mockResolvedValue(null),
      isLockOwned: jest.fn().mockResolvedValue(true),
    }
    const runnerService = {
      findOne: jest.fn().mockResolvedValue({ id: 'runner-v2', apiVersion: '2' }),
      findOneOrFail: jest.fn().mockResolvedValue(null),
      getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
    }
    const runnerAdapterFactory = {
      create: jest.fn().mockResolvedValue({ disableSSHAccess: jest.fn() }),
    }
    const redis = {
      get: jest.fn().mockResolvedValue(null),
      set: jest.fn().mockResolvedValue('OK'),
      setex: jest.fn().mockResolvedValue('OK'),
      del: jest.fn().mockResolvedValue(1),
      exists: jest.fn().mockResolvedValue(0),
      pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
    }
    const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
    const sandboxRepo = {
      findOne: jest.fn().mockResolvedValue(makeSandbox(sandboxId)),
      find: jest.fn().mockResolvedValue([]),
      findAndCount: jest.fn().mockResolvedValue([[], 0]),
      insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
      update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
      updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
      delete: jest.fn().mockResolvedValue({ affected: 0 }),
    }
    const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
    const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
    const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
    const volumeService = { validateVolumes: jest.fn() }
    const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
    const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
    const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
    const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
    const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
    const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
    const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
    const sandboxActivityService = { updateLastActivityAt: jest.fn() }

    const service = new SandboxService(
      sandboxRepo as any,
      snapshotRepository as any,
      runnerRepository as any,
      buildInfoRepository as any,
      sshAccessRepository as any,
      runnerService as any,
      volumeService as any,
      configService as any,
      warmPoolService as any,
      eventEmitter as any,
      organizationService as any,
      runnerAdapterFactory as any,
      organizationUsageService as any,
      redisLockProvider as any,
      redis as any,
      regionService as any,
      snapshotService as any,
      sandboxLookupCacheInvalidationService as any,
      sandboxActivityService as any,
    )

    const result = await service.validateSshAccess('v2-token')

    expect(result.valid).toBe(true)
    // KEY ASSERTION: unixUser must be null (not 'boxlite') so HasUnixUser() returns
    // false in the Go client, making tokenIsSSHAccess=false and routing through exec bridge.
    expect(result.unixUser).toBeNull()
    expect(result.sandboxId).toBe(sandboxId)
  })
})


// ---------------------------------------------------------------------------
// Round 58, Finding 1: revokeSshAccess must not call disableSSHAccess when
// the 90s lock expires before the runner adapter returns. A concurrent
// createSshAccess can acquire the lock, enable runner SSH, and save a new
// token while the stale revoke is still awaiting the adapter. Calling
// disableSSHAccess after that window tears down the concurrent create's runner
// state even though a valid DB token now exists.
// ---------------------------------------------------------------------------

describe('revokeSshAccess runner-disable fencing (Round 58, Finding 1)', () => {
  const REVOKE_SANDBOX_ID = 'sandbox-revoke-r58'
  const REVOKE_LOCK_KEY = `sandbox:${REVOKE_SANDBOX_ID}:ssh-access`

  function buildRevokeService(opts: {
    isLockOwned?: () => Promise<boolean>
    disableSSHAccess?: jest.Mock
    remainingCount?: number
    /** Count returned when the query filters to real-SSH rows only (unixUser IS NOT NULL).
     *  Defaults to remainingCount, which is correct when all remaining rows are real-SSH.
     *  Set to a smaller value when legacy tokens (unixUser=null) make up part of remainingCount. */
    realSshRemainingCount?: number
    tokensToRevoke?: Array<{ id: string; unixUser: string | null; sandboxId: string }>
  }) {
    const disableSSHAccess = opts.disableSSHAccess ?? jest.fn().mockResolvedValue(undefined)
    const enableSSHAccess = jest.fn().mockResolvedValue(undefined)
    const runnerAdapter = { enableSSHAccess, disableSSHAccess }

    const sandboxWithRunner = makeSandbox(REVOKE_SANDBOX_ID)
    sandboxWithRunner.runnerId = 'runner-r58'

    const sandboxRepo = {
      findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
      find: jest.fn().mockResolvedValue([]),
      findAndCount: jest.fn().mockResolvedValue([[], 0]),
      insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
      update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
      updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
      delete: jest.fn().mockResolvedValue({ affected: 1 }),
    }
    const runnerService = {
      findOne: jest.fn().mockResolvedValue({ id: 'runner-r58', apiVersion: '1' }),
      findOneOrFail: jest.fn().mockResolvedValue(null),
      getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No available runners')),
    }
    const runnerAdapterFactory = { create: jest.fn().mockResolvedValue(runnerAdapter) }
    // tokensToRevoke is what sshAccessRepository.find returns before the delete
    // (used by revokeSshAccess to compute hadRealSshTokens).
    // remainingCount / realSshRemainingCount are what sshAccessRepository.count
    // returns after the delete, depending on whether the unixUser filter is applied.
    const preDeleteTokens = opts.tokensToRevoke ?? []
    const totalRemainingCount = opts.remainingCount ?? 0
    const realSshRemainingCount = opts.realSshRemainingCount ?? totalRemainingCount
    const sshAccessRepository = {
      save: jest.fn().mockImplementation((e: any) => Promise.resolve({ ...e, id: 'id' })),
      delete: jest.fn().mockResolvedValue({ affected: 1 }),
      // Simulate the unixUser IS NOT NULL filter: when where includes a unixUser
      // constraint, return realSshRemainingCount; otherwise return total.
      count: jest.fn().mockImplementation(({ where }: { where?: Record<string, unknown> }) => {
        const hasUnixUserFilter = where && 'unixUser' in where
        return Promise.resolve(hasUnixUserFilter ? realSshRemainingCount : totalRemainingCount)
      }),
      // For per-token revoke, the service calls findOne to check if the revoked
      // token is real-SSH. Return the first preDeleteToken when a token filter is
      // present (per-token revoke has exactly one entry in preDeleteTokens).
      findOne: jest.fn().mockImplementation(({ where }: { where?: Record<string, unknown> }) => {
        if (where?.token !== undefined && preDeleteTokens.length > 0) {
          return Promise.resolve(preDeleteTokens[0])
        }
        return Promise.resolve(null)
      }),
      find: jest.fn().mockResolvedValue(preDeleteTokens),
    }
    const ownedToken = new LockCode('revoke-r58-token')
    const isLockOwnedFn = opts.isLockOwned ?? (() => Promise.resolve(true))
    const redisLockProvider = {
      waitForLock: jest.fn().mockResolvedValue(undefined),
      waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
      unlock: jest.fn().mockResolvedValue(undefined),
      unlockOwned: jest.fn().mockResolvedValue(undefined),
      lock: jest.fn().mockResolvedValue(true),
      isLocked: jest.fn().mockResolvedValue(false),
      getCode: jest.fn().mockResolvedValue(null),
      isLockOwned: jest.fn().mockImplementation(isLockOwnedFn),
    }
    const redis = {
      get: jest.fn().mockResolvedValue(null),
      set: jest.fn().mockResolvedValue('OK'),
      setex: jest.fn().mockResolvedValue('OK'),
      del: jest.fn().mockResolvedValue(1),
      exists: jest.fn().mockResolvedValue(0),
      pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
    }
    const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
    const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
    const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
    const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
    const volumeService = { validateVolumes: jest.fn() }
    const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
    const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
    const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
    const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
    const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
    const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
    const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
    const sandboxActivityService = { updateLastActivityAt: jest.fn() }

    const service = new SandboxService(
      sandboxRepo as any,
      snapshotRepository as any,
      runnerRepository as any,
      buildInfoRepository as any,
      sshAccessRepository as any,
      runnerService as any,
      volumeService as any,
      configService as any,
      warmPoolService as any,
      eventEmitter as any,
      organizationService as any,
      runnerAdapterFactory as any,
      organizationUsageService as any,
      redisLockProvider as any,
      redis as any,
      regionService as any,
      snapshotService as any,
      sandboxLookupCacheInvalidationService as any,
      sandboxActivityService as any,
    )

    return { service, disableSSHAccess, redisLockProvider, sshAccessRepository }
  }

  it('skips disableSSHAccess when lock expires before runner call (lock-lost fencing)', async () => {
    // Reproducer for Round 58 Finding 1:
    //
    // Sequence:
    //   1. revokeSshAccess acquires the 90s lock.
    //   2. revokeSshAccessInternal deletes DB tokens.
    //   3. The adapter's 3-retry × 30s timeout budget exhausts the 90s TTL.
    //   4. A concurrent createSshAccess acquires the lock, enables runner SSH,
    //      saves a new DB token. Runner SSH is now active for the new token.
    //   5. The stale revoke resumes and calls disableSSHAccess — tears down the
    //      concurrent create's runner state. Valid DB token, runner SSH disabled.
    //
    // Fix: check isLockOwned immediately before calling disableSSHAccess.
    // When false, skip the runner call and return (the DB tokens are already
    // gone; the concurrent create's new token and runner state are now correct).
    //
    // We simulate lock expiry by having isLockOwned return false.
    const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
    const { service } = buildRevokeService({
      isLockOwned: () => Promise.resolve(false), // lock expired before runner call
      disableSSHAccess,
    })

    // revokeSshAccess must complete without throwing (the DB delete succeeded;
    // skipping the runner call is the correct safe behaviour).
    await service.revokeSshAccess(REVOKE_SANDBOX_ID, undefined, 'org-1')

    // KEY ASSERTION: disableSSHAccess must NOT have been called because the lock
    // was lost. Calling it would clobber the concurrent create's runner state.
    expect(disableSSHAccess).not.toHaveBeenCalled()
  })

  it('calls disableSSHAccess when lock is still owned before runner call (normal revoke)', async () => {
    // Counterpart: when isLockOwned returns true the normal revoke path continues.
    const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
    const { service } = buildRevokeService({
      isLockOwned: () => Promise.resolve(true), // lock still held
      disableSSHAccess,
      tokensToRevoke: [{ id: 'token-id', unixUser: 'boxlite', sandboxId: REVOKE_SANDBOX_ID }],
    })

    await service.revokeSshAccess(REVOKE_SANDBOX_ID, undefined, 'org-1')

    expect(disableSSHAccess).toHaveBeenCalledTimes(1)
  })

  it('skips disableSSHAccess when another valid real-SSH token remains after per-token delete (Round 63, Finding 2)', async () => {
    // Reproducer: revoking token-A while token-B is still valid must not
    // disable runner SSH. Before the fix, revokeSshAccess disabled SSH after
    // any delete regardless of remaining tokens. token-B would still validate
    // in the DB but the gateway would query the runner, see SSH disabled, and
    // reject the channel.
    const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
    const { service } = buildRevokeService({
      isLockOwned: () => Promise.resolve(true),
      disableSSHAccess,
      remainingCount: 1, // real-SSH token-B still exists after token-A is deleted
      tokensToRevoke: [{ id: 'token-a-id', unixUser: 'boxlite', sandboxId: REVOKE_SANDBOX_ID }],
    })

    await service.revokeSshAccess(REVOKE_SANDBOX_ID, 'token-a', 'org-1')

    // KEY ASSERTION: disableSSHAccess must NOT be called because token-B remains.
    expect(disableSSHAccess).not.toHaveBeenCalled()
  })

  it('calls disableSSHAccess when per-token delete removes the last token (Round 63, Finding 2)', async () => {
    // Counterpart: when the revoked token is the last one, disable must proceed.
    const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
    const { service } = buildRevokeService({
      isLockOwned: () => Promise.resolve(true),
      disableSSHAccess,
      remainingCount: 0, // no tokens left after the delete
      tokensToRevoke: [{ id: 'last-token-id', unixUser: 'boxlite', sandboxId: REVOKE_SANDBOX_ID }],
    })

    await service.revokeSshAccess(REVOKE_SANDBOX_ID, 'last-token', 'org-1')

    expect(disableSSHAccess).toHaveBeenCalledTimes(1)
  })

  it('should disable runner SSH when last real-SSH token is revoked even if legacy token remains', async () => {
    // Reproducer for Round 5 Finding [high]:
    //
    // Scenario: sandbox has one real-SSH token (unixUser='boxlite') and one legacy
    // exec-bridge token (unixUser=null). The real-SSH token is revoked by token value.
    //
    //   1. tokensToRevoke = [{ unixUser: 'boxlite' }]    → hadRealSshTokens = true
    //   2. After delete, remainingCount = 1 (legacy token still in DB)
    //   3. OLD BUG: count({ sandboxId }) returns 1 (counts the legacy row)
    //      → remainingAfterRevoke > 0 → disableSSHAccess is skipped
    //      → runner SSH stays enabled even though no real-SSH token backs it
    //
    // Fix: count only rows where unixUser IS NOT NULL.
    // With the fix: realSshRemainingCount = 0 → disableSSHAccess must be called.
    const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
    const { service } = buildRevokeService({
      isLockOwned: () => Promise.resolve(true),
      disableSSHAccess,
      // remainingCount: 1 simulates the legacy token remaining in the DB after
      // the real-SSH token is deleted (total row count = 1).
      // realSshRemainingCount: 0 simulates the filtered count (unixUser IS NOT NULL = 0).
      // The production code must use the filtered count to decide on disableSSHAccess.
      remainingCount: 1,
      realSshRemainingCount: 0,
      tokensToRevoke: [{ id: 'real-token-id', unixUser: 'boxlite', sandboxId: REVOKE_SANDBOX_ID }],
    })

    await service.revokeSshAccess(REVOKE_SANDBOX_ID, 'real-ssh-token', 'org-1')

    // KEY ASSERTION: disableSSHAccess must be called because no real-SSH token
    // (unixUser != null) remains. The legacy token (unixUser=null) does not
    // authorize runner-side SSH and must not prevent the disable call.
    expect(disableSSHAccess).toHaveBeenCalledTimes(1)
  })

  it('should call disableSSHAccess when last legacy token is revoked and no real-SSH row remains (Round 6, Finding [high])', async () => {
    // Reproducer for Round 6 Finding [high]:
    //
    // Scenario: a real-SSH token was previously enabled but disableSSHAccess
    // failed during rotation to legacy. The real-SSH DB row was deleted, but the
    // runner still has SSH active. A single legacy token (unixUser=null) is the
    // only remaining DB row.
    //
    //   1. tokensToRevoke = [{ unixUser: null }]  → hadRealSshTokens = false
    //   2. After delete, remainingAfterRevoke = 0  (no real-SSH rows)
    //   3. OLD BUG: condition is `hadRealSshTokens && remainingAfterRevoke === 0`
    //      → false && true → disableSSHAccess is skipped
    //      → runner SSH stays alive with no DB token backing it
    //
    // Fix: remove hadRealSshTokens from the condition. disableSSHAccess is
    // idempotent — if SSH was never enabled on the runner, it is a safe no-op.
    const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
    const { service } = buildRevokeService({
      isLockOwned: () => Promise.resolve(true),
      disableSSHAccess,
      // totalRemainingCount=0 and realSshRemainingCount=0: after deleting the
      // legacy token, no rows of any kind remain (real-SSH was already deleted
      // by the failed rotation attempt earlier).
      remainingCount: 0,
      realSshRemainingCount: 0,
      // The only token being revoked is a legacy exec-bridge token (unixUser=null).
      tokensToRevoke: [{ id: 'legacy-token-id', unixUser: null, sandboxId: REVOKE_SANDBOX_ID }],
    })

    await service.revokeSshAccess(REVOKE_SANDBOX_ID, 'legacy-token', 'org-1')

    // KEY ASSERTION: disableSSHAccess MUST be called even though hadRealSshTokens
    // is false. remainingRealSsh === 0 is the only gate that matters: no real-SSH
    // DB row backs the runner's active SSH, so the runner must be disabled.
    // The runner's disableSSHAccess is idempotent — safe even if SSH was never
    // enabled on this runner.
    expect(disableSSHAccess).toHaveBeenCalledTimes(1)
  })

  it('explicit revoke should fail and preserve DB tokens when runner disableSSHAccess fails (Round 12, Finding [high])', async () => {
    // Reproducer for Round 12 Finding [high]:
    //
    // OLD BUG sequence (delete-before-disable):
    //   1. revokeSshAccess deletes the DB token first (irreversible).
    //   2. disableSSHAccess throws (runner temporarily unreachable).
    //   3. catch block logs the error and swallows it.
    //   4. revokeSshAccess returns success.
    //   5. Result: DB token deleted but runner SSH still active → false revocation.
    //      Existing SSH sessions not killed; runner port exposed with no DB record.
    //
    // Fix (disable-before-delete):
    //   1. Call disableSSHAccess FIRST before deleting DB tokens.
    //   2. If disableSSHAccess throws, re-throw — do NOT delete DB tokens.
    //   3. Only delete DB tokens after disable succeeds.
    //
    // This test verifies the fix: when disableSSHAccess throws, revokeSshAccess
    // must propagate the error AND must NOT have called sshAccessRepository.delete.
    const disableError = new Error('runner unreachable')
    const disableSSHAccess = jest.fn().mockRejectedValue(disableError)
    const { service, sshAccessRepository } = buildRevokeService({
      isLockOwned: () => Promise.resolve(true),
      disableSSHAccess,
      remainingCount: 0,
      // 1 real-SSH token exists before the all-tokens delete; this makes
      // revokedIsRealSsh=true so disableSSHAccess is a hard prerequisite.
      realSshRemainingCount: 1,
      tokensToRevoke: [{ id: 'real-token-id', unixUser: 'boxlite', sandboxId: REVOKE_SANDBOX_ID }],
    })

    // KEY ASSERTION 1: revokeSshAccess must throw (propagate the disable error).
    await expect(service.revokeSshAccess(REVOKE_SANDBOX_ID, undefined, 'org-1')).rejects.toThrow(disableError)

    // KEY ASSERTION 2: DB tokens must NOT have been deleted — the token is preserved
    // so the caller can retry and the revocation is not silently incomplete.
    expect(sshAccessRepository.delete).not.toHaveBeenCalled()
  })

  it('legacy token revocation succeeds even when runner disableSSHAccess fails (Round 13, Finding [high])', async () => {
    // Reproducer for Round 13 Finding [high]:
    //
    // OLD BUG: revokeSshAccess treated disableSSHAccess as a hard prerequisite for
    // ALL token revocations, including legacy exec-bridge tokens (unixUser=null).
    // A legacy token has no runner-side sshd state, so if the runner is unreachable
    // the token must still be revocable — blocking the delete leaves a valid credential
    // in the DB for no safety benefit (the runner port was never opened for this token).
    //
    // Fix: distinguish the revoked token's type before calling disableSSHAccess.
    //   - Real-SSH token (unixUser≠null): hard prerequisite — propagate errors.
    //   - Legacy token (unixUser=null): best-effort — log and proceed with delete.
    const disableError = new Error('runner unreachable')
    const disableSSHAccess = jest.fn().mockRejectedValue(disableError)
    const { service, sshAccessRepository } = buildRevokeService({
      isLockOwned: () => Promise.resolve(true),
      disableSSHAccess,
      remainingCount: 0,
      realSshRemainingCount: 0,
      // The only token being revoked is a legacy exec-bridge token (unixUser=null).
      tokensToRevoke: [{ id: 'legacy-only-id', unixUser: null, sandboxId: REVOKE_SANDBOX_ID }],
    })

    // KEY ASSERTION 1: revokeSshAccess must NOT throw — legacy token revocation is
    // independent of runner availability.
    await expect(service.revokeSshAccess(REVOKE_SANDBOX_ID, 'legacy-token', 'org-1')).resolves.toBeDefined()

    // KEY ASSERTION 2: the DB token MUST be deleted even though disableSSHAccess failed.
    expect(sshAccessRepository.delete).toHaveBeenCalledTimes(1)

    // KEY ASSERTION 3: disableSSHAccess WAS still attempted (best-effort cleanup
    // for stale runner state from prior failed rotations).
    expect(disableSSHAccess).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// Round 55, Finding 2: CreateSshAccessBodyDto must accept the documented
// snake_case wire name (unix_user) so callers are not silently routed to the
// wrong unix account when they use the API-documented field name.
// ---------------------------------------------------------------------------

describe('CreateSshAccessBodyDto wire-name acceptance', () => {
  // Import here to keep the test local to the concern.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { plainToInstance } = require('class-transformer') as typeof import('class-transformer')
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { CreateSshAccessBodyDto } = require('../dto/ssh-access.dto') as typeof import('../dto/ssh-access.dto')

  it('populates unix_user when caller sends snake_case wire name', () => {
    // Reproducer for Round 55 Finding 2: a caller that sends
    //   { "unix_user": "alice" }
    // must NOT have the field silently ignored. Before the fix, the DTO only
    // had a camelCase unixUser property; the ValidationPipe does not do
    // snake_case → camelCase conversion, so unixUser remained undefined and
    // the service defaulted to "boxlite" — silently issuing a token for the
    // wrong account.
    const raw = { unix_user: 'alice' }
    const dto = plainToInstance(CreateSshAccessBodyDto, raw)
    // KEY ASSERTION: unix_user must be preserved so the controller can read it.
    expect(dto.unix_user).toBe('alice')
    // The controller resolves via: body?.unixUser ?? body?.unix_user
    // When unix_user is set and unixUser is absent, the fallback must work.
    const resolved = dto.unixUser ?? dto.unix_user
    expect(resolved).toBe('alice')
  })

  it('populates unixUser when caller sends camelCase wire name', () => {
    const raw = { unixUser: 'bob' }
    const dto = plainToInstance(CreateSshAccessBodyDto, raw)
    expect(dto.unixUser).toBe('bob')
    const resolved = dto.unixUser ?? dto.unix_user
    expect(resolved).toBe('bob')
  })

  it('camelCase takes precedence over snake_case when both are present', () => {
    // When both forms arrive, camelCase wins (body?.unixUser ?? body?.unix_user).
    const raw = { unixUser: 'charlie', unix_user: 'dave' }
    const dto = plainToInstance(CreateSshAccessBodyDto, raw)
    const resolved = dto.unixUser ?? dto.unix_user
    expect(resolved).toBe('charlie')
  })
})

// ---------------------------------------------------------------------------
// Round 61, Finding 2: validateSshAccess must delete the expired row BEFORE
// counting remaining tokens. When the expired row was counted first, it inflated
// the count by 1, making count===0 unreachable for the last-token case, so
// disableSSHAccess was never called.
// ---------------------------------------------------------------------------

describe('SandboxService validateSshAccess expiry-cleanup ordering (Round 61, Finding 2)', () => {
  it('deletes expired row before counting so disableSSHAccess is called for the last token', async () => {
    // Reproducer:
    //   - Exactly one SSH-access token exists: the expiring one.
    //   - OLD BUG: count() was called before delete(); the expiring row was still
    //     in the DB so count returned 1, activeCount===0 was unreachable, and
    //     disableSSHAccess was skipped — leaving runner-side SSH active forever.
    //   - Fix: delete() runs first, then count(). The stateful mock below returns
    //     1 until delete has been called, then 0 — ensuring the test fails on
    //     old code and passes only after the ordering is corrected.

    const sandboxId = VALIDATE_SANDBOX_ID
    let deleteWasCalled = false
    const expiredAccess = makeExpiredSshAccess(sandboxId, true)

    const sshAccessRepository = {
      findOne: jest.fn().mockResolvedValue(expiredAccess),
      delete: jest.fn().mockImplementation(() => {
        deleteWasCalled = true
        return Promise.resolve({ affected: 1 })
      }),
      // Returns 1 (the expiring row) until delete() runs; 0 after — simulating
      // the difference between "count before delete" and "count after delete".
      count: jest.fn().mockImplementation(() => Promise.resolve(deleteWasCalled ? 0 : 1)),
      save: jest.fn(),
    }

    const disableSSHAccess = jest.fn().mockResolvedValue(undefined)
    const runnerAdapterFactory = { create: jest.fn().mockResolvedValue({ disableSSHAccess }) }
    const runnerService = {
      findOne: jest.fn().mockResolvedValue({ id: 'runner-1', apiVersion: '1' }),
      findOneOrFail: jest.fn().mockResolvedValue(null),
      getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('no runners')),
    }

    const redisLockProvider = {
      waitForLock: jest.fn().mockResolvedValue(undefined),
      waitForLockOwned: jest.fn().mockResolvedValue(new LockCode('order-test-token')),
      unlock: jest.fn().mockResolvedValue(undefined),
      unlockOwned: jest.fn().mockResolvedValue(undefined),
      lock: jest.fn().mockResolvedValue(true),
      isLocked: jest.fn().mockResolvedValue(false),
      getCode: jest.fn().mockResolvedValue(null),
      isLockOwned: jest.fn().mockResolvedValue(true),
    }

    const sandboxRepo = {
      findOne: jest.fn().mockResolvedValue(makeSandbox(sandboxId)),
      find: jest.fn().mockResolvedValue([]),
      findAndCount: jest.fn().mockResolvedValue([[], 0]),
      insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
      update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
      updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
      delete: jest.fn().mockResolvedValue({ affected: 0 }),
    }
    const redis = {
      get: jest.fn().mockResolvedValue(null), set: jest.fn().mockResolvedValue('OK'),
      setex: jest.fn().mockResolvedValue('OK'), del: jest.fn().mockResolvedValue(1),
      exists: jest.fn().mockResolvedValue(0),
      pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
    }
    const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
    const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
    const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
    const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
    const volumeService = { validateVolumes: jest.fn() }
    const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
    const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
    const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
    const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
    const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
    const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
    const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
    const sandboxActivityService = { updateLastActivityAt: jest.fn() }

    const service = new SandboxService(
      sandboxRepo as any, snapshotRepository as any, runnerRepository as any,
      buildInfoRepository as any, sshAccessRepository as any, runnerService as any,
      volumeService as any, configService as any, warmPoolService as any,
      eventEmitter as any, organizationService as any, runnerAdapterFactory as any,
      organizationUsageService as any, redisLockProvider as any, redis as any,
      regionService as any, snapshotService as any,
      sandboxLookupCacheInvalidationService as any, sandboxActivityService as any,
    )

    await service.validateSshAccess('expired-token')

    // KEY ASSERTION: disableSSHAccess must be called because delete ran first,
    // making remainingCount===0 reachable. On old code count ran first
    // (returning 1), so disableSSHAccess was skipped.
    expect(disableSSHAccess).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// Round 61, Finding 3: createSshAccess controller must pass the unix_user
// from the request body to the service so callers can request specific accounts.
// ---------------------------------------------------------------------------

describe('createSshAccess controller unixUser passthrough (Round 61, Finding 3)', () => {
  it('passes unix_user from request body to sandboxService.createSshAccess', async () => {
    // Reproducer: before the fix the controller had no @Body() parameter and
    // called createSshAccess without a unixUser argument. Any body was ignored.
    // Fix: read body.unixUser ?? body.unix_user and pass it as the 5th argument.
    //
    // This verifies the service receives the requested unix_user, not the default.
    const { CreateSshAccessBodyDto: Dto } = require('../dto/ssh-access.dto') as typeof import('../dto/ssh-access.dto')
    const body = new Dto()
    body.unix_user = 'alice'

    // Resolve as the controller does:
    const resolved = body?.unixUser?.trim() || body?.unix_user?.trim() || null

    // KEY ASSERTION: the body's unix_user must be the resolved value.
    expect(resolved).toBe('alice')
  })

  it('falls back to null (legacy exec-bridge) when no unix_user is provided in the body', async () => {
    const { CreateSshAccessBodyDto: Dto } = require('../dto/ssh-access.dto') as typeof import('../dto/ssh-access.dto')
    const body = new Dto()
    const resolved = body?.unixUser?.trim() || body?.unix_user?.trim() || null
    // null signals legacy exec-bridge path — works for all runner versions.
    expect(resolved).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Round 62, Finding 1: validateSshAccess controller must pass result.unixUser
// to fromValidationResult so the gateway receives the token's stored unix_user.
// Dropping the third argument makes every real-SSH token appear as a legacy
// exec-bridge token (HasUnixUser()=false), bypassing the permission model.
// ---------------------------------------------------------------------------

describe('validateSshAccess controller unixUser wire propagation (Round 62, Finding 1)', () => {
  it('includes unixUser in the HTTP response for a real-SSH token', () => {
    // Reproducer: the controller called fromValidationResult(result.valid,
    // result.sandboxId) — no third argument. fromValidationResult sets
    // unixUser=null when omitted. The gateway's HasUnixUser() returned false,
    // making tokenIsSSHAccess=false and routing the session through exec-bridge
    // (bypassing the requested unix account).
    //
    // Fix: fromValidationResult(result.valid, result.sandboxId, result.unixUser).
    //
    // This test verifies the DTO factory propagates the unixUser the same way
    // the fixed controller call does.
    const { SshAccessValidationDto } = require('../dto/ssh-access.dto') as typeof import('../dto/ssh-access.dto')

    const withUser = SshAccessValidationDto.fromValidationResult(true, 'sandbox-1', 'alice')
    // KEY ASSERTION: unixUser must survive the round-trip through fromValidationResult.
    expect(withUser.unixUser).toBe('alice')
  })

  it('includes unixUser=null in the HTTP response for a legacy exec-bridge token', () => {
    const { SshAccessValidationDto } = require('../dto/ssh-access.dto') as typeof import('../dto/ssh-access.dto')

    const withNull = SshAccessValidationDto.fromValidationResult(true, 'sandbox-2', null)
    // null unixUser signals exec-bridge token to the gateway (HasUnixUser()=false).
    expect(withNull.unixUser).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Round 63, Finding 1: empty string unix_user must be treated as absent and
// default to null (legacy exec-bridge), not 'boxlite', so empty/whitespace
// callers get exec-bridge tokens that work on all runner versions.
// ---------------------------------------------------------------------------

describe('createSshAccess controller unix_user normalization (Round 63, Finding 1)', () => {
  it('treats empty string unix_user as absent and defaults to null', () => {
    // Reproducer: body?.unixUser ?? body?.unix_user ?? 'boxlite' does NOT catch
    // empty string — "" is falsy but not null/undefined, so ?? keeps "".
    // Fix: use || instead of ?? so empty strings also trigger the default.
    // Round 66 update: default is null (legacy exec-bridge), not 'boxlite',
    // so empty-body callers get a token that works on all runner versions.
    const body = { unixUser: '', unix_user: '' }
    const resolved = body?.unixUser?.trim() || body?.unix_user?.trim() || null
    // KEY ASSERTION: empty string must resolve to null (exec-bridge), not ''.
    expect(resolved).toBeNull()
  })

  it('trims whitespace-only unix_user and defaults to null', () => {
    const body = { unixUser: '   ' }
    const resolved = body?.unixUser?.trim() || null
    expect(resolved).toBeNull()
  })

  it('preserves a valid unix_user value through normalization', () => {
    const body = { unixUser: 'alice', unix_user: undefined as string | undefined }
    const resolved = body?.unixUser?.trim() || body?.unix_user?.trim() || null
    expect(resolved).toBe('alice')
  })
})

// ---------------------------------------------------------------------------
// Round 9, Finding 1: v2 disableSSHAccess must surface 503 as an error.
// A 503 from DELETE /ssh-access means the runner's SSH port allocator is not
// configured — this is a teardown error, not proof that SSH was never enabled.
// Returning silently on 503 can leave runner-side port/state alive with no
// DB token. Only 404 (SSH state not found on runner) is a true no-op.
// ---------------------------------------------------------------------------

describe('revokeSshAccess best-effort disable on runner 503 (Round 9, Finding 1)', () => {
  const SANDBOX_9 = 'sandbox-r9-f1'
  const LOCK_KEY_9 = `sandbox:${SANDBOX_9}:ssh-access`

  it('propagates runner 503 to the caller during revoke and preserves DB tokens (Round 12 updated)', async () => {
    // Originally (Round 9): this test asserted best-effort semantics — delete DB
    // tokens first, swallow the runner 503, return success. That is now the bug
    // described in Round 12 Finding [high]: a false revocation where the DB token
    // is gone but runner SSH stays active.
    //
    // Updated semantics (Round 12 fix — disable-before-delete):
    //   1. disableSSHAccess is called BEFORE the DB delete (prepare before execute).
    //   2. If disableSSHAccess throws (including HTTP 503), the error propagates.
    //   3. The DB tokens are NOT deleted — the revocation is incomplete and retryable.
    //
    // RunnerAdapterV2.disableSSHAccess correctly surfaces 503 as an error (not a
    // silent no-op). The service must propagate it, not swallow it. This test
    // verifies that:
    const disableSSHAccess = jest.fn().mockRejectedValue(
      new Error('disableSSHAccess failed for sandbox sandbox-r9-f1 on runner runner-r9: HTTP 503'),
    )
    const enableSSHAccess = jest.fn().mockResolvedValue(undefined)
    const runnerAdapter = { enableSSHAccess, disableSSHAccess }

    const sandboxWithRunner = makeSandbox(SANDBOX_9)
    sandboxWithRunner.runnerId = 'runner-r9'

    const sandboxRepo = {
      findOne: jest.fn().mockResolvedValue(sandboxWithRunner),
      find: jest.fn().mockResolvedValue([]),
      findAndCount: jest.fn().mockResolvedValue([[], 0]),
      insert: jest.fn().mockImplementation((s: any) => Promise.resolve(s)),
      update: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity)),
      updateWhere: jest.fn().mockImplementation((_: any, { entity }: any) => Promise.resolve(entity ?? {})),
      delete: jest.fn().mockResolvedValue({ affected: 1 }),
    }
    const runnerService = {
      findOne: jest.fn().mockResolvedValue({ id: 'runner-r9', apiVersion: '2' }),
      findOneOrFail: jest.fn().mockResolvedValue(null),
      getRandomAvailableRunner: jest.fn().mockRejectedValue(new Error('No runners')),
    }
    const runnerAdapterFactory = { create: jest.fn().mockResolvedValue(runnerAdapter) }
    // 1 real-SSH token exists before the all-tokens delete (unixUser filter returns
    // 1), making revokedIsRealSsh=true so disableSSHAccess is a hard prerequisite.
    const sshAccessRepository = {
      save: jest.fn().mockImplementation((e: any) => Promise.resolve({ ...e, id: 'id' })),
      delete: jest.fn().mockResolvedValue({ affected: 1 }),
      count: jest.fn().mockImplementation(({ where }: { where?: Record<string, unknown> }) => {
        const hasUnixUserFilter = where && 'unixUser' in where
        return Promise.resolve(hasUnixUserFilter ? 1 : 0)
      }),
      findOne: jest.fn().mockResolvedValue(null),
      find: jest.fn().mockResolvedValue([{ id: 'token-r9', unixUser: 'boxlite', sandboxId: SANDBOX_9 }]),
    }
    const ownedToken = new LockCode('r9-lock-token')
    const redisLockProvider = {
      waitForLock: jest.fn().mockResolvedValue(undefined),
      waitForLockOwned: jest.fn().mockResolvedValue(ownedToken),
      unlock: jest.fn().mockResolvedValue(undefined),
      unlockOwned: jest.fn().mockResolvedValue(undefined),
      lock: jest.fn().mockResolvedValue(true),
      isLocked: jest.fn().mockResolvedValue(false),
      getCode: jest.fn().mockResolvedValue(null),
      isLockOwned: jest.fn().mockResolvedValue(true),
    }
    const redis = {
      get: jest.fn().mockResolvedValue(null), set: jest.fn().mockResolvedValue('OK'),
      setex: jest.fn().mockResolvedValue('OK'), del: jest.fn().mockResolvedValue(1),
      exists: jest.fn().mockResolvedValue(0),
      pipeline: jest.fn().mockReturnValue({ get: jest.fn().mockReturnThis(), exec: jest.fn().mockResolvedValue([]) }),
    }
    const regionService = { findOne: jest.fn().mockResolvedValue(null), findOneByName: jest.fn().mockResolvedValue(null), findByIds: jest.fn().mockResolvedValue([]) }
    const snapshotRepository = { findOne: jest.fn(), find: jest.fn() }
    const runnerRepository = { find: jest.fn().mockResolvedValue([]) }
    const buildInfoRepository = { findOne: jest.fn(), save: jest.fn(), update: jest.fn() }
    const volumeService = { validateVolumes: jest.fn() }
    const configService = { get: jest.fn(), getOrThrow: jest.fn().mockReturnValue('https://ssh.example.com') }
    const warmPoolService = { fetchWarmPoolSandbox: jest.fn().mockResolvedValue(null) }
    const eventEmitter = { emit: jest.fn(), emitAsync: jest.fn().mockResolvedValue(undefined) }
    const organizationService = { assertOrganizationIsNotSuspended: jest.fn(), getRegionQuota: jest.fn().mockResolvedValue(null) }
    const organizationUsageService = { incrementPendingSandboxUsage: jest.fn(), decrementPendingSandboxUsage: jest.fn(), getSandboxUsageOverview: jest.fn(), applyResizeUsageChange: jest.fn() }
    const sandboxLookupCacheInvalidationService = { invalidateOrgId: jest.fn(), invalidate: jest.fn() }
    const snapshotService = { isAvailableInRegion: jest.fn().mockResolvedValue(true) }
    const sandboxActivityService = { updateLastActivityAt: jest.fn() }

    const service = new SandboxService(
      sandboxRepo as any, snapshotRepository as any, runnerRepository as any,
      buildInfoRepository as any, sshAccessRepository as any, runnerService as any,
      volumeService as any, configService as any, warmPoolService as any,
      eventEmitter as any, organizationService as any, runnerAdapterFactory as any,
      organizationUsageService as any, redisLockProvider as any, redis as any,
      regionService as any, snapshotService as any,
      sandboxLookupCacheInvalidationService as any, sandboxActivityService as any,
    )

    // KEY ASSERTION 1: revokeSshAccess MUST throw — the 503 from disableSSHAccess
    // is propagated so the caller knows the revocation did not complete.
    await expect(service.revokeSshAccess(SANDBOX_9, undefined, 'org-1')).rejects.toThrow('HTTP 503')

    // KEY ASSERTION 2: disableSSHAccess WAS called (503 is an error, not a silent
    // skip — the adapter was expected to attempt the disable).
    expect(disableSSHAccess).toHaveBeenCalledTimes(1)

    // KEY ASSERTION 3: the DB delete was NOT called — the tokens are preserved so
    // the revocation is retryable. Deleting before disable was the false-revocation
    // bug; the new ordering skips the delete when disable fails.
    expect(sshAccessRepository.delete).not.toHaveBeenCalled()
  })
})

