/*
 * Copyright 2025 BoxLite AI
 * SPDX-License-Identifier: AGPL-3.0
 */

import { NotFoundException } from '@nestjs/common'

import { BoxService } from './box.service'

// The ssh-access methods only touch sshAccessRepository, regionService and
// configService (plus findOneByIdOrName, spied per test); every other
// injected dependency is irrelevant.
function makeService() {
  const sshAccessRepository = {
    save: jest.fn().mockImplementation(async (entity: any) => entity),
    delete: jest.fn().mockResolvedValue(undefined),
    findOne: jest.fn(),
  } as any
  const regionService = { findOne: jest.fn().mockResolvedValue(null) } as any
  const runnerService = { findOne: jest.fn() } as any
  const configService = { getOrThrow: jest.fn() } as any
  const noop = {} as any
  const service = new BoxService(
    noop, // boxRepository
    noop, // runnerRepository
    sshAccessRepository, // sshAccessRepository
    runnerService, // runnerService
    noop, // volumeService
    configService, // configService
    noop, // warmPoolService
    noop, // eventEmitter
    noop, // organizationService
    noop, // runnerAdapterFactory
    noop, // redisLockProvider
    noop, // redis
    regionService, // regionService
    noop, // boxLookupCacheInvalidationService
    noop, // boxActivityService
  )
  return { service, sshAccessRepository, regionService, runnerService, configService }
}

const box = { id: 'box-1', region: 'us' } as any

describe('BoxService.createSshAccess', () => {
  it('revokes existing SSH access for the box before saving the new token', async () => {
    const { service, sshAccessRepository, configService } = makeService()
    jest.spyOn(service, 'findOneByIdOrName').mockResolvedValue(box)
    configService.getOrThrow.mockReturnValue('gateway.example.com')

    await service.createSshAccess('box-1')

    expect(sshAccessRepository.delete).toHaveBeenCalledWith({ boxId: 'box-1' })
    // Revocation must land before the new token is persisted, otherwise the
    // fresh token would be wiped along with the stale ones.
    expect(sshAccessRepository.delete.mock.invocationCallOrder[0]).toBeLessThan(
      sshAccessRepository.save.mock.invocationCallOrder[0],
    )
  })

  it('generates a 32-char token without CLI-hostile _ or - characters', async () => {
    const { service, sshAccessRepository, configService } = makeService()
    jest.spyOn(service, 'findOneByIdOrName').mockResolvedValue(box)
    configService.getOrThrow.mockReturnValue('gateway.example.com')

    await service.createSshAccess('box-1')

    const saved = sshAccessRepository.save.mock.calls[0][0]
    expect(saved.token).toHaveLength(32)
    expect(saved.token).not.toMatch(/[_-]/)
  })

  it('honors expiresInMinutes when computing expiresAt', async () => {
    jest.useFakeTimers().setSystemTime(new Date('2026-01-01T00:00:00.000Z'))
    try {
      const { service, sshAccessRepository, configService } = makeService()
      jest.spyOn(service, 'findOneByIdOrName').mockResolvedValue(box)
      configService.getOrThrow.mockReturnValue('gateway.example.com')

      await service.createSshAccess('box-1', 15)

      const saved = sshAccessRepository.save.mock.calls[0][0]
      expect(saved.expiresAt).toEqual(new Date('2026-01-01T00:15:00.000Z'))
    } finally {
      jest.useRealTimers()
    }
  })

  it('builds sshCommand from the region SSH gateway url', async () => {
    const { service, regionService } = makeService()
    jest.spyOn(service, 'findOneByIdOrName').mockResolvedValue(box)
    regionService.findOne.mockResolvedValue({ sshGatewayUrl: 'ssh.example.com:2222' })

    const dto = await service.createSshAccess('box-1')

    expect(regionService.findOne).toHaveBeenCalledWith('us', true)
    expect(dto.sshCommand).toBe(`ssh -p 2222 ${dto.token}@ssh.example.com`)
  })

  it('falls back to the configured gateway url when the region has none', async () => {
    const { service, configService } = makeService()
    jest.spyOn(service, 'findOneByIdOrName').mockResolvedValue(box)
    configService.getOrThrow.mockReturnValue('gateway.example.com')

    const dto = await service.createSshAccess('box-1')

    expect(configService.getOrThrow).toHaveBeenCalledWith('sshGateway.url')
    expect(dto.sshCommand).toBe(`ssh ${dto.token}@gateway.example.com`)
  })

  it('denies access to a box outside the caller organization', async () => {
    const { service, sshAccessRepository } = makeService()
    // findOneByIdOrName org-scopes its own lookup and throws NotFoundException
    // when the box exists but not within the given organizationId — the same
    // path a cross-org token grab would hit.
    jest.spyOn(service, 'findOneByIdOrName').mockRejectedValue(new NotFoundException())

    await expect(service.createSshAccess('box-1', 60, 'org-not-owning-the-box')).rejects.toThrow(
      NotFoundException,
    )
    expect(sshAccessRepository.save).not.toHaveBeenCalled()
    expect(sshAccessRepository.delete).not.toHaveBeenCalled()
  })

  it('denies access to a box that does not exist', async () => {
    const { service, sshAccessRepository } = makeService()
    jest.spyOn(service, 'findOneByIdOrName').mockRejectedValue(new NotFoundException())

    await expect(service.createSshAccess('nonexistent-box')).rejects.toThrow(NotFoundException)
    expect(sshAccessRepository.save).not.toHaveBeenCalled()
  })
})

describe('BoxService.validateSshAccess', () => {
  const futureDate = () => new Date(Date.now() + 60 * 60 * 1000)

  it('returns valid with boxId, unixUser and tokenId for a live token', async () => {
    const { service, sshAccessRepository } = makeService()
    sshAccessRepository.findOne.mockResolvedValue({
      id: 'access-1',
      boxId: 'box-1',
      token: 'live-token',
      expiresAt: futureDate(),
      box: { id: 'box-1', runnerId: null },
    })

    const result = await service.validateSshAccess('live-token')

    expect(result).toEqual({ valid: true, boxId: 'box-1', unixUser: 'root', tokenId: 'access-1' })
  })

  it('returns the same contract when the box is assigned to a runner', async () => {
    const { service, sshAccessRepository, runnerService } = makeService()
    sshAccessRepository.findOne.mockResolvedValue({
      id: 'access-1',
      boxId: 'box-1',
      token: 'live-token',
      expiresAt: futureDate(),
      box: { id: 'box-1', runnerId: 'runner-1' },
    })
    runnerService.findOne.mockResolvedValue({ id: 'runner-1' })

    const result = await service.validateSshAccess('live-token')

    expect(result).toEqual({ valid: true, boxId: 'box-1', unixUser: 'root', tokenId: 'access-1' })
  })

  it('returns invalid without unixUser/tokenId for an unknown token', async () => {
    const { service, sshAccessRepository } = makeService()
    sshAccessRepository.findOne.mockResolvedValue(null)

    const result = await service.validateSshAccess('unknown-token')

    // toStrictEqual also rejects extra keys set to undefined, so this proves
    // the invalid path leaks no session details to the gateway.
    expect(result).toStrictEqual({ valid: false, boxId: null })
  })

  it('returns invalid for an expired token', async () => {
    const { service, sshAccessRepository } = makeService()
    sshAccessRepository.findOne.mockResolvedValue({
      id: 'access-1',
      boxId: 'box-1',
      token: 'expired-token',
      expiresAt: new Date(Date.now() - 1000),
      box: { id: 'box-1', runnerId: null },
    })

    const result = await service.validateSshAccess('expired-token')

    expect(result).toStrictEqual({ valid: false, boxId: null })
  })
})

describe('BoxService.revokeSshAccess', () => {
  it('deletes the specific token when one is given', async () => {
    const { service, sshAccessRepository } = makeService()
    jest.spyOn(service, 'findOneByIdOrName').mockResolvedValue(box)

    const revokedBox = await service.revokeSshAccess('box-1', 'token-1', 'org-1')

    expect(sshAccessRepository.delete).toHaveBeenCalledWith({ boxId: 'box-1', token: 'token-1' })
    expect(revokedBox).toBe(box)
  })

  it('deletes all SSH access for the box when no token is given', async () => {
    const { service, sshAccessRepository } = makeService()
    jest.spyOn(service, 'findOneByIdOrName').mockResolvedValue(box)

    await service.revokeSshAccess('box-1')

    expect(sshAccessRepository.delete).toHaveBeenCalledWith({ boxId: 'box-1' })
  })

  it('denies revocation for a box outside the caller organization', async () => {
    const { service, sshAccessRepository } = makeService()
    jest.spyOn(service, 'findOneByIdOrName').mockRejectedValue(new NotFoundException())

    await expect(
      service.revokeSshAccess('box-1', undefined, 'org-not-owning-the-box'),
    ).rejects.toThrow(NotFoundException)
    expect(sshAccessRepository.delete).not.toHaveBeenCalled()
  })

  it('denies revocation for a box that does not exist', async () => {
    const { service, sshAccessRepository } = makeService()
    jest.spyOn(service, 'findOneByIdOrName').mockRejectedValue(new NotFoundException())

    await expect(service.revokeSshAccess('nonexistent-box')).rejects.toThrow(NotFoundException)
    expect(sshAccessRepository.delete).not.toHaveBeenCalled()
  })
})
