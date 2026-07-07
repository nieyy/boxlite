/*
 * Copyright 2025 BoxLite AI
 * SPDX-License-Identifier: AGPL-3.0
 */

import 'reflect-metadata'
import { validate } from 'class-validator'
import { plainToInstance } from 'class-transformer'
import { CreateSshAccessBodyDto } from './ssh-access.dto'

// unixUser/unix_user are interpolated unquoted into guest-side /etc/passwd,
// /etc/sudoers.d/$UNIX_USER, and the sshd AllowUsers config by
// boxlite-enable-ssh. A value outside the POSIX username charset (e.g.
// containing '/', ':', or a newline) can corrupt those files or inject extra
// sshd config directives, so the DTO must reject it at the request boundary
// (the global ValidationPipe in main.ts turns constraint violations into
// HTTP 400s; that wiring is verified live, not here).
describe('CreateSshAccessBodyDto unix username validation', () => {
  it.each([
    ['a newline-smuggled sshd directive', 'alice\nPermitRootLogin yes\n#'],
    ['a path separator', 'root/../etc'],
    ['a sudoers-filename colon', 'alice:x:0:0'],
    ['an uppercase username', 'Boxlite'],
    ['a leading digit', '1boxlite'],
    ['a 33-character username', 'a'.repeat(33)],
  ])('rejects unixUser containing %s', async (_desc, value) => {
    const errors = await validate(plainToInstance(CreateSshAccessBodyDto, { unixUser: value }))

    const fieldError = errors.find((e) => e.property === 'unixUser')
    expect(fieldError?.constraints).toHaveProperty('matches')
  })

  it.each([
    ['boxlite', 'boxlite'],
    ['root', 'root'],
    ['a 32-character username', 'a'.repeat(32)],
    ['underscores and hyphens', 'my_user-1'],
  ])('accepts a valid %s unixUser', async (_desc, value) => {
    const errors = await validate(plainToInstance(CreateSshAccessBodyDto, { unixUser: value }))

    expect(errors).toHaveLength(0)
  })

  it('accepts an omitted unixUser', async () => {
    const errors = await validate(plainToInstance(CreateSshAccessBodyDto, {}))

    expect(errors).toHaveLength(0)
  })

  it('accepts and trims a whitespace-padded unixUser, matching the controller normalization contract', async () => {
    const instance = plainToInstance(CreateSshAccessBodyDto, { unixUser: '  boxlite  ' })
    const errors = await validate(instance)

    expect(errors).toHaveLength(0)
    expect(instance.unixUser).toBe('boxlite')
  })

  it('accepts an empty-string unixUser, since the controller treats it as absent', async () => {
    const errors = await validate(plainToInstance(CreateSshAccessBodyDto, { unixUser: '' }))

    expect(errors).toHaveLength(0)
  })

  it('accepts a whitespace-only unixUser, since it trims to empty (treated as absent)', async () => {
    const errors = await validate(plainToInstance(CreateSshAccessBodyDto, { unixUser: '   ' }))

    expect(errors).toHaveLength(0)
  })

  it('rejects a malicious unix_user (snake_case form) the same way as unixUser', async () => {
    // eslint-disable-next-line @typescript-eslint/naming-convention
    const errors = await validate(plainToInstance(CreateSshAccessBodyDto, { unix_user: 'alice\n#' }))

    const fieldError = errors.find((e) => e.property === 'unix_user')
    expect(fieldError?.constraints).toHaveProperty('matches')
  })
})
