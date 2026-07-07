/*
 * Copyright 2025 Daytona Platforms Inc.
 * Modified by BoxLite AI, 2025-2026
 * SPDX-License-Identifier: AGPL-3.0
 */

import { ApiHideProperty, ApiProperty } from '@nestjs/swagger'
import { Transform } from 'class-transformer'
import { IsOptional, Matches } from 'class-validator'
import { SshAccess } from '../entities/ssh-access.entity'

// POSIX portable username charset (matches useradd/adduser's NAME_REGEX):
// lowercase letter or underscore, then up to 31 lowercase letters, digits,
// underscores, or hyphens. Also matches the empty string, since the
// controller treats an empty/whitespace-only unixUser as "absent" and falls
// back to a legacy exec-bridge token (see createSshAccess below) — validation
// must not reject that case.
//
// unixUser is interpolated unquoted into guest-side /etc/passwd,
// /etc/sudoers.d/$UNIX_USER, and the sshd AllowUsers config by
// boxlite-enable-ssh, so rejecting anything outside this charset here (rather
// than relying on the guest script) stops a crafted value — e.g. containing
// ':', '/', or a newline — from corrupting those files or injecting extra
// sshd config directives.
const UNIX_USERNAME_PATTERN = /^([a-z_][a-z0-9_-]{0,31})?$/
const trimIfString = ({ value }: { value: unknown }) => (typeof value === 'string' ? value.trim() : value)

export class SshAccessDto {
  @ApiProperty({
    description: 'Unique identifier for the SSH access',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  id: string

  @ApiProperty({
    description: 'ID of the box this SSH access is for',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  boxId: string

  @ApiProperty({
    description: 'SSH access token',
    example: 'abc123def456ghi789jkl012mno345pqr678stu901vwx234yz',
  })
  token: string

  @ApiProperty({
    description: 'When the SSH access expires',
    example: '2025-01-01T12:00:00.000Z',
  })
  expiresAt: Date

  @ApiProperty({
    description: 'When the SSH access was created',
    example: '2025-01-01T11:00:00.000Z',
  })
  createdAt: Date

  @ApiProperty({
    description: 'When the SSH access was last updated',
    example: '2025-01-01T11:00:00.000Z',
  })
  updatedAt: Date

  @ApiProperty({
    description: 'SSH command to connect to the box',
    example: 'ssh -p 2222 token@localhost',
  })
  sshCommand: string

  static fromSshAccess(sshAccess: SshAccess, sshGatewayUrl: string): SshAccessDto {
    const dto = new SshAccessDto()
    dto.id = sshAccess.id
    dto.boxId = sshAccess.boxId
    dto.token = sshAccess.token
    dto.expiresAt = sshAccess.expiresAt
    dto.createdAt = sshAccess.createdAt
    dto.updatedAt = sshAccess.updatedAt
    // Robustly extract host and port from sshGatewayUrl
    let host: string
    let port: string
    try {
      // If protocol is present, use URL
      if (sshGatewayUrl.includes('://')) {
        const url = new URL(sshGatewayUrl)
        host = url.hostname
        port = url.port || '22'
      } else {
        // No protocol, parse manually
        const [hostPart, portPart] = sshGatewayUrl.split(':')
        host = hostPart
        port = portPart || '22'
      }
    } catch {
      // Fallback: treat as host only
      host = sshGatewayUrl
      port = '22'
    }

    if (port === '22') {
      dto.sshCommand = `ssh ${sshAccess.token}@${host}`
    } else {
      dto.sshCommand = `ssh -p ${port} ${sshAccess.token}@${host}`
    }

    return dto
  }
}

export class SshAccessValidationDto {
  @ApiProperty({
    description: 'Whether the SSH access token is valid',
    example: true,
  })
  valid: boolean

  @ApiProperty({
    description: 'ID of the box this SSH access is for',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  boxId: string

  @ApiProperty({
    description: 'Unix user for real-SSH access; null for legacy exec-bridge tokens',
    example: 'boxlite',
    nullable: true,
    required: false,
  })
  unixUser?: string | null

  static fromValidationResult(valid: boolean, boxId: string, unixUser?: string | null): SshAccessValidationDto {
    const dto = new SshAccessValidationDto()
    dto.valid = valid
    dto.boxId = boxId
    dto.unixUser = unixUser ?? null
    return dto
  }
}

// Request body for creating SSH access. Accepts both snake_case (unix_user) and
// camelCase (unixUser) field names so callers using either naming convention work.
// The controller resolves via: body?.unixUser ?? body?.unix_user
//
// unix_user is hidden from the OpenAPI schema (ApiHideProperty) rather than
// documented alongside unixUser: both camelCase and snake_case forms PascalCase
// to the same Go identifier (UnixUser), and generating both produces a duplicate
// field declaration that fails to compile in apps/api-client-go. The runtime
// fallback below still accepts unix_user from the raw request body regardless
// of what's in the generated schema.
export class CreateSshAccessBodyDto {
  @ApiProperty({
    description: 'Unix user for SSH access (camelCase form)',
    example: 'boxlite',
    required: false,
    pattern: UNIX_USERNAME_PATTERN.source,
  })
  @IsOptional()
  @Transform(trimIfString)
  @Matches(UNIX_USERNAME_PATTERN, { message: 'unixUser must be a valid POSIX username' })
  unixUser?: string

  @ApiHideProperty()
  @IsOptional()
  @Transform(trimIfString)
  @Matches(UNIX_USERNAME_PATTERN, { message: 'unix_user must be a valid POSIX username' })
  // eslint-disable-next-line @typescript-eslint/naming-convention
  unix_user?: string
}

export class RevokeSshAccessDto {
  @ApiProperty({
    description: 'ID of the box',
    example: '123e4567-e89b-12d3-a456-426614174000',
  })
  boxId: string

  @ApiProperty({
    description: 'SSH access token to revoke',
    example: 'abc123def456ghi789jkl012mno345pqr678stu901vwx234yz',
  })
  token: string
}
