/*
 * Copyright 2025 BoxLite AI
 * SPDX-License-Identifier: AGPL-3.0
 */

import { MigrationInterface, QueryRunner } from 'typeorm'

/**
 * Add unixUser column to ssh_access table.
 *
 * Stores the unix account that was configured on the runner when the token was
 * issued. Used by the save-failure rollback in createSshAccess to detect
 * whether the unix_user changed between the prior token and the new request:
 * if it changed, the runner is now configured for the new user while old DB
 * tokens still reference the old user, so runner SSH must be disabled rather
 * than left enabled (Finding [high], Round 51).
 *
 * Nullable with no default: existing rows left as NULL, which application
 * logic treats as a legacy exec-bridge token (no runner-side SSH state)
 * rather than a real-SSH token for a specific unix user.
 */
export class Migration1778751201300 implements MigrationInterface {
  name = 'Migration1778751201300'

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "ssh_access" ADD COLUMN IF NOT EXISTS "unixUser" text NULL`)
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`ALTER TABLE "ssh_access" DROP COLUMN IF EXISTS "unixUser"`)
  }
}
