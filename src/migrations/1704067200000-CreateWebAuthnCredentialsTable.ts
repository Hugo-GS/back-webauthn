import { MigrationInterface, QueryRunner, Table, TableForeignKey } from 'typeorm';

export class CreateWebAuthnCredentialsTable1704067200000 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.createTable(
      new Table({
        name: 'webauthn_credentials',
        columns: [
          {
            name: 'id',
            type: 'integer',
            isPrimary: true,
            isGenerated: true,
            generationStrategy: 'increment',
          },
          {
            name: 'credentialID',
            type: 'varchar',
            isUnique: true,
          },
          {
            name: 'credentialPublicKey',
            type: 'text',
          },
          {
            name: 'counter',
            type: 'integer',
            default: 0,
          },
          {
            name: 'credentialDeviceType',
            type: 'varchar',
          },
          {
            name: 'credentialBackedUp',
            type: 'boolean',
            default: false,
          },
          {
            name: 'transports',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'deviceName',
            type: 'text',
            isNullable: true,
          },
          {
            name: 'createdAt',
            type: 'datetime',
            default: 'CURRENT_TIMESTAMP',
          },
          {
            name: 'lastUsed',
            type: 'datetime',
            default: 'CURRENT_TIMESTAMP',
          },
          {
            name: 'userId',
            type: 'integer',
          },
        ],
      }),
      true,
    );

    // Create foreign key constraint to User entity
    await queryRunner.createForeignKey(
      'webauthn_credentials',
      new TableForeignKey({
        columnNames: ['userId'],
        referencedColumnNames: ['id'],
        referencedTableName: 'user',
        onDelete: 'CASCADE',
      }),
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop foreign key first
    const table = await queryRunner.getTable('webauthn_credentials');
    if (table) {
      const foreignKey = table.foreignKeys.find(fk => fk.columnNames.indexOf('userId') !== -1);
      if (foreignKey) {
        await queryRunner.dropForeignKey('webauthn_credentials', foreignKey);
      }
    }

    // Drop the table
    await queryRunner.dropTable('webauthn_credentials');
  }
}