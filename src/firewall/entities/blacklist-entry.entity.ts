import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn } from 'typeorm';

export enum BlockSource {
  AUTO = 'auto',
  MANUAL = 'manual',
}

@Entity('blacklist_entries')
export class BlacklistEntry {
  @PrimaryGeneratedColumn()
  id!: number;

  @Column({ unique: true })
  ip!: string;

  @Column({ nullable: true })
  reason!: string;

  @Column({
    type: 'enum',
    enum: BlockSource,
    default: BlockSource.MANUAL,
  })
  source!: BlockSource;

  @Column({ nullable: true })
  addedBy!: string;

  @CreateDateColumn()
  createdAt!: Date;

  @Column({ default: true })
  active!: boolean;

  @Column({ nullable: true, type: 'int' })
  abuseScore: number | null = null;

  @Column({ nullable: true, type: 'varchar', length: 255 })
  abuseCategories: string | null = null;

  @Column({ nullable: true, type: 'varchar', length: 10 })
  countryCode: string | null = null;
}
