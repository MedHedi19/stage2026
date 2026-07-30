import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn } from 'typeorm';

export enum BlockSource {
  AUTO = 'auto',
  MANUAL = 'manual',
}

@Entity('blacklist_entries')
export class BlacklistEntry {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  ip: string;

  @Column({ nullable: true })
  reason: string;

  @Column({
    type: 'enum',
    enum: BlockSource,
    default: BlockSource.MANUAL,
  })
  source: BlockSource;

  @Column({ nullable: true })
  addedBy: string;

  @CreateDateColumn()
  createdAt: Date;

  @Column({ default: true })
  active: boolean;
}
