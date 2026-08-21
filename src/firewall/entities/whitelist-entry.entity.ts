import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
} from 'typeorm';

@Entity('whitelist_entries')
export class WhitelistEntry {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ unique: true })
  ip: string;

  @Column({ nullable: true })
  reason: string;

  @Column()
  addedBy: string;

  @CreateDateColumn()
  createdAt: Date;
}
