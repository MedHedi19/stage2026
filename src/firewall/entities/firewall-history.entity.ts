import { Entity, Column, PrimaryGeneratedColumn, CreateDateColumn } from 'typeorm';

export enum FirewallListType {
  BLACKLIST = 'blacklist',
  WHITELIST = 'whitelist',
}

export enum FirewallAction {
  ADD = 'add',
  REMOVE = 'remove',
  PURGE = 'purge',
}

@Entity('firewall_history')
export class FirewallHistory {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({
    type: 'enum',
    enum: FirewallListType,
  })
  listType: FirewallListType;

  @Column({
    type: 'enum',
    enum: FirewallAction,
  })
  action: FirewallAction;

  @Column()
  ip: string;

  @Column({ nullable: true })
  reason: string;

  /** 'system' for auto-blocks, actual username otherwise */
  @Column({ default: 'system' })
  performedBy: string;

  @CreateDateColumn()
  createdAt: Date;
}
