import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

@Entity()
export class ConversationLog {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  userId: number;

  @Column({ nullable: true })
  alertId: string;

  @Column('text')
  userMessage: string;

  @Column('text')
  aiReply: string;

  @Column()
  conversationId: string;

  @CreateDateColumn()
  createdAt: Date;
}
