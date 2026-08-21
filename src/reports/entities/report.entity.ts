import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from '../../users/entities/user.entity';
import { ReportType } from '../report-types.enum';

@Entity('reports')
export class Report {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ nullable: true })
  userId: number;

  @Column({ nullable: true })
  username: string;

  @CreateDateColumn()
  createdAt: Date;

  @Column()
  format: string;

  @Column({
    type: 'enum',
    enum: ReportType,
    default: ReportType.EXECUTIVE_SUMMARY,
  })
  reportType: ReportType = ReportType.EXECUTIVE_SUMMARY;

  @Column({ type: 'text', nullable: true })
  filters: string;

  @ManyToOne(() => User, { onDelete: 'SET NULL', nullable: true })
  @JoinColumn({ name: 'userId' })
  user: User;
}
