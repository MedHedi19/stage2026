import { IsIP, IsString, IsNotEmpty, MaxLength } from 'class-validator';

export class AddIpDto {
  @IsIP()
  ip: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  reason: string;
}
