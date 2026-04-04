import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { SocialController } from './social.controller';
import { SocialService } from './social.service';

@Module({
  imports: [AuthModule],
  controllers: [SocialController],
  providers: [SocialService],
  exports: [SocialService],
})
export class SocialModule {}
