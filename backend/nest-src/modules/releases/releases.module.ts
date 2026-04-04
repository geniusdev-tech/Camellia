import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module';
import { ReleasesController } from './releases.controller';
import { ReleasesService } from './releases.service';
import { QueueModule } from '../queue/queue.module';

@Module({
  imports: [QueueModule, AuthModule],
  controllers: [ReleasesController],
  providers: [ReleasesService],
})
export class ReleasesModule {}
