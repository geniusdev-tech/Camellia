import { Injectable } from '@nestjs/common';
import { QueueService } from '../queue/queue.service';
import { PrismaService } from '../../prisma/prisma.service';
import { CreateReleaseInput } from './release.schemas';

@Injectable()
export class ReleasesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly queueService: QueueService,
  ) {}

  async createRelease(payload: CreateReleaseInput) {
    const release = await this.prisma.release.create({
      data: {
        packageName: payload.packageName,
        packageVersion: payload.packageVersion,
        releaseChannel: payload.releaseChannel,
        deploymentEnv: payload.deploymentEnv,
        maxCvss: payload.maxCvss,
        complianceScore: payload.complianceScore,
        riskScore: payload.riskScore,
        metadataJson: payload.metadata ? JSON.stringify(payload.metadata) : null,
      },
    });

    await this.queueService.enqueueScan(release.id);

    return release;
  }

  async listReleases() {
    return this.prisma.release.findMany({
      orderBy: { createdAt: 'desc' },
      take: 200,
    });
  }

  async enqueuePublish(releaseId: string) {
    await this.queueService.enqueuePublish(releaseId);
    return { enqueued: true, job: 'publish-release', releaseId };
  }

  async enqueueRollback(releaseId: string, targetReleaseId: string) {
    await this.queueService.enqueueRollback(releaseId, targetReleaseId);
    return { enqueued: true, job: 'rollback-release', releaseId, targetReleaseId };
  }
}
