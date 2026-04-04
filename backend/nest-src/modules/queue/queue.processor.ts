import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { PinoLogger } from 'nestjs-pino';
import { PrismaService } from '../../prisma/prisma.service';
import { parseEnv } from '../../common/config/env.schema';
import { QueueService } from './queue.service';

@Processor('release-jobs')
export class QueueProcessor extends WorkerHost {
  private readonly env = parseEnv(process.env);

  constructor(
    private readonly logger: PinoLogger,
    private readonly prisma: PrismaService,
    private readonly queueService: QueueService,
  ) {
    super();
  }

  async process(job: Job<{ releaseId: string; targetReleaseId?: string }>): Promise<void> {
    this.logger.info({ jobId: job.id, payload: job.data, name: job.name }, 'Queue job received');

    try {
      if (job.name === 'scan-release') {
        await this.handleScan(job.data.releaseId);
        return;
      }

      if (job.name === 'publish-release') {
        await this.handlePublish(job.data.releaseId);
        return;
      }

      if (job.name === 'rollback-release') {
        if (!job.data.targetReleaseId) throw new Error('targetReleaseId is required');
        await this.handleRollback(job.data.releaseId, job.data.targetReleaseId);
        return;
      }

      if (job.name === 'release-dlq') return;

      throw new Error(`Unknown job: ${job.name}`);
    } catch (error) {
      await this.queueService.enqueueDeadLetter(
        job.name,
        { ...job.data },
        error instanceof Error ? error.message : String(error),
      );
      throw error;
    }
  }

  private async handleScan(releaseId: string): Promise<void> {
    const release = await this.prisma.release.findUnique({ where: { id: releaseId } });
    if (!release) throw new Error('Release not found');

    const policyApproved = release.maxCvss < this.env.PUBLISH_MAX_CVSS;
    const adjustedCompliance = Math.max(0, Math.min(100, release.complianceScore + (policyApproved ? 10 : -20)));
    const adjustedRisk = Math.max(0, Math.min(100, release.riskScore + (policyApproved ? -10 : 20)));

    await this.prisma.release.update({
      where: { id: releaseId },
      data: {
        policyApproved,
        complianceScore: adjustedCompliance,
        riskScore: adjustedRisk,
        status: policyApproved && release.status === 'draft' ? 'approved' : release.status,
      },
    });
  }

  private async handlePublish(releaseId: string): Promise<void> {
    const release = await this.prisma.release.findUnique({ where: { id: releaseId } });
    if (!release) throw new Error('Release not found');
    if (!release.policyApproved) throw new Error('Release blocked by policy');
    if (!['approved', 'archived'].includes(release.status)) throw new Error(`Invalid status transition to published from ${release.status}`);

    await this.prisma.$transaction(async (tx) => {
      await tx.release.updateMany({
        where: {
          packageName: release.packageName,
          status: 'published',
          id: { not: release.id },
        },
        data: { status: 'archived' },
      });

      await tx.release.update({
        where: { id: release.id },
        data: { status: 'published', rollbackOfId: null },
      });
    });
  }

  private async handleRollback(currentReleaseId: string, targetReleaseId: string): Promise<void> {
    const current = await this.prisma.release.findUnique({ where: { id: currentReleaseId } });
    const target = await this.prisma.release.findUnique({ where: { id: targetReleaseId } });

    if (!current || !target) throw new Error('Rollback releases not found');
    if (current.packageName !== target.packageName) throw new Error('Rollback target must be from same package');
    if (current.status !== 'published') throw new Error('Current release must be published');
    if (target.status !== 'archived') throw new Error('Target release must be archived');

    await this.prisma.$transaction(async (tx) => {
      await tx.release.update({
        where: { id: current.id },
        data: { status: 'archived' },
      });
      await tx.release.update({
        where: { id: target.id },
        data: { status: 'published', rollbackOfId: current.id },
      });
    });
  }
}
