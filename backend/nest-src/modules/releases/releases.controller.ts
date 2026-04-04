import { Body, Controller, Get, Param, Post, UseGuards, UsePipes } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { ZodValidationPipe } from '../../common/pipes/zod-validation.pipe';
import {
  createReleaseSchema,
  type CreateReleaseInput,
  releaseIdParamSchema,
  rollbackSchema,
  type RollbackInput,
  type ReleaseIdParam,
} from './release.schemas';
import { ReleasesService } from './releases.service';

@Controller('api/releases')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ReleasesController {
  constructor(private readonly releasesService: ReleasesService) {}

  @Post()
  @Roles('admin', 'writer')
  @UsePipes(new ZodValidationPipe(createReleaseSchema))
  async create(@Body() body: CreateReleaseInput) {
    const release = await this.releasesService.createRelease(body);
    return { success: true, release };
  }

  @Get()
  @Roles('admin', 'writer', 'reader')
  async list() {
    const releases = await this.releasesService.listReleases();
    return { success: true, releases };
  }

  @Post(':releaseId/publish')
  @Roles('admin')
  async publish(@Param(new ZodValidationPipe(releaseIdParamSchema)) params: ReleaseIdParam) {
    const payload = await this.releasesService.enqueuePublish(params.releaseId);
    return { success: true, ...payload };
  }

  @Post(':releaseId/rollback')
  @Roles('admin')
  async rollback(
    @Param(new ZodValidationPipe(releaseIdParamSchema)) params: ReleaseIdParam,
    @Body(new ZodValidationPipe(rollbackSchema)) body: RollbackInput,
  ) {
    const payload = await this.releasesService.enqueueRollback(params.releaseId, body.targetReleaseId);
    return { success: true, ...payload };
  }
}
