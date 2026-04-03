import { Router } from 'express';
import { requireAuth, requirePermission } from '../middleware/auth';
import prisma from '../db';

const router = Router();

router.get('/jobs', requireAuth, requirePermission('projects:read'), async (req: any, res) => {
  const jobs = await prisma.asyncJob.findMany({
    where: req.roles?.includes('owner') ? {} : { createdByUserId: req.userId },
    orderBy: { createdAt: 'desc' },
    take: 50
  });
  res.json({ success: true, jobs });
});

router.get('/jobs/:job_id', requireAuth, requirePermission('projects:read'), async (req: any, res) => {
  const job = await prisma.asyncJob.findUnique({ where: { id: req.params.job_id } });
  if (!job) return res.status(404).json({ success: false, msg: "Job não encontrado" });
  if (!req.roles?.includes('owner') && job.createdByUserId !== req.userId) {
    return res.status(403).json({ success: false, msg: "Permissões insuficientes" });
  }
  res.json({ success: true, job });
});

export default router;
