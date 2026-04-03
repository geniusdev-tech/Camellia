import { Router, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import multer from 'multer';
import crypto from 'crypto';
import prisma from '../db';
import { AuthRequest, requireAuth, requirePermission } from '../middleware/auth';
import { uploadFileToSupabase } from '../utils/supabase';

const router = Router();
const upload = multer({ limits: { fileSize: 25 * 1024 * 1024 } }); // 25MB

const utcNow = () => new Date().toISOString();

router.post('/upload', requireAuth, requirePermission('projects:write'), upload.single('file'), async (req: AuthRequest, res) => {
  const file = req.file;
  if (!file) return res.status(400).json({ success: false, msg: "Arquivo obrigatório" });

  const { package_name, package_version, description, changelog, visibility, metadata } = req.body;
  const userId = req.userId!;
  const bucket = process.env.SUPABASE_BUCKET || 'projects';

  const checksum = crypto.createHash('sha256').update(file.buffer).digest('hex');
  const storageKey = `projects/${userId}/${package_name}/${package_version}/${uuidv4()}-${file.originalname}`;

  try {
    await uploadFileToSupabase(bucket, storageKey, file.buffer, file.mimetype);

    const project = await prisma.projectUpload.create({
      data: {
        userId,
        packageName: package_name || 'default-package',
        packageVersion: package_version || '1.0.0',
        filename: file.originalname,
        description,
        changelog,
        contentType: file.mimetype,
        sizeBytes: file.size,
        checksumSha256: checksum,
        storageKey,
        bucket,
        visibility: visibility || 'private',
        lifecycleStatus: 'draft',
        createdAt: utcNow(),
      }
    });

    res.json({ success: true, project });
  } catch (error: any) {
    res.status(500).json({ success: false, msg: error.message });
  }
});

router.get('/:project_id', requireAuth, requirePermission('projects:read'), async (req: AuthRequest, res) => {
  const { project_id } = req.params;
  const project = await prisma.projectUpload.findUnique({
    where: { id: project_id },
    include: { shareGrants: true, teamGrants: true }
  });

  if (!project) return res.status(404).json({ success: false, msg: "Projeto não encontrado" });

  // Basic access check
  if (project.userId !== req.userId && project.visibility !== 'public') {
     // Check grants (simplified)
     const hasGrant = project.shareGrants.some(g => g.granteeUserId === req.userId);
     if (!hasGrant) return res.status(403).json({ success: false, msg: "Permissões insuficientes" });
  }

  res.json({ success: true, project });
});

router.patch('/:project_id', requireAuth, requirePermission('projects:write'), async (req: AuthRequest, res) => {
  const { project_id } = req.params;
  const { lifecycle_status, description, visibility } = req.body;

  const project = await prisma.projectUpload.findUnique({ where: { id: project_id } });
  if (!project) return res.status(404).json({ success: false, msg: "Projeto não encontrado" });
  if (project.userId !== req.userId && !req.roles?.includes('owner')) {
    return res.status(403).json({ success: false, msg: "Permissões insuficientes" });
  }

  const updated = await prisma.projectUpload.update({
    where: { id: project_id },
    data: {
      lifecycleStatus: lifecycle_status || project.lifecycleStatus,
      description: description !== undefined ? description : project.description,
      visibility: visibility || project.visibility,
    }
  });

  res.json({ success: true, project: updated });
});

router.delete('/:project_id', requireAuth, requirePermission('projects:write'), async (req: AuthRequest, res) => {
  const { project_id } = req.params;
  const project = await prisma.projectUpload.findUnique({ where: { id: project_id } });
  if (!project) return res.status(404).json({ success: false, msg: "Projeto não encontrado" });
  if (project.userId !== req.userId && !req.roles?.includes('owner')) {
    return res.status(403).json({ success: false, msg: "Permissões insuficientes" });
  }

  await prisma.projectUpload.delete({ where: { id: project_id } });
  res.json({ success: true, msg: "Projeto removido" });
});

router.get('/list', requireAuth, requirePermission('projects:read'), async (req: AuthRequest, res) => {
  const userId = req.userId!;
  const projects = await prisma.projectUpload.findMany({
    where: {
      OR: [
        { userId },
        { visibility: 'public', lifecycleStatus: { in: ['published', 'archived'] } }
      ]
    },
    orderBy: { createdAt: 'desc' }
  });
  res.json({ success: true, projects });
});

export default router;
