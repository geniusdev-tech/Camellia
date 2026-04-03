import { Router, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import crypto from 'crypto';
import prisma from '../db';
import { AuthRequest, requireAuth, requirePermission } from '../middleware/auth';

const router = Router();

const utcNow = () => new Date().toISOString();

const isTeamManager = async (teamId: string, userId: number): Promise<boolean> => {
  const team = await prisma.team.findUnique({ where: { id: teamId } });
  if (!team) return false;
  if (team.ownerUserId === userId) return true;

  const membership = await prisma.teamMember.findFirst({
    where: { teamId, userId }
  });
  return !!(membership && (membership.role === 'manager' || membership.role === 'owner'));
};

const serializeTeam = async (team: any) => {
  const members = await prisma.teamMember.findMany({ where: { teamId: team.id } });
  return {
    id: team.id,
    name: team.name,
    owner_user_id: team.ownerUserId,
    created_at: team.createdAt,
    members: members.map(m => ({
      user_id: m.userId,
      role: m.role,
      created_at: m.createdAt,
    })),
  };
};

router.get('/teams', requireAuth, requirePermission('projects:read'), async (req: AuthRequest, res) => {
  const userId = req.userId!;
  const memberships = await prisma.teamMember.findMany({ where: { userId } });
  const teamIds = memberships.map(m => m.teamId);

  const teams = await prisma.team.findMany({
    where: {
      OR: [
        { ownerUserId: userId },
        { id: { in: teamIds } }
      ]
    },
    orderBy: { createdAt: 'asc' }
  });

  const serializedTeams = await Promise.all(teams.map(t => serializeTeam(t)));
  res.json({ success: true, teams: serializedTeams });
});

router.post('/teams', requireAuth, requirePermission('projects:write'), async (req: AuthRequest, res) => {
  const userId = req.userId!;
  const { name } = req.body;
  if (!name || name.trim().length < 3) return res.status(400).json({ success: false, msg: "Nome do time inválido" });

  const existing = await prisma.team.findUnique({ where: { name } });
  if (existing) return res.status(409).json({ success: false, msg: "Time já existe" });

  const team = await prisma.team.create({
    data: {
      name: name.trim(),
      ownerUserId: userId,
      createdAt: utcNow(),
      members: {
        create: {
          userId,
          role: 'owner',
          createdAt: utcNow(),
        }
      }
    }
  });

  res.json({ success: true, team: await serializeTeam(team) });
});

// Other routes (invites, accept, project-team-grants) would follow...

export default router;
