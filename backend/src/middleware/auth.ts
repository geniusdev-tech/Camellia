import { Router, Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import prisma from '../db';

const SECRET_KEY = process.env.SECRET_KEY || 'dev-secret-key';

export interface AuthRequest extends Request {
  userId?: number;
  roles?: string[];
}

export const requireAuth = async (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, msg: 'Token não fornecido' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, SECRET_KEY) as any;
    if (payload.type !== 'access') {
      return res.status(401).json({ success: false, msg: 'Tipo de token inválido' });
    }
    req.userId = payload.sub;
    req.roles = payload.roles;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, msg: 'Token inválido ou expirado' });
  }
};

const ROLE_PERMISSIONS: Record<string, string[]> = {
  owner: [
    'projects:read',
    'projects:write',
    'projects:read_all',
    'projects:approve',
    'projects:share',
    'audit:read',
  ],
  user: [
    'projects:read',
    'projects:write',
  ],
};

export const requirePermission = (permission: string) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    const roles = req.roles || ['user'];
    const hasPermission = roles.some(role => ROLE_PERMISSIONS[role]?.includes(permission));
    if (!hasPermission) {
      return res.status(403).json({ success: false, msg: 'Permissões insuficientes' });
    }
    next();
  };
};
