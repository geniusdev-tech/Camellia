import { Router, Request, Response } from 'express';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import * as otplib from 'otplib';
import { v4 as uuidv4 } from 'uuid';
import prisma from '../db';
import { authenticator } from 'otplib';
import QRCode from 'qrcode';

const router = Router();
const SECRET_KEY = process.env.SECRET_KEY || 'dev-secret-key';

const utcNow = () => new Date().toISOString();

const passwordError = (password: string): string | null => {
  if (password.length < 12) return "Senha deve ter pelo menos 12 caracteres";
  if (!/[A-Z]/.test(password)) return "Senha deve conter ao menos uma letra maiúscula";
  if (!/[a-z]/.test(password)) return "Senha deve conter ao menos uma letra minúscula";
  if (!/[0-9]/.test(password)) return "Senha deve conter ao menos um número";
  if (!/[^A-Za-z0-9]/.test(password)) return "Senha deve conter ao menos um caractere especial";
  return null;
};

router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success: false, msg: "Email e senha obrigatórios" });

  const error = passwordError(password);
  if (error) return res.status(400).json({ success: false, msg: error });

  const existing = await prisma.user.findUnique({ where: { username: email } });
  if (existing) return res.status(409).json({ success: false, msg: "Email já cadastrado" });

  const userRole = await prisma.role.findUnique({ where: { name: 'user' } });
  const hashedPassword = await argon2.hash(password);

  await prisma.user.create({
    data: {
      username: email,
      passwordHash: hashedPassword,
      roleId: userRole?.id,
      isActive: true,
    }
  });

  res.json({ success: true, msg: "Conta criada com sucesso" });
});

router.post('/login', async (req, res) => {
  const { email, username, password } = req.body;
  const identifier = (email || username || "").trim();
  if (!identifier || !password) return res.status(400).json({ success: false, msg: "Credenciais obrigatórias" });

  const user = await prisma.user.findUnique({ where: { username: identifier }, include: { role: true } });
  if (!user || !(await argon2.verify(user.passwordHash, password))) {
    return res.status(401).json({ success: false, msg: "Credenciais inválidas" });
  }

  if (!user.isActive) return res.status(403).json({ success: false, msg: "Conta desativada" });

  if (user.mfaSecretEnc) {
    // In a real app, use a secure session or a temporary token for MFA step
    return res.json({ success: false, requires_mfa: true, user_id: user.id, msg: "MFA necessário" });
  }

  const roleName = user.role?.name || 'user';
  const accessToken = jwt.sign({ sub: user.id, roles: [roleName], type: 'access' }, SECRET_KEY, { expiresIn: '15m', jwtid: uuidv4() });
  const refreshToken = jwt.sign({ sub: user.id, type: 'refresh' }, SECRET_KEY, { expiresIn: '7d', jwtid: uuidv4() });

  const refreshPayload = jwt.decode(refreshToken) as any;
  await prisma.refreshTokenSession.create({
    data: {
      userId: user.id,
      tokenJti: refreshPayload.jti,
      issuedAt: utcNow(),
      expiresAt: new Date(refreshPayload.exp * 1000).toISOString(),
      userAgent: req.header('User-Agent'),
      ipAddress: req.ip,
    }
  });

  res.json({
    success: true,
    access_token: accessToken,
    refresh_token: refreshToken,
    email: user.username,
    has_2fa: !!user.mfaSecretEnc,
    role: roleName,
  });
});

router.post('/login/mfa', async (req, res) => {
  const { code, user_id } = req.body;
  if (!user_id || !code) return res.status(401).json({ success: false, msg: "Sessão inválida" });

  const user = await prisma.user.findUnique({ where: { id: user_id }, include: { role: true } });
  if (!user || !user.mfaSecretEnc) return res.status(400).json({ success: false, msg: "Erro na validação MFA" });

  const isValid = authenticator.verify({ token: code, secret: user.mfaSecretEnc });
  if (!isValid) return res.status(401).json({ success: false, msg: "Código MFA inválido" });

  const roleName = user.role?.name || 'user';
  const accessToken = jwt.sign({ sub: user.id, roles: [roleName], type: 'access' }, SECRET_KEY, { expiresIn: '15m', jwtid: uuidv4() });
  const refreshToken = jwt.sign({ sub: user.id, type: 'refresh' }, SECRET_KEY, { expiresIn: '7d', jwtid: uuidv4() });

  const refreshPayload = jwt.decode(refreshToken) as any;
  await prisma.refreshTokenSession.create({
    data: {
      userId: user.id,
      tokenJti: refreshPayload.jti,
      issuedAt: utcNow(),
      expiresAt: new Date(refreshPayload.exp * 1000).toISOString(),
      userAgent: req.header('User-Agent'),
      ipAddress: req.ip,
    }
  });

  res.json({
    success: true,
    access_token: accessToken,
    refresh_token: refreshToken,
    email: user.username,
    has_2fa: true,
    role: roleName,
  });
});

router.post('/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ success: false, msg: "Token obrigatório" });

  try {
    const payload = jwt.verify(refresh_token, SECRET_KEY) as any;
    if (payload.type !== 'refresh' || !payload.jti) return res.status(401).json({ success: false, msg: "Token inválido" });

    const user = await prisma.user.findUnique({ where: { id: payload.sub }, include: { role: true } });
    if (!user || !user.isActive) return res.status(401).json({ success: false, msg: "Usuário inválido" });

    const session = await prisma.refreshTokenSession.findUnique({ where: { tokenJti: payload.jti } });
    if (!session || session.revokedAt) return res.status(401).json({ success: false, msg: "Refresh token revogado" });

    const roleName = user.role?.name || 'user';
    const newAccessToken = jwt.sign({ sub: user.id, roles: [roleName], type: 'access' }, SECRET_KEY, { expiresIn: '15m', jwtid: uuidv4() });
    const newRefreshToken = jwt.sign({ sub: user.id, type: 'refresh' }, SECRET_KEY, { expiresIn: '7d', jwtid: uuidv4() });

    const newRefreshPayload = jwt.decode(newRefreshToken) as any;

    await prisma.$transaction([
      prisma.refreshTokenSession.create({
        data: {
          userId: user.id,
          tokenJti: newRefreshPayload.jti,
          issuedAt: utcNow(),
          expiresAt: new Date(newRefreshPayload.exp * 1000).toISOString(),
          userAgent: req.header('User-Agent'),
          ipAddress: req.ip,
        }
      }),
      prisma.refreshTokenSession.update({
        where: { tokenJti: payload.jti },
        data: {
          revokedAt: utcNow(),
          replacedByJti: newRefreshPayload.jti,
        }
      })
    ]);

    res.json({
      success: true,
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
    });
  } catch (err) {
    return res.status(401).json({ success: false, msg: "Token inválido ou expirado" });
  }
});

import { requireAuth } from '../middleware/auth';

router.get('/status', requireAuth, async (req: any, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.userId }, include: { role: true } });
  if (!user) return res.status(404).json({ success: false, msg: "Usuário não encontrado" });

  res.json({
    success: true,
    user_id: user.id,
    email: user.username,
    has_2fa: !!user.mfaSecretEnc,
    role: user.role?.name || 'user',
  });
});

router.post('/logout', async (req, res) => {
  const { refresh_token } = req.body;
  if (refresh_token) {
    try {
      const payload = jwt.decode(refresh_token) as any;
      if (payload && payload.type === 'refresh' && payload.jti) {
        await prisma.refreshTokenSession.updateMany({
          where: { tokenJti: payload.jti },
          data: { revokedAt: utcNow() }
        });
      }
    } catch (e) {}
  }
  res.json({ success: true, msg: "Sessão encerrada" });
});

router.post('/mfa/setup', requireAuth, async (req: any, res) => {
  const user = await prisma.user.findUnique({ where: { id: req.userId } });
  if (!user) return res.status(404).json({ success: false, msg: "Usuário não encontrado" });

  const secret = authenticator.generateSecret();
  const otpauth = authenticator.keyuri(user.username, 'GateStack', secret);
  const qrCode = await QRCode.toDataURL(otpauth);

  await prisma.user.update({
    where: { id: user.id },
    data: { mfaSecretEnc: secret }
  });

  res.json({ success: true, secret, qr_code: qrCode });
});

export default router;
