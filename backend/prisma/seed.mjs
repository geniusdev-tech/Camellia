import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();

const seeds = [
  {
    packageName: 'gate-cli',
    packageVersion: '1.0.0',
    releaseChannel: 'stable',
    deploymentEnv: 'prod',
    status: 'published',
    maxCvss: 0,
    complianceScore: 98,
    riskScore: 8,
    policyApproved: true,
    metadataJson: JSON.stringify({ source: 'seed', team: 'platform' }),
  },
  {
    packageName: 'gate-sdk',
    packageVersion: '1.1.0-beta.1',
    releaseChannel: 'beta',
    deploymentEnv: 'staging',
    status: 'approved',
    maxCvss: 3.1,
    complianceScore: 86,
    riskScore: 24,
    policyApproved: true,
    metadataJson: JSON.stringify({ source: 'seed', team: 'appsec' }),
  },
];

const communitySeeds = [
  {
    slug: 'security-watch',
    name: 'Security Watch',
    description: 'Triagem contínua de segurança e compliance.',
  },
  {
    slug: 'release-ops',
    name: 'Release Ops',
    description: 'Publicação, rollback e estabilidade operacional.',
  },
  {
    slug: 'team-hub',
    name: 'Team Hub',
    description: 'Colaboração entre times e governança de acesso.',
  },
];

async function main() {
  const adminEmail = String(process.env.ADMIN_EMAIL || 'admin@gatestack.local').toLowerCase();
  const adminPassword = String(process.env.ADMIN_PASSWORD || 'ChangeMeNow_12345');
  const adminHash = await bcrypt.hash(adminPassword, 12);

  await prisma.user.upsert({
    where: { email: adminEmail },
    update: { passwordHash: adminHash, role: 'admin' },
    create: { email: adminEmail, passwordHash: adminHash, role: 'admin' },
  });

  await prisma.user.upsert({
    where: { email: 'writer@gatestack.local' },
    update: { role: 'writer' },
    create: { email: 'writer@gatestack.local', passwordHash: adminHash, role: 'writer' },
  });

  await prisma.user.upsert({
    where: { email: 'reader@gatestack.local' },
    update: { role: 'reader' },
    create: { email: 'reader@gatestack.local', passwordHash: adminHash, role: 'reader' },
  });

  for (const item of seeds) {
    await prisma.release.upsert({
      where: {
        packageName_packageVersion: {
          packageName: item.packageName,
          packageVersion: item.packageVersion,
        },
      },
      update: item,
      create: item,
    });
  }

  await prisma.socialCommunity.createMany({
    data: communitySeeds,
    skipDuplicates: true,
  });

  const releases = await prisma.release.findMany({
    select: { id: true, packageName: true, packageVersion: true, releaseChannel: true, deploymentEnv: true },
  });
  const existingPosts = await prisma.socialPost.findMany({
    where: { releaseId: { in: releases.map((release) => release.id) } },
    select: { releaseId: true },
  });
  const existing = new Set(existingPosts.map((row) => row.releaseId));
  const missingPosts = releases
    .filter((release) => !existing.has(release.id))
    .map((release) => ({
      releaseId: release.id,
      content: `Nova release ${release.packageName}@${release.packageVersion} (${release.releaseChannel}/${release.deploymentEnv}).`,
    }));
  if (missingPosts.length) {
    await prisma.socialPost.createMany({
      data: missingPosts,
      skipDuplicates: true,
    });
  }

  console.log(`Seed applied: ${seeds.length} releases`);
}

main()
  .catch((error) => {
    console.error(error);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
