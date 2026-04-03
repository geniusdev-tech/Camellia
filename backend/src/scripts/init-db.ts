import { PrismaClient } from '@prisma/client';
import argon2 from 'argon2';
import * as dotenv from 'dotenv';

dotenv.config();

const prisma = new PrismaClient();

async function main() {
  console.log('Initializing database...');

  // Roles
  const ownerRole = await prisma.role.upsert({
    where: { name: 'owner' },
    update: {},
    create: { name: 'owner' },
  });

  const userRole = await prisma.role.upsert({
    where: { name: 'user' },
    update: {},
    create: { name: 'user' },
  });

  // Admin User
  const adminEmail = process.env.GATESTACK_DEV_EMAIL || 'rodrigo@mail.com';
  const adminPassword = process.env.GATESTACK_DEV_PASSWORD || 'Nses@100';

  const existingAdmin = await prisma.user.findUnique({
    where: { username: adminEmail },
  });

  if (!existingAdmin) {
    const hashedPassword = await argon2.hash(adminPassword);
    await prisma.user.create({
      data: {
        username: adminEmail,
        passwordHash: hashedPassword,
        roleId: ownerRole.id,
        isActive: true,
      },
    });
    console.log(`Admin user ${adminEmail} created.`);
  } else {
    console.log(`Admin user ${adminEmail} already exists.`);
  }

  console.log('Database initialization complete.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
