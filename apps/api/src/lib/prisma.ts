import { PrismaPg } from '@prisma/adapter-pg';

import { getEnvironment } from '../config/env.js';

import { PrismaClient } from '../generated/prisma/client.js';

const environment = getEnvironment();

const adapter = new PrismaPg({
  connectionString: environment.DATABASE_URL,
});

export const prisma = new PrismaClient({
  adapter,
});
