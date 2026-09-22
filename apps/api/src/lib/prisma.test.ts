import { afterAll, describe, expect, it } from 'vitest';

import { prisma } from './prisma.js';

describe('database', () => {
  afterAll(async () => {
    await prisma.$disconnect();
  });

  it('connects to PostgreSQL', async () => {
    const result = await prisma.$queryRaw<Array<{ value: number }>>`
      SELECT 1 AS value
    `;

    expect(result[0]?.value).toBe(1);
  });
});
