export function resolveTrustProxy(): false | number {
  const value = process.env.TRUST_PROXY_HOPS?.trim();

  /*
   * Fail closed by default.
   *
   * X-Forwarded-* headers are not trusted
   * unless deployment explicitly opts in.
   */
  if (!value) {
    return false;
  }

  if (!/^[1-9]\d*$/.test(value)) {
    throw new Error('TRUST_PROXY_HOPS must be a positive integer.');
  }

  const hops = Number(value);

  if (!Number.isSafeInteger(hops) || hops > 10) {
    throw new Error('TRUST_PROXY_HOPS is outside the supported range.');
  }

  return hops;
}
