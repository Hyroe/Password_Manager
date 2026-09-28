export const SESSION_USER_AGENT_MAX_LENGTH = 512;

export function normalizeSessionUserAgent(value: string | undefined): string | null {
  const normalized = value?.trim();

  if (!normalized) {
    return null;
  }

  return normalized.slice(0, SESSION_USER_AGENT_MAX_LENGTH);
}

export function describeSessionDevice(userAgent: string | null): string {
  if (!userAgent) {
    return 'Unknown device';
  }

  let browser = 'Unknown browser';

  if (/Edg\//i.test(userAgent)) {
    browser = 'Edge';
  } else if (/FxiOS\//i.test(userAgent) || /Firefox\//i.test(userAgent)) {
    browser = 'Firefox';
  } else if (/CriOS\//i.test(userAgent) || /Chrome\//i.test(userAgent)) {
    browser = 'Chrome';
  } else if (/Safari\//i.test(userAgent) && /Version\//i.test(userAgent)) {
    browser = 'Safari';
  }

  let platform = 'Unknown OS';

  if (/Windows NT/i.test(userAgent)) {
    platform = 'Windows';
  } else if (/Android/i.test(userAgent)) {
    platform = 'Android';
  } else if (/iPhone|iPad|iPod/i.test(userAgent)) {
    platform = 'iOS';
  } else if (/Macintosh|Mac OS X/i.test(userAgent)) {
    platform = 'macOS';
  } else if (/Linux/i.test(userAgent)) {
    platform = 'Linux';
  }

  if (browser === 'Unknown browser' && platform === 'Unknown OS') {
    return 'Unknown device';
  }

  if (browser === 'Unknown browser') {
    return platform;
  }

  if (platform === 'Unknown OS') {
    return browser;
  }

  return `${browser} on ${platform}`;
}
