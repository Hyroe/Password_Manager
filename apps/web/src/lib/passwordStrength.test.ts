import { ZxcvbnFactory } from '@zxcvbn-ts/core';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { MAX_PASSWORD_STRENGTH_INPUT_LENGTH, evaluatePasswordStrength } from './passwordStrength';

describe('password strength', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('does not evaluate an empty password', async () => {
    const checkSpy = vi.spyOn(ZxcvbnFactory.prototype, 'check');

    const assessment = await evaluatePasswordStrength('');

    expect(assessment).toEqual({
      status: 'empty',
      score: null,
      label: 'Not evaluated',
      warning: null,
      suggestions: [],
    });

    expect(checkSpy).not.toHaveBeenCalled();
  });

  it('recognizes a common password as very weak', async () => {
    const assessment = await evaluatePasswordStrength('password');

    expect(assessment.status).toBe('estimated');
    expect(assessment.score).toBe(0);
    expect(assessment.label).toBe('Very weak');
  });

  it('does not consider predictable character diversity strong', async () => {
    const assessment = await evaluatePasswordStrength('Password123!');

    expect(assessment.status).toBe('estimated');
    expect(assessment.score).not.toBeNull();
    expect(assessment.score).toBeLessThanOrEqual(2);
  });

  it('does not consider a long repetition strong', async () => {
    const assessment = await evaluatePasswordStrength('a'.repeat(64));

    expect(assessment.status).toBe('estimated');
    expect(assessment.score).not.toBeNull();
    expect(assessment.score).toBeLessThanOrEqual(1);
  });

  it('rates a varied test fixture higher than a common password', async () => {
    const weak = await evaluatePasswordStrength('password');

    const varied = await evaluatePasswordStrength('7q$L2v!R9m#T4x@N8z%P');

    expect(weak.score).not.toBeNull();
    expect(varied.score).not.toBeNull();

    expect(varied.score).toBeGreaterThan(weak.score!);
  });

  it('preserves spaces and Unicode in the password', async () => {
    const checkSpy = vi.spyOn(ZxcvbnFactory.prototype, 'check');

    const password = '  café-雪-Example42!  ';

    const assessment = await evaluatePasswordStrength(password);

    expect(assessment.status).toBe('estimated');
    expect(assessment.score).not.toBeNull();

    expect(checkSpy).toHaveBeenCalledExactlyOnceWith(password, []);
  });

  it('passes contextual user inputs to the estimator', async () => {
    const checkSpy = vi.spyOn(ZxcvbnFactory.prototype, 'check');

    const password = 'CreatureCodex42!';
    const userInputs = ['Creature Codex', 'daniel@example.com', 'https://example.com'];

    await evaluatePasswordStrength(password, userInputs);

    expect(checkSpy).toHaveBeenCalledExactlyOnceWith(password, userInputs);
  });

  it('removes empty and duplicate contextual user inputs', async () => {
    const checkSpy = vi.spyOn(ZxcvbnFactory.prototype, 'check');

    const password = 'Example42!';

    await evaluatePasswordStrength(password, [
      '',
      '  ',
      'Example',
      ' Example ',
      'user@example.com',
      'user@example.com',
    ]);

    expect(checkSpy).toHaveBeenCalledExactlyOnceWith(password, ['Example', 'user@example.com']);
  });

  it('handles symbol-only passwords', async () => {
    const assessment = await evaluatePasswordStrength('!@#$%^&*()!@#$%^&*()');

    expect(assessment.status).toBe('estimated');
    expect(assessment.score).not.toBeNull();
  });

  it('evaluates a password at the configured limit', async () => {
    const assessment = await evaluatePasswordStrength(
      'a'.repeat(MAX_PASSWORD_STRENGTH_INPUT_LENGTH),
    );

    expect(assessment.status).toBe('estimated');
    expect(assessment.score).not.toBeNull();
  });

  it('does not silently truncate an oversized password', async () => {
    const checkSpy = vi.spyOn(ZxcvbnFactory.prototype, 'check');

    const password = 'a'.repeat(MAX_PASSWORD_STRENGTH_INPUT_LENGTH + 1);

    const assessment = await evaluatePasswordStrength(password);

    expect(assessment).toEqual({
      status: 'not-evaluated',
      score: null,
      label: 'Not evaluated',
      warning:
        'This password exceeds the local strength meter limit. It has not been truncated or evaluated.',
      suggestions: [],
    });

    expect(checkSpy).not.toHaveBeenCalled();
  });

  it('returns only safe assessment fields', async () => {
    const password = '7q$L2v!R9m#T4x@N8z%P';

    const assessment = await evaluatePasswordStrength(password);

    expect(Object.keys(assessment).sort()).toEqual(
      ['status', 'score', 'label', 'warning', 'suggestions'].sort(),
    );

    expect(assessment).not.toHaveProperty('password');

    expect(assessment).not.toHaveProperty('sequence');

    expect(assessment).not.toHaveProperty('crackTimes');

    expect(JSON.stringify(assessment)).not.toContain(password);
  });

  it('does not make a network request during evaluation', async () => {
    const fetchSpy = vi.fn(() => {
      throw new Error('Network access must not occur.');
    });

    vi.stubGlobal('fetch', fetchSpy);

    const assessment = await evaluatePasswordStrength('Password123!');

    expect(assessment.status).toBe('estimated');

    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('returns a generic unavailable result without logging estimator errors', async () => {
    const password = 'private-test-password';

    vi.spyOn(ZxcvbnFactory.prototype, 'check').mockImplementationOnce(() => {
      throw new Error(`Estimator failed for ${password}`);
    });

    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);

    const warningSpy = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    const assessment = await evaluatePasswordStrength(password);

    expect(assessment).toEqual({
      status: 'unavailable',
      score: null,
      label: 'Estimate unavailable',
      warning:
        'Password strength could not be estimated locally. You can still save this password.',
      suggestions: [],
    });

    expect(JSON.stringify(assessment)).not.toContain(password);

    expect(errorSpy).not.toHaveBeenCalled();
    expect(warningSpy).not.toHaveBeenCalled();
  });
});
