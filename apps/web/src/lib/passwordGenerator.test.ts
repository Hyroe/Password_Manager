import { describe, expect, it, vi } from 'vitest';

import {
  DEFAULT_PASSWORD_LENGTH,
  MAX_GENERATED_PASSWORD_LENGTH,
  MIN_GENERATED_PASSWORD_LENGTH,
  PASSWORD_GENERATOR_CHARACTER_SETS,
  generatePassword,
} from './passwordGenerator';

describe('password generator', () => {
  it('generates a password with the default length and every default character category', () => {
    const password = generatePassword();

    expect(password).toHaveLength(DEFAULT_PASSWORD_LENGTH);

    expect(
      [...password].some((character) =>
        PASSWORD_GENERATOR_CHARACTER_SETS.lowercase.includes(character),
      ),
    ).toBe(true);

    expect(
      [...password].some((character) =>
        PASSWORD_GENERATOR_CHARACTER_SETS.uppercase.includes(character),
      ),
    ).toBe(true);

    expect(
      [...password].some((character) =>
        PASSWORD_GENERATOR_CHARACTER_SETS.numbers.includes(character),
      ),
    ).toBe(true);

    expect(
      [...password].some((character) =>
        PASSWORD_GENERATOR_CHARACTER_SETS.symbols.includes(character),
      ),
    ).toBe(true);
  });

  it('supports a custom password length', () => {
    const password = generatePassword({
      length: 64,
    });

    expect(password).toHaveLength(64);
  });

  it('uses only enabled character categories', () => {
    const password = generatePassword({
      length: 64,

      includeLowercase: true,
      includeUppercase: false,
      includeNumbers: false,
      includeSymbols: false,
    });

    expect(password).toHaveLength(64);

    expect(
      [...password].every((character) =>
        PASSWORD_GENERATOR_CHARACTER_SETS.lowercase.includes(character),
      ),
    ).toBe(true);
  });

  it('guarantees at least one character from every enabled category', () => {
    const password = generatePassword({
      length: MIN_GENERATED_PASSWORD_LENGTH,

      includeLowercase: true,
      includeUppercase: true,
      includeNumbers: true,
      includeSymbols: true,
    });

    for (const characterSet of Object.values(PASSWORD_GENERATOR_CHARACTER_SETS)) {
      expect([...password].some((character) => characterSet.includes(character))).toBe(true);
    }
  });

  it('rejects passwords shorter than the minimum length', () => {
    expect(() =>
      generatePassword({
        length: MIN_GENERATED_PASSWORD_LENGTH - 1,
      }),
    ).toThrow(
      `Password length must be an integer between ${MIN_GENERATED_PASSWORD_LENGTH} and ${MAX_GENERATED_PASSWORD_LENGTH}.`,
    );
  });

  it('rejects passwords longer than the maximum length', () => {
    expect(() =>
      generatePassword({
        length: MAX_GENERATED_PASSWORD_LENGTH + 1,
      }),
    ).toThrow(
      `Password length must be an integer between ${MIN_GENERATED_PASSWORD_LENGTH} and ${MAX_GENERATED_PASSWORD_LENGTH}.`,
    );
  });

  it('rejects non-integer password lengths', () => {
    expect(() =>
      generatePassword({
        length: 20.5,
      }),
    ).toThrow(
      `Password length must be an integer between ${MIN_GENERATED_PASSWORD_LENGTH} and ${MAX_GENERATED_PASSWORD_LENGTH}.`,
    );
  });

  it('requires at least one enabled character category', () => {
    expect(() =>
      generatePassword({
        includeLowercase: false,
        includeUppercase: false,
        includeNumbers: false,
        includeSymbols: false,
      }),
    ).toThrow('At least one password character set must be enabled.');
  });

  it('does not use Math.random', () => {
    const randomSpy = vi.spyOn(Math, 'random');

    try {
      generatePassword({
        length: 32,
      });

      expect(randomSpy).not.toHaveBeenCalled();
    } finally {
      randomSpy.mockRestore();
    }
  });

  it('generates independent passwords across repeated calls', () => {
    const generatedPasswords = new Set<string>();

    for (let index = 0; index < 10; index += 1) {
      generatedPasswords.add(
        generatePassword({
          length: 32,
        }),
      );
    }

    expect(generatedPasswords.size).toBeGreaterThan(1);
  });
});
