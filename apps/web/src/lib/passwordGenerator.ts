export const DEFAULT_PASSWORD_LENGTH = 20;

export const MIN_GENERATED_PASSWORD_LENGTH = 12;

export const MAX_GENERATED_PASSWORD_LENGTH = 128;

export const PASSWORD_GENERATOR_CHARACTER_SETS = {
  lowercase: 'abcdefghijklmnopqrstuvwxyz',
  uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  numbers: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.?/',
} as const;

export interface PasswordGeneratorOptions {
  length?: number;

  includeLowercase?: boolean;
  includeUppercase?: boolean;
  includeNumbers?: boolean;
  includeSymbols?: boolean;
}

function secureRandomIndex(upperBound: number): number {
  if (!Number.isSafeInteger(upperBound) || upperBound <= 0) {
    throw new Error('Random upper bound must be a positive integer.');
  }

  const cryptoApi = globalThis.crypto;

  if (!cryptoApi?.getRandomValues) {
    throw new Error('Secure random generation is unavailable.');
  }

  /*
   * Rejection sampling avoids modulo bias.
   *
   * 2^32 is exactly representable by JavaScript numbers.
   */
  const randomRange = 0x1_0000_0000;

  const limit = randomRange - (randomRange % upperBound);

  const randomValue = new Uint32Array(1);

  while (true) {
    cryptoApi.getRandomValues(randomValue);

    const value = randomValue[0]!;

    if (value < limit) {
      return value % upperBound;
    }
  }
}

function pickRandomCharacter(characterSet: string): string {
  return characterSet[secureRandomIndex(characterSet.length)]!;
}

function secureShuffle(values: string[]): void {
  for (let index = values.length - 1; index > 0; index -= 1) {
    const swapIndex = secureRandomIndex(index + 1);

    [values[index], values[swapIndex]] = [values[swapIndex]!, values[index]!];
  }
}

export function generatePassword(options: PasswordGeneratorOptions = {}): string {
  const {
    length = DEFAULT_PASSWORD_LENGTH,

    includeLowercase = true,
    includeUppercase = true,
    includeNumbers = true,
    includeSymbols = true,
  } = options;

  if (
    !Number.isSafeInteger(length) ||
    length < MIN_GENERATED_PASSWORD_LENGTH ||
    length > MAX_GENERATED_PASSWORD_LENGTH
  ) {
    throw new Error(
      `Password length must be an integer between ${MIN_GENERATED_PASSWORD_LENGTH} and ${MAX_GENERATED_PASSWORD_LENGTH}.`,
    );
  }

  const enabledCharacterSets: string[] = [];

  if (includeLowercase) {
    enabledCharacterSets.push(PASSWORD_GENERATOR_CHARACTER_SETS.lowercase);
  }

  if (includeUppercase) {
    enabledCharacterSets.push(PASSWORD_GENERATOR_CHARACTER_SETS.uppercase);
  }

  if (includeNumbers) {
    enabledCharacterSets.push(PASSWORD_GENERATOR_CHARACTER_SETS.numbers);
  }

  if (includeSymbols) {
    enabledCharacterSets.push(PASSWORD_GENERATOR_CHARACTER_SETS.symbols);
  }

  if (enabledCharacterSets.length === 0) {
    throw new Error('At least one password character set must be enabled.');
  }

  if (length < enabledCharacterSets.length) {
    throw new Error('Password length is too short for the enabled character sets.');
  }

  const passwordCharacters: string[] = [];

  /*
   * Guarantee at least one character from
   * every enabled category.
   */
  for (const characterSet of enabledCharacterSets) {
    passwordCharacters.push(pickRandomCharacter(characterSet));
  }

  const combinedCharacterSet = enabledCharacterSets.join('');

  while (passwordCharacters.length < length) {
    passwordCharacters.push(pickRandomCharacter(combinedCharacterSet));
  }

  /*
   * The mandatory category characters were
   * inserted first, so shuffle them securely
   * before returning the password.
   */
  secureShuffle(passwordCharacters);

  return passwordCharacters.join('');
}
