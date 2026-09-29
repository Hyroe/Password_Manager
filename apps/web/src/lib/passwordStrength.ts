import type { ZxcvbnFactory } from '@zxcvbn-ts/core';

export const MAX_PASSWORD_STRENGTH_INPUT_LENGTH = 128;

const MAX_CONTEXT_INPUTS = 16;
const MAX_CONTEXT_INPUT_LENGTH = 128;

export type PasswordStrengthScore = 0 | 1 | 2 | 3 | 4;

export type PasswordStrengthStatus = 'empty' | 'estimated' | 'not-evaluated' | 'unavailable';

export interface PasswordStrengthAssessment {
  status: PasswordStrengthStatus;
  score: PasswordStrengthScore | null;
  label: string;
  warning: string | null;
  suggestions: string[];
}

const scoreLabels: Record<PasswordStrengthScore, string> = {
  0: 'Very weak',
  1: 'Weak',
  2: 'Fair',
  3: 'Good',
  4: 'Strong',
};

let estimatorPromise: Promise<ZxcvbnFactory> | null = null;

function prepareUserInputs(userInputs: readonly string[]): string[] {
  const normalized = userInputs
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => value.slice(0, MAX_CONTEXT_INPUT_LENGTH));

  return [...new Set(normalized)].slice(0, MAX_CONTEXT_INPUTS);
}

async function getEstimator(): Promise<ZxcvbnFactory> {
  if (!estimatorPromise) {
    estimatorPromise = Promise.all([
      import('@zxcvbn-ts/core'),
      import('@zxcvbn-ts/language-common'),
      import('@zxcvbn-ts/language-en'),
    ])
      .then(([core, common, english]) => {
        return new core.ZxcvbnFactory({
          dictionary: {
            ...common.dictionary,
            ...english.dictionary,
          },

          graphs: common.adjacencyGraphs,

          translations: english.translations,

          maxLength: MAX_PASSWORD_STRENGTH_INPUT_LENGTH,
        });
      })
      .catch((error: unknown) => {
        /*
         * Do not permanently cache a failed lazy import.
         * A later attempt may succeed.
         */
        estimatorPromise = null;

        throw error;
      });
  }

  return estimatorPromise;
}

export async function evaluatePasswordStrength(
  password: string,
  userInputs: readonly string[] = [],
): Promise<PasswordStrengthAssessment> {
  if (password.length === 0) {
    return {
      status: 'empty',
      score: null,
      label: 'Not evaluated',
      warning: null,
      suggestions: [],
    };
  }

  if (password.length > MAX_PASSWORD_STRENGTH_INPUT_LENGTH) {
    return {
      status: 'not-evaluated',
      score: null,
      label: 'Not evaluated',
      warning:
        'This password exceeds the local strength meter limit. It has not been truncated or evaluated.',
      suggestions: [],
    };
  }

  try {
    const estimator = await getEstimator();

    const result = estimator.check(password, prepareUserInputs(userInputs));

    return {
      status: 'estimated',
      score: result.score,
      label: scoreLabels[result.score],
      warning: result.feedback.warning || null,
      suggestions: [...result.feedback.suggestions],
    };
  } catch {
    /*
     * Do not log the underlying error here.
     * Library errors could theoretically contain
     * password-derived information.
     */
    return {
      status: 'unavailable',
      score: null,
      label: 'Estimate unavailable',
      warning:
        'Password strength could not be estimated locally. You can still save this password.',
      suggestions: [],
    };
  }
}
