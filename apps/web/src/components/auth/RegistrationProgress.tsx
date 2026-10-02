interface RegistrationProgressProps {
  currentStep: number;
}

const steps = ['Account', 'Verify', 'Passkey', 'Vault', 'Recovery', 'Ready'];

export function RegistrationProgress({ currentStep }: RegistrationProgressProps) {
  return (
    <ol className="registration-progress" aria-label="Account setup progress">
      {steps.map((label, index) => {
        const step = index + 1;
        const completed = step < currentStep;
        const active = step === currentStep;

        return (
          <li
            key={label}
            className={[
              'registration-progress__step',
              completed ? 'registration-progress__step--completed' : '',
              active ? 'registration-progress__step--active' : '',
            ]
              .filter(Boolean)
              .join(' ')}
            aria-current={active ? 'step' : undefined}
          >
            <span className="registration-progress__indicator" aria-hidden="true">
              {completed ? '✓' : step}
            </span>

            <span>{label}</span>
          </li>
        );
      })}
    </ol>
  );
}
