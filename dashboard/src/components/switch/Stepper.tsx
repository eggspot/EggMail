import { STEP_ORDER, stepIndex } from '../../lib/switchFlow';
import type { WizardStep } from '../../lib/switchFlow';

/** The wizard's step list. The current step carries aria-current="step"; earlier steps are marked done. */
export function Stepper({ step }: { step: WizardStep }) {
  const current = stepIndex(step);
  return (
    <ol class="steps" aria-label="Storage switch steps">
      {STEP_ORDER.map((s, i) => (
        <li key={s.id} aria-current={i === current ? 'step' : undefined} class={i < current ? 'done' : undefined}>
          {s.label}
          {i < current && <span class="sr-only"> (done)</span>}
        </li>
      ))}
    </ol>
  );
}
