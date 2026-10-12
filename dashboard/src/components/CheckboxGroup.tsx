import type { ComponentChildren } from 'preact';
import { useId } from 'preact/hooks';

/** Accessible group of checkboxes (fieldset + legend) with hint and error wiring. */
export function CheckboxGroup({
  legend,
  options,
  selected,
  onChange,
  error,
  hint,
  describe,
}: {
  legend: string;
  options: readonly string[];
  selected: string[];
  onChange: (next: string[]) => void;
  error?: string;
  hint?: ComponentChildren;
  /** Optional extra text per option. */
  describe?: (option: string) => string | undefined;
}) {
  const id = useId();
  const toggle = (opt: string, on: boolean) => onChange(on ? [...selected, opt] : selected.filter((s) => s !== opt));
  const describedBy = [hint ? `${id}-hint` : '', error ? `${id}-err` : ''].filter(Boolean).join(' ') || undefined;
  return (
    <fieldset aria-describedby={describedBy} class={error ? 'field-error' : undefined}>
      <legend>{legend}</legend>
      <div class="stack">
        {options.map((opt, i) => (
          <div class="check" key={opt}>
            <input
              type="checkbox"
              id={`${id}-${i}`}
              checked={selected.includes(opt)}
              onChange={(e) => toggle(opt, (e.currentTarget as HTMLInputElement).checked)}
            />
            <label for={`${id}-${i}`}>
              <code>{opt}</code>
              {describe?.(opt) && (
                <>
                  {' '}
                  <span class="muted small">{describe(opt)}</span>
                </>
              )}
            </label>
          </div>
        ))}
      </div>
      {hint && (
        <div class="hint" id={`${id}-hint`}>
          {hint}
        </div>
      )}
      {error && (
        <div class="error-text" id={`${id}-err`}>
          {error}
        </div>
      )}
    </fieldset>
  );
}
