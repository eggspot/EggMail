import type { ComponentChildren, JSX } from 'preact';
import { useEffect, useId, useRef, useState } from 'preact/hooks';
import { errorFootnote, friendlyMessage } from '../api/errorMessages';

/* ---------- Chip ---------- */

export type Tone = 'ok' | 'warn' | 'bad' | 'info' | 'neutral';

/** A status chip. Meaning is always carried by the text; the color is secondary. */
export function Chip({ tone = 'neutral', children, title }: { tone?: Tone; children: ComponentChildren; title?: string }) {
  return (
    <span class={`chip chip-${tone}`} title={title}>
      {children}
    </span>
  );
}

const STATUS_TONES: Record<string, Tone> = {
  verified: 'ok',
  ok: 'ok',
  delivered: 'ok',
  active: 'ok',
  available: 'ok',
  queued: 'info',
  pending: 'info',
  verifying: 'info',
  deferred: 'warn',
  temporary_failure: 'warn',
  suppressed: 'warn',
  possible_duplicate: 'warn',
  body_expired: 'warn',
  missing: 'bad',
  invalid: 'bad',
  failed: 'bad',
  bounced: 'bad',
  expired: 'bad',
  complained: 'bad',
  cancelled: 'neutral',
};

export function toneFor(status: string): Tone {
  return STATUS_TONES[status] ?? 'neutral';
}

export function StatusChip({ status, label }: { status: string; label?: string }) {
  return <Chip tone={toneFor(status)}>{label ?? status.replace(/_/g, ' ')}</Chip>;
}

/* ---------- Loading, errors, empty states ---------- */

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <p class="loading" role="status">
      <span class="spinner" aria-hidden="true" /> {label}...
    </p>
  );
}

export function ErrorNotice({ error, onRetry, title }: { error: unknown; onRetry?: () => void; title?: string }) {
  const foot = errorFootnote(error);
  return (
    <div class="notice notice-bad" role="alert">
      <strong>{title ?? 'Something went wrong'}</strong>
      <p>{friendlyMessage(error)}</p>
      {foot && <p class="muted small">{foot}</p>}
      {onRetry && (
        <button type="button" class="btn" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ComponentChildren; action?: ComponentChildren }) {
  return (
    <div class="empty">
      <h2>{title}</h2>
      {children && <div class="muted">{children}</div>}
      {action && <div class="empty-action">{action}</div>}
    </div>
  );
}

export function Notice({ tone = 'info', title, children }: { tone?: Tone; title?: string; children: ComponentChildren }) {
  return (
    <div class={`notice notice-${tone}`} role={tone === 'bad' ? 'alert' : 'status'}>
      {title && <strong>{title}</strong>}
      <div>{children}</div>
    </div>
  );
}

/* ---------- Page scaffolding ---------- */

export function PageHeader({ title, actions, subtitle }: { title: string; actions?: ComponentChildren; subtitle?: ComponentChildren }) {
  return (
    <header class="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p class="muted">{subtitle}</p>}
      </div>
      {actions && <div class="page-actions">{actions}</div>}
    </header>
  );
}

export function Card({ title, children, actions, id }: { title?: string; children: ComponentChildren; actions?: ComponentChildren; id?: string }) {
  const autoId = useId();
  const headingId = id ?? autoId;
  return (
    <section class="card" aria-labelledby={title ? headingId : undefined}>
      {(title || actions) && (
        <div class="card-head">
          {title && <h2 id={headingId}>{title}</h2>}
          {actions && <div class="card-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

/* ---------- Forms ---------- */

interface FieldProps {
  label: string;
  error?: string;
  hint?: ComponentChildren;
  children: (ids: { id: string; describedBy: string | undefined; invalid: boolean }) => JSX.Element;
}

/** Label + control + hint + error wiring (aria-describedby, aria-invalid). */
export function Field({ label, error, hint, children }: FieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errId = `${id}-err`;
  const describedBy = [hint ? hintId : '', error ? errId : ''].filter(Boolean).join(' ') || undefined;
  return (
    <div class={`field${error ? ' field-error' : ''}`}>
      <label for={id}>{label}</label>
      {children({ id, describedBy, invalid: !!error })}
      {hint && (
        <div class="hint" id={hintId}>
          {hint}
        </div>
      )}
      {error && (
        <div class="error-text" id={errId}>
          {error}
        </div>
      )}
    </div>
  );
}

export function TextField({
  label,
  value,
  onInput,
  error,
  hint,
  type = 'text',
  ...rest
}: {
  label: string;
  value: string;
  onInput: (v: string) => void;
  error?: string;
  hint?: ComponentChildren;
  type?: string;
} & Omit<JSX.InputHTMLAttributes<HTMLInputElement>, 'value' | 'onInput' | 'type' | 'label'>) {
  return (
    <Field label={label} error={error} hint={hint}>
      {({ id, describedBy, invalid }) => (
        <input
          {...rest}
          id={id}
          type={type}
          value={value}
          aria-describedby={describedBy}
          aria-invalid={invalid || undefined}
          onInput={(e) => onInput((e.currentTarget as HTMLInputElement).value)}
        />
      )}
    </Field>
  );
}

export function Button({
  variant = 'default',
  busy,
  children,
  ...rest
}: { variant?: 'default' | 'primary' | 'danger' | 'ghost'; busy?: boolean } & JSX.ButtonHTMLAttributes<HTMLButtonElement>) {
  const { disabled, class: cls, ...others } = rest as JSX.ButtonHTMLAttributes<HTMLButtonElement> & { class?: string };
  return (
    <button type="button" {...others} class={`btn btn-${variant}${cls ? ` ${cls}` : ''}`} disabled={disabled || busy} aria-busy={busy || undefined}>
      {children}
    </button>
  );
}

/* ---------- Clipboard ---------- */

export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to the legacy path */
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.className = 'offscreen';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

export function CopyButton({ text, label = 'Copy', what }: { text: string; label?: string; what?: string }) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const timer = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => () => clearTimeout(timer.current), []);
  const onClick = async () => {
    const ok = await copyText(text);
    setState(ok ? 'copied' : 'failed');
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setState('idle'), 2000);
  };
  return (
    <>
      <button type="button" class="btn btn-small" onClick={onClick} aria-label={what ? `${label} ${what}` : undefined}>
        {state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : label}
      </button>
      <span class="sr-only" role="status">
        {state === 'copied' ? 'Copied to clipboard' : state === 'failed' ? 'Copy failed, select the text and copy it manually' : ''}
      </span>
    </>
  );
}

/**
 * Shows a secret exactly once (API key, SMTP password, webhook signing secret). The value lives only
 * in component state of the creating page and is dropped when the user confirms they saved it.
 */
export function OneTimeSecret({ title, secret, onDone, hint }: { title: string; secret: string; onDone: () => void; hint?: ComponentChildren }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    ref.current?.focus();
  }, []);
  return (
    <div class="notice notice-warn secret" role="alertdialog" aria-labelledby="secret-title" aria-describedby="secret-warning" tabIndex={-1} ref={ref}>
      <strong id="secret-title">{title}</strong>
      <p id="secret-warning">
        <strong>Copy it now.</strong> This secret is shown only once and cannot be retrieved later. If you lose it, create a new one and revoke this one.
      </p>
      <div class="secret-row">
        <code class="secret-value" data-testid="secret-value">
          {secret}
        </code>
        <CopyButton text={secret} what="secret" />
      </div>
      {hint && <div class="muted small">{hint}</div>}
      <button type="button" class="btn btn-primary" onClick={onDone}>
        I have saved it
      </button>
    </div>
  );
}

/* ---------- Dialog ---------- */

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

/** Modal dialog with a focus trap, Escape to close and focus restore. */
export function Dialog({ title, children, onClose, labelledBy }: { title: string; children: ComponentChildren; onClose: () => void; labelledBy?: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const autoId = useId();
  const titleId = labelledBy ?? autoId;
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const node = ref.current;
    const first = node?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? node)?.focus();
    return () => previous?.focus?.();
  }, []);
  const onKeyDown = (e: KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      onClose();
      return;
    }
    if (e.key !== 'Tab' || !ref.current) return;
    const items = Array.from(ref.current.querySelectorAll<HTMLElement>(FOCUSABLE));
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };
  return (
    <div class="dialog-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div class="dialog" role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1} ref={ref} onKeyDown={onKeyDown}>
        <h2 id={titleId}>{title}</h2>
        {children}
      </div>
    </div>
  );
}

/** Confirmation for destructive actions. Optionally requires typing a phrase. */
export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  onConfirm,
  onCancel,
  danger = true,
  busy,
  error,
  requirePhrase,
  dismissLabel = 'Cancel',
  confirmDisabled = false,
}: {
  title: string;
  children: ComponentChildren;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
  danger?: boolean;
  busy?: boolean;
  error?: unknown;
  requirePhrase?: string;
  /** Label of the button that closes the dialog without doing anything ("Cancel" unless that word means something else on the page). */
  dismissLabel?: string;
  /** Keeps the confirm button disabled, for example while nothing is selected. */
  confirmDisabled?: boolean;
}) {
  const [typed, setTyped] = useState('');
  const ok = !confirmDisabled && (!requirePhrase || typed.trim() === requirePhrase);
  return (
    <Dialog title={title} onClose={onCancel}>
      <div class="stack">
        {children}
        {requirePhrase && (
          <TextField label={`Type "${requirePhrase}" to confirm`} value={typed} onInput={setTyped} autocomplete="off" spellcheck={false} />
        )}
        {error !== undefined && error !== null && <ErrorNotice error={error} />}
        <div class="row end">
          <Button onClick={onCancel}>{dismissLabel}</Button>
          <Button variant={danger ? 'danger' : 'primary'} onClick={onConfirm} disabled={!ok} busy={busy}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

/* ---------- Pager ---------- */

export function LoadMore({ hasMore, busy, onClick }: { hasMore: boolean; busy?: boolean; onClick: () => void }) {
  if (!hasMore) return null;
  return (
    <div class="row center">
      <Button onClick={onClick} busy={busy}>
        {busy ? 'Loading...' : 'Load more'}
      </Button>
    </div>
  );
}

/* ---------- Description list ---------- */

export function KeyValue({ items }: { items: [string, ComponentChildren][] }) {
  return (
    <dl class="kv">
      {items.map(([k, v]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/* ---------- Tabs ---------- */

export function Tabs({ tabs, active, onChange, label }: { tabs: { id: string; label: string }[]; active: string; onChange: (id: string) => void; label: string }) {
  const onKeyDown = (e: KeyboardEvent, i: number) => {
    let next = -1;
    if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') next = (i - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = tabs.length - 1;
    if (next >= 0) {
      e.preventDefault();
      onChange(tabs[next].id);
      requestAnimationFrame(() => document.getElementById(`tab-${tabs[next].id}`)?.focus());
    }
  };
  return (
    <div class="tabs" role="tablist" aria-label={label}>
      {tabs.map((t, i) => (
        <button
          key={t.id}
          type="button"
          role="tab"
          id={`tab-${t.id}`}
          aria-selected={active === t.id}
          aria-controls={`panel-${t.id}`}
          tabIndex={active === t.id ? 0 : -1}
          class={`tab${active === t.id ? ' tab-active' : ''}`}
          onClick={() => onChange(t.id)}
          onKeyDown={(e) => onKeyDown(e, i)}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}
