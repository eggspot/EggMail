import { useEffect, useRef, useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { ApiError } from '../api/client';
import { fieldErrors, friendlyMessage, errorFootnote, isCode } from '../api/errorMessages';
import type { SendMessageResponse } from '../api/types';
import { Button, Card, ErrorNotice, Field, Notice, PageHeader, TextField } from '../components/ui';
import { formatBytes } from '../lib/format';
import { useDocumentTitle } from '../lib/hooks';
import { emptySendForm, formFieldFor, newIdempotencyKey, validateSendForm } from '../lib/messages';
import type { AttachmentInput, SendFormValues } from '../lib/messages';
import { useApp } from '../state/app';

function readFile(file: File): Promise<AttachmentInput> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const s = String(reader.result);
      resolve({ filename: file.name, content_type: file.type || 'application/octet-stream', content: s.slice(s.indexOf(',') + 1), size: file.size });
    };
    reader.onerror = () => reject(reader.error ?? new Error('Could not read the file'));
    reader.readAsDataURL(file);
  });
}

function TextArea({ label, value, onInput, error, hint, rows = 6 }: { label: string; value: string; onInput: (v: string) => void; error?: string; hint?: string; rows?: number }) {
  return (
    <Field label={label} error={error} hint={hint}>
      {({ id, describedBy, invalid }) => (
        <textarea id={id} rows={rows} value={value} aria-describedby={describedBy} aria-invalid={invalid || undefined} onInput={(e) => onInput((e.currentTarget as HTMLTextAreaElement).value)} />
      )}
    </Field>
  );
}

export default function Send() {
  useDocumentTitle('Send test message');
  const { capabilities, historyMode } = useApp();
  const limits = capabilities?.limits ?? { maxMessageBytes: 26214400, maxRecipients: 50 };
  const [values, setValues] = useState<SendFormValues>(emptySendForm);
  const [clientErrors, setClientErrors] = useState<Record<string, string>>({});
  const [serverError, setServerError] = useState<unknown>(undefined);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SendMessageResponse | null>(null);
  const [fileError, setFileError] = useState('');
  // One Idempotency-Key per distinct request body: a retry of the unchanged form reuses it.
  const keyRef = useRef<{ key: string; signature: string } | null>(null);
  const resultRef = useRef<HTMLDivElement>(null);
  const formRef = useRef<HTMLFormElement>(null);

  const set = <K extends keyof SendFormValues>(k: K) => (v: SendFormValues[K]) => setValues((cur) => ({ ...cur, [k]: v }));

  useEffect(() => {
    if (result) resultRef.current?.focus();
  }, [result]);

  const serverFields: Record<string, string> = {};
  for (const [field, message] of Object.entries(fieldErrors(serverError))) serverFields[formFieldFor(field)] ??= message;
  const err = (f: string) => clientErrors[f] ?? serverFields[f];

  const onFiles = async (e: Event) => {
    const input = e.currentTarget as HTMLInputElement;
    const files = Array.from(input.files ?? []);
    setFileError('');
    try {
      const read = await Promise.all(files.map(readFile));
      setValues((cur) => ({ ...cur, attachments: [...cur.attachments, ...read] }));
    } catch {
      setFileError('One of the files could not be read.');
    }
    input.value = '';
  };

  const submit = async (e: Event) => {
    e.preventDefault();
    setResult(null);
    setServerError(undefined);
    const { errors, request } = validateSendForm(values, limits);
    setClientErrors(errors);
    if (!request) {
      requestAnimationFrame(() => formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
      return;
    }
    const signature = JSON.stringify(request);
    if (!keyRef.current || keyRef.current.signature !== signature) keyRef.current = { key: newIdempotencyKey(), signature };
    setBusy(true);
    try {
      const res = await api.send(request, keyRef.current.key);
      setResult(res);
      keyRef.current = null; // the next send is a new send
    } catch (ex) {
      setServerError(ex);
    } finally {
      setBusy(false);
    }
  };

  const clear = () => {
    setValues(emptySendForm);
    setClientErrors({});
    setServerError(undefined);
    setResult(null);
    keyRef.current = null;
  };

  const totalAttachmentBytes = values.attachments.reduce((n, a) => n + a.size, 0);

  return (
    <>
      <PageHeader title="Send test message" subtitle="Sends a real message through POST /api/v1/messages. The From domain must be a verified domain." />
      {result && (
        <div ref={resultRef} tabIndex={-1} data-testid="send-result">
          <Notice tone="ok" title="Message accepted">
            <p>
              Status <strong>{result.status}</strong> for {result.recipients} recipient{result.recipients === 1 ? '' : 's'}. Message id{' '}
              {historyMode === 'full' ? <a href={`/messages/${result.id}`}>{result.id}</a> : <code>{result.id}</code>}.
            </p>
            {historyMode === 'statsonly' && <p class="small">Per-message history is not recorded on this server, so this id cannot be looked up. It is only useful for log correlation.</p>}
          </Notice>
        </div>
      )}
      {serverError !== undefined &&
        (isCode(serverError, 'domain_not_verified') ? (
          <Notice tone="bad" title="The From domain is not verified">
            <p>{friendlyMessage(serverError)}</p>
            <p>
              <a href="/domains">Open the domains page</a> to publish the DNS records and verify the domain.
            </p>
            {serverError instanceof ApiError && errorFootnote(serverError) && <p class="muted small">{errorFootnote(serverError)}</p>}
          </Notice>
        ) : (
          <ErrorNotice error={serverError} title="The message was not sent" />
        ))}
      <Card>
        <form ref={formRef} onSubmit={submit} noValidate class="stack" aria-label="Send a test message">
          <div class="form-grid">
            <TextField label="From" value={values.from} onInput={set('from')} error={err('from')} hint="sender@example.com or Name <sender@example.com>" autocomplete="off" required />
            <TextField label="Reply-To (optional)" value={values.replyTo} onInput={set('replyTo')} error={err('reply_to')} autocomplete="off" />
          </div>
          <TextArea label="To" value={values.to} onInput={set('to')} error={err('to')} rows={2} hint={`Separate addresses with commas, spaces or new lines. At most ${limits.maxRecipients} recipients in total.`} />
          <div class="form-grid">
            <TextField label="Cc (optional)" value={values.cc} onInput={set('cc')} error={err('cc')} autocomplete="off" />
            <TextField label="Bcc (optional)" value={values.bcc} onInput={set('bcc')} error={err('bcc')} autocomplete="off" />
          </div>
          <TextField label="Subject" value={values.subject} onInput={set('subject')} error={err('subject')} autocomplete="off" required />
          <TextArea label="Text body" value={values.text} onInput={set('text')} error={err('text')} hint="Plain text part. Provide a text body, an HTML body, or both." />
          <TextArea label="HTML body (optional)" value={values.html} onInput={set('html')} error={err('html')} />
          <div class="form-grid">
            <TextField label="Tags (optional)" value={values.tags} onInput={set('tags')} error={err('tags')} hint="Comma separated" autocomplete="off" />
          </div>
          <TextArea label="Extra headers (optional)" value={values.headers} onInput={set('headers')} error={err('headers')} rows={3} hint="One per line, as Name: value. Line breaks inside a value are not allowed." />

          <Field label="Attachments (optional)" error={err('attachments') || fileError || undefined} hint={`Total size must stay under ${formatBytes(limits.maxMessageBytes)}.`}>
            {({ id, describedBy, invalid }) => <input id={id} type="file" multiple aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={onFiles} />}
          </Field>
          {values.attachments.length > 0 && (
            <>
              <ul class="plain-list" aria-label="Selected attachments">
                {values.attachments.map((a, i) => (
                  <li key={`${a.filename}-${i}`} class="row">
                    <span>
                      {a.filename} <span class="muted">({formatBytes(a.size)})</span>
                    </span>
                    <Button variant="ghost" onClick={() => setValues((cur) => ({ ...cur, attachments: cur.attachments.filter((_, j) => j !== i) }))} aria-label={`Remove ${a.filename}`}>
                      Remove
                    </Button>
                  </li>
                ))}
              </ul>
              <p class="muted small">{formatBytes(totalAttachmentBytes)} in total.</p>
              <div class="check">
                <input id="store-attachments" type="checkbox" checked={values.storeAttachments} onChange={(e) => set('storeAttachments')((e.currentTarget as HTMLInputElement).checked)} />
                <label for="store-attachments">Store the attachments so this message can be resent later (the server may need attachment storage enabled)</label>
              </div>
            </>
          )}

          <div class="row">
            <Button type="submit" variant="primary" busy={busy}>
              {busy ? 'Sending...' : 'Send message'}
            </Button>
            <Button onClick={clear}>Clear form</Button>
          </div>
        </form>
      </Card>
    </>
  );
}
