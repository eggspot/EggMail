import { useState } from 'preact/hooks';
import { api } from '../../api/endpoints';
import { fieldErrors } from '../../api/errorMessages';
import { CertificateExpiry } from '../../components/CertificateExpiry';
import { Button, Card, Chip, EmptyState, ErrorNotice, Field, Loading, Notice, PageHeader, StatusChip, Tabs, TextField } from '../../components/ui';
import { formatDateTime, formatRelative } from '../../lib/format';
import { useAction, useApi, useDocumentTitle } from '../../lib/hooks';

const PEM_CERT = /-----BEGIN CERTIFICATE-----[\s\S]+-----END CERTIFICATE-----/;
const PEM_KEY = /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]+-----END (?:RSA |EC )?PRIVATE KEY-----/;
const HOSTNAME = /^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;

/** Reads a file and returns it base64-encoded (without a data: prefix). */
export function readAsBase64(file: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error('Could not read the file.'));
    reader.onload = () => {
      const bytes = new Uint8Array(reader.result as ArrayBuffer);
      let binary = '';
      for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      resolve(btoa(binary));
    };
    reader.readAsArrayBuffer(file);
  });
}

function sourceChip(source: string) {
  if (source === 'self_signed') return <Chip tone="warn">self-signed</Chip>;
  if (source === 'acme') return <Chip tone="info">ACME</Chip>;
  if (source === 'upload') return <Chip tone="neutral">uploaded</Chip>;
  return <Chip>{source}</Chip>;
}

function UploadForm({ onDone }: { onDone: (msg: string) => void }) {
  const [tab, setTab] = useState<'pem' | 'pfx'>('pem');
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [pfx, setPfx] = useState<File | null>(null);
  const [pfxPassword, setPfxPassword] = useState('');
  const [local, setLocal] = useState<Record<string, string>>({});

  const upload = useAction(async () => {
    const errors: Record<string, string> = {};
    if (tab === 'pem') {
      if (!PEM_CERT.test(certPem)) errors.certificatePem = 'Paste a PEM certificate (-----BEGIN CERTIFICATE-----).';
      if (!PEM_KEY.test(keyPem)) errors.privateKeyPem = 'Paste the PEM private key (-----BEGIN PRIVATE KEY-----).';
    } else if (!pfx) errors.pfxBase64 = 'Choose a PFX or PKCS#12 file.';
    setLocal(errors);
    if (Object.keys(errors).length) return;
    const body = tab === 'pem' ? { certificatePem: certPem.trim(), privateKeyPem: keyPem.trim() } : { pfxBase64: await readAsBase64(pfx as File), pfxPassword: pfxPassword || undefined };
    const cert = await api.uploadCertificate(body);
    // The key material never stays in the page after a successful upload.
    setCertPem('');
    setKeyPem('');
    setPfx(null);
    setPfxPassword('');
    onDone(`Uploaded ${cert.subject}. It is stored in the database with its private key protected by Data Protection.`);
  });
  const server = fieldErrors(upload.error);
  const err = (k: string) => local[k] ?? server[k];

  return (
    <Card title="Upload a certificate">
      <Tabs
        label="Certificate format"
        tabs={[
          { id: 'pem', label: 'PEM' },
          { id: 'pfx', label: 'PFX / PKCS#12' },
        ]}
        active={tab}
        onChange={(id) => setTab(id as 'pem' | 'pfx')}
      />
      <form
        class="stack"
        role="tabpanel"
        id={`panel-${tab}`}
        aria-labelledby={`tab-${tab}`}
        onSubmit={(e) => {
          e.preventDefault();
          void upload.run();
        }}
        noValidate
      >
        {tab === 'pem' ? (
          <>
            <Field label="Certificate chain (PEM)" error={err('certificatePem')} hint="The certificate first, then intermediates.">
              {({ id, describedBy, invalid }) => (
                <textarea id={id} value={certPem} spellcheck={false} autocomplete="off" aria-describedby={describedBy} aria-invalid={invalid || undefined} onInput={(e) => setCertPem((e.currentTarget as HTMLTextAreaElement).value)} />
              )}
            </Field>
            <Field label="Private key (PEM)" error={err('privateKeyPem')} hint="Sent once over HTTPS, stored protected, and cleared from this page after the upload.">
              {({ id, describedBy, invalid }) => (
                <textarea id={id} value={keyPem} spellcheck={false} autocomplete="off" aria-describedby={describedBy} aria-invalid={invalid || undefined} onInput={(e) => setKeyPem((e.currentTarget as HTMLTextAreaElement).value)} />
              )}
            </Field>
          </>
        ) : (
          <>
            <Field label="PFX file" error={err('pfxBase64')}>
              {({ id, describedBy, invalid }) => (
                <input id={id} type="file" accept=".pfx,.p12,application/x-pkcs12" aria-describedby={describedBy} aria-invalid={invalid || undefined} onChange={(e) => setPfx((e.currentTarget as HTMLInputElement).files?.[0] ?? null)} />
              )}
            </Field>
            <TextField label="PFX password (if any)" type="password" autocomplete="off" value={pfxPassword} onInput={setPfxPassword} error={err('pfxPassword')} />
          </>
        )}
        {upload.error !== undefined && Object.keys(server).length === 0 && <ErrorNotice error={upload.error} />}
        <div>
          <Button type="submit" variant="primary" busy={upload.busy}>
            Upload certificate
          </Button>
        </div>
      </form>
    </Card>
  );
}

function AcmeForm({ onDone }: { onDone: (msg: string) => void }) {
  const [text, setText] = useState('');
  const [local, setLocal] = useState('');
  const request = useAction(async () => {
    const domains = text.split(/[\s,;]+/).filter(Boolean);
    const bad = domains.find((d) => !HOSTNAME.test(d));
    if (!domains.length) return setLocal('Enter at least one host name.');
    if (bad) return setLocal(`"${bad}" is not a valid host name.`);
    setLocal('');
    const r = await api.requestAcmeCertificate(domains);
    setText('');
    onDone(r.message || `Certificate requested (${r.status}).`);
  });
  const server = fieldErrors(request.error);
  return (
    <Card title="Request a certificate (ACME)">
      <form
        class="stack"
        onSubmit={(e) => {
          e.preventDefault();
          void request.run();
        }}
        noValidate
      >
        <TextField
          label="Host names"
          value={text}
          onInput={setText}
          error={local || server.domains}
          hint="Separate several names with spaces or commas. Validation uses DNS-01 by default; no inbound port is needed."
          placeholder="mail.example.com"
        />
        {request.error !== undefined && !server.domains && <ErrorNotice error={request.error} />}
        <div>
          <Button type="submit" variant="primary" busy={request.busy}>
            Request certificate
          </Button>
        </div>
      </form>
    </Card>
  );
}

/** Renewal state of certificates requested through ACME: what the renewal service last tried and what it will do next. */
function AcmeRenewals({ reloadKey }: { reloadKey: number }) {
  const { data, error, loading, reload } = useApi(() => api.acmeRenewals(), [reloadKey]);
  return (
    <Card title="ACME renewals">
      {loading && !data && <Loading />}
      {error !== undefined && <ErrorNotice error={error} onRetry={reload} />}
      {data && data.length === 0 && <p class="muted">No certificate was requested through ACME yet.</p>}
      {data && data.length > 0 && (
        <div class="table-wrap">
          <table>
            <caption class="sr-only">ACME certificate renewals</caption>
            <thead>
              <tr>
                <th scope="col">Certificate</th>
                <th scope="col">Status</th>
                <th scope="col">Last attempt</th>
                <th scope="col">Next attempt</th>
                <th scope="col" class="num">
                  Failures
                </th>
                <th scope="col">Last error</th>
              </tr>
            </thead>
            <tbody>
              {data.map((r) => (
                <tr key={r.certificateName}>
                  <th scope="row">{r.certificateName}</th>
                  <td>
                    <StatusChip status={r.status} />
                  </td>
                  <td>{r.lastAttemptAt ? `${formatDateTime(r.lastAttemptAt)} (${formatRelative(r.lastAttemptAt)})` : 'Never'}</td>
                  <td>{r.nextAttemptAt ? formatDateTime(r.nextAttemptAt) : '-'}</td>
                  <td class="num">{r.failures ?? 0}</td>
                  <td class="wrap">{r.lastError ?? '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export default function Certificates(_props: Record<string, unknown>) {
  useDocumentTitle('Certificates');
  const list = useApi(() => api.certificates(), []);
  const [message, setMessage] = useState('');
  const [renewalsKey, setRenewalsKey] = useState(0);
  const done = (msg: string) => {
    setMessage(msg);
    list.reload();
    setRenewalsKey((k) => k + 1);
  };
  const certs = list.data ?? [];
  return (
    <>
      <PageHeader title="Certificates" subtitle="TLS certificates for SMTP and the dashboard. They live in the database and hot-reload without a restart." />
      {message && (
        <Notice tone="ok">
          <span role="status">{message}</span>
        </Notice>
      )}
      {list.loading && !list.data && <Loading />}
      {list.error !== undefined && <ErrorNotice error={list.error} onRetry={list.reload} />}
      {list.data && (
        <Card title="Installed certificates">
          {certs.length === 0 ? (
            <EmptyState title="No certificates">Upload one or request one with ACME below. Until then the server uses a self-signed certificate.</EmptyState>
          ) : (
            <div class="table-wrap">
              <table>
                <caption class="sr-only">Installed certificates</caption>
                <thead>
                  <tr>
                    <th scope="col">Subject</th>
                    <th scope="col">Names</th>
                    <th scope="col">Issuer</th>
                    <th scope="col">Source</th>
                    <th scope="col">Not after</th>
                    <th scope="col">In use</th>
                  </tr>
                </thead>
                <tbody>
                  {certs.map((c) => (
                    <tr key={c.id}>
                      <th scope="row">{c.subject}</th>
                      <td class="wrap">{c.san.join(', ')}</td>
                      <td class="wrap">{c.issuer ?? '-'}</td>
                      <td>{sourceChip(c.source)}</td>
                      <td>
                        {formatDateTime(c.notAfter)} <CertificateExpiry notAfter={c.notAfter} />
                      </td>
                      <td>{c.active ? <Chip tone="ok">active</Chip> : <Chip>not active</Chip>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {certs.some((c) => c.source === 'self_signed' && c.active) && (
                <Notice tone="warn">A self-signed certificate is in use. Mail clients and browsers will not trust it; upload or request a real certificate.</Notice>
              )}
            </div>
          )}
        </Card>
      )}
      <AcmeRenewals reloadKey={renewalsKey} />
      <div class="grid">
        <UploadForm onDone={done} />
        <AcmeForm onDone={done} />
      </div>
    </>
  );
}
