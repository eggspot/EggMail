import { useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { fieldErrors } from '../api/errorMessages';
import { Button, Card, ErrorNotice, KeyValue, Notice, PageHeader, TextField } from '../components/ui';
import { useAction, useDocumentTitle } from '../lib/hooks';
import { useApp } from '../state/app';

const MIN_PASSWORD = 10;

/** The signed-in user's own account: who they are and a password change. */
export default function Account(_props: Record<string, unknown>) {
  useDocumentTitle('Account');
  const { me } = useApp();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [again, setAgain] = useState('');
  const [clientErrors, setClientErrors] = useState<Record<string, string>>({});
  const [done, setDone] = useState(false);

  const change = useAction(async () => {
    await api.changePassword(current, next);
    setCurrent('');
    setNext('');
    setAgain('');
    setDone(true);
  });
  const serverErrors = fieldErrors(change.error);
  const errs = { ...serverErrors, ...clientErrors };

  const submit = async (e: Event) => {
    e.preventDefault();
    setDone(false);
    const found: Record<string, string> = {};
    if (!current) found.currentPassword = 'Enter your current password.';
    if (next.length < MIN_PASSWORD) found.newPassword = `Use at least ${MIN_PASSWORD} characters.`;
    else if (next === current) found.newPassword = 'The new password must differ from the current one.';
    if (again !== next) found.again = 'The two new passwords are not the same.';
    setClientErrors(found);
    if (Object.keys(found).length) return;
    await change.run();
  };

  return (
    <>
      <PageHeader title="Account" subtitle="Your own sign-in." />
      <Card title="Signed in as">
        <KeyValue
          items={[
            ['User', me?.user ?? ''],
            ['Role', me?.role === 'admin' ? 'Administrator' : 'Tenant user'],
          ]}
        />
      </Card>
      <Card title="Change your password">
        <form class="form-grid" onSubmit={submit} noValidate>
          <TextField label="Current password" type="password" value={current} onInput={setCurrent} error={errs.currentPassword} autocomplete="current-password" />
          <TextField
            label="New password"
            type="password"
            value={next}
            onInput={setNext}
            error={errs.newPassword}
            autocomplete="new-password"
            hint={`At least ${MIN_PASSWORD} characters. Your other sessions are signed out; this one stays.`}
          />
          <TextField label="New password again" type="password" value={again} onInput={setAgain} error={errs.again} autocomplete="new-password" />
          <div>
            <Button type="submit" variant="primary" busy={change.busy}>
              Change password
            </Button>
          </div>
        </form>
        {change.error !== undefined && !serverErrors.currentPassword && !serverErrors.newPassword && <ErrorNotice error={change.error} />}
        {done && (
          <Notice tone="ok">
            <span role="status">Password changed. Your other sessions were signed out.</span>
          </Notice>
        )}
      </Card>
    </>
  );
}
