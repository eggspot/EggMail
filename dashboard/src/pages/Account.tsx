import { useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { fieldErrors } from '../api/errorMessages';
import { Button, Card, ErrorNotice, KeyValue, Notice, PageHeader, TextField } from '../components/ui';
import { useAction, useDocumentTitle } from '../lib/hooks';
import { useApp } from '../state/app';

import { MIN_PASSWORD, passwordProblem } from '../lib/passwords';

/** The signed-in user's own account: who they are and a password change. */
export default function Account(_props: Record<string, unknown>) {
  useDocumentTitle('Account');
  const { me, refreshMe } = useApp();
  const forced = me?.mustChangePassword === true;
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [again, setAgain] = useState('');
  const [clientErrors, setClientErrors] = useState<Record<string, string>>({});
  const [done, setDone] = useState(false);
  const [reloadNeeded, setReloadNeeded] = useState(false);

  const change = useAction(async () => {
    await api.changePassword(current, next);
    setCurrent('');
    setNext('');
    setAgain('');
    setDone(true);
    if (forced) {
      // The temporary mark is gone: the full dashboard opens. The password HAS changed, so failing to load what the dashboard needs next is not a failed change.
      try {
        await refreshMe();
      } catch {
        setReloadNeeded(true);
      }
    }
  });
  const serverErrors = fieldErrors(change.error);
  const errs = { ...serverErrors, ...clientErrors };

  const submit = async (e: Event) => {
    e.preventDefault();
    setDone(false);
    const found: Record<string, string> = {};
    if (!current) found.currentPassword = 'Enter your current password.';
    const problem = passwordProblem(next);
    if (problem) found.newPassword = problem;
    else if (next === current) found.newPassword = 'The new password must differ from the current one.';
    if (again !== next) found.again = 'The two new passwords are not the same.';
    setClientErrors(found);
    if (Object.keys(found).length) return;
    await change.run();
  };

  return (
    <>
      <PageHeader title="Account" subtitle="Your own sign-in." />
      {forced && (
        <Notice tone="warn">
          <span role="alert">
            You signed in with a temporary password (the one the server printed once in its log). Choose your own now: the rest of the dashboard opens after that.
          </span>
        </Notice>
      )}
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
        {reloadNeeded && (
          <Notice tone="warn">
            <span role="status">
              Your password was changed, but the dashboard could not load what it needs next.{' '}
              <button type="button" class="btn btn-small" onClick={() => window.location.reload()}>
                Reload the dashboard
              </button>
            </span>
          </Notice>
        )}
        {done && (
          <Notice tone="ok">
            <span role="status">Password changed. Your other sessions were signed out.</span>
          </Notice>
        )}
      </Card>
    </>
  );
}
