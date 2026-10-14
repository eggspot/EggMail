import { useState } from 'preact/hooks';
import { friendlyMessage, isCode } from '../api/errorMessages';
import { Button, TextField } from '../components/ui';
import { ThemeToggle } from '../components/Layout';
import { WarningBanner } from '../components/WarningBanner';
import { useDocumentTitle } from '../lib/hooks';
import { useApp } from '../state/app';

export default function Login() {
  useDocumentTitle('Sign in');
  const { login, signInNotice } = useApp();
  const [user, setUser] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const submit = async (e: Event) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(user.trim(), password);
    } catch (err) {
      setError(err);
      setPassword('');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div class="login-wrap">
      <WarningBanner />
      <main class="login card" id="main">
        <div class="row between">
          <h1>
            <span class="brand-egg" aria-hidden="true" /> EggMail
          </h1>
          <ThemeToggle />
        </div>
        <p class="muted">Sign in to the dashboard.</p>
        {signInNotice && (
          <div class="notice notice-warn" role="status">
            {signInNotice}
          </div>
        )}
        <form onSubmit={submit} class="stack" noValidate>
          <TextField label="User" value={user} onInput={setUser} autocomplete="username" required autoFocus />
          <TextField label="Password" type="password" value={password} onInput={setPassword} autocomplete="current-password" required />
          {error !== null && (
            <div class="notice notice-bad" role="alert">
              {isCode(error, 'unauthorized') ? 'The user name or password is not correct.' : friendlyMessage(error)}
            </div>
          )}
          <Button type="submit" variant="primary" busy={busy} disabled={!user || !password}>
            {busy ? 'Signing in...' : 'Sign in'}
          </Button>
        </form>
      </main>
    </div>
  );
}
