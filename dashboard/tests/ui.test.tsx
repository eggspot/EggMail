import { describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { useState } from 'preact/hooks';
import { Chip, ConfirmDialog, CopyButton, Dialog, EmptyState, ErrorNotice, Field, OneTimeSecret, StatusChip, Tabs, TextField, toneFor } from '../src/components/ui';
import { ApiError } from '../src/api/client';

describe('Chip and StatusChip', () => {
  it('carries the status as text, not just color', () => {
    render(<StatusChip status="temporary_failure" />);
    expect(screen.getByText('temporary failure').className).toContain('chip-warn');
  });
  it('maps domain, record and delivery statuses to tones', () => {
    expect(toneFor('verified')).toBe('ok');
    expect(toneFor('ok')).toBe('ok');
    expect(toneFor('missing')).toBe('bad');
    expect(toneFor('invalid')).toBe('bad');
    expect(toneFor('pending')).toBe('info');
    expect(toneFor('deferred')).toBe('warn');
    expect(toneFor('unknown-thing')).toBe('neutral');
  });
  it('renders custom chips', () => {
    render(<Chip tone="bad">locked</Chip>);
    expect(screen.getByText('locked').className).toContain('chip-bad');
  });
});

describe('CopyButton', () => {
  it('copies via the async clipboard API and announces it', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    render(<CopyButton text="value-123" what="record value" />);
    fireEvent.click(screen.getByRole('button', { name: 'Copy record value' }));
    await waitFor(() => expect(writeText).toHaveBeenCalledWith('value-123'));
    await waitFor(() => expect(screen.getByRole('button').textContent).toBe('Copied'));
    expect(screen.getByText('Copied to clipboard')).toBeTruthy();
  });

  it('reports a failed copy', async () => {
    Object.defineProperty(navigator, 'clipboard', { value: { writeText: vi.fn().mockRejectedValue(new Error('denied')) }, configurable: true });
    (document as unknown as { execCommand: () => boolean }).execCommand = () => false;
    render(<CopyButton text="x" />);
    fireEvent.click(screen.getByRole('button'));
    await waitFor(() => expect(screen.getByRole('button').textContent).toBe('Copy failed'));
  });
});

describe('OneTimeSecret', () => {
  it('shows the secret with a warning and a copy button, and hides it when dismissed', () => {
    function Host() {
      const [secret, setSecret] = useState<string | null>('whsec_abc123');
      return secret ? <OneTimeSecret title="Signing secret" secret={secret} onDone={() => setSecret(null)} /> : <p>done</p>;
    }
    render(<Host />);
    expect(screen.getByTestId('secret-value').textContent).toBe('whsec_abc123');
    expect(screen.getByRole('alertdialog').textContent).toMatch(/shown only once/);
    expect(screen.getByRole('button', { name: /copy secret/i })).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'I have saved it' }));
    expect(screen.queryByText('whsec_abc123')).toBeNull();
    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
  });
  it('moves focus to the secret panel', () => {
    render(<OneTimeSecret title="Key" secret="k" onDone={() => {}} />);
    expect(document.activeElement?.getAttribute('role')).toBe('alertdialog');
  });
});

describe('Dialog', () => {
  it('traps focus, closes on Escape and restores focus', () => {
    function Host() {
      const [open, setOpen] = useState(false);
      return (
        <div>
          <button onClick={() => setOpen(true)}>open</button>
          {open && (
            <Dialog title="Confirm" onClose={() => setOpen(false)}>
              <button>first</button>
              <button>last</button>
            </Dialog>
          )}
        </div>
      );
    }
    render(<Host />);
    const opener = screen.getByText('open');
    opener.focus();
    fireEvent.click(opener);
    const dialog = screen.getByRole('dialog');
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    expect(dialog.getAttribute('aria-labelledby')).toBeTruthy();
    expect(document.activeElement?.textContent).toBe('first');
    screen.getByText('last').focus();
    fireEvent.keyDown(dialog, { key: 'Tab' });
    expect(document.activeElement?.textContent).toBe('first');
    fireEvent.keyDown(dialog, { key: 'Tab', shiftKey: true });
    expect(document.activeElement?.textContent).toBe('last');
    fireEvent.keyDown(dialog, { key: 'Escape' });
    expect(screen.queryByRole('dialog')).toBeNull();
    expect(document.activeElement).toBe(opener);
  });
});

describe('ConfirmDialog', () => {
  it('requires the typed phrase before the confirm button works', () => {
    const onConfirm = vi.fn();
    render(
      <ConfirmDialog title="Delete" confirmLabel="Delete domain" requirePhrase="example.com" onConfirm={onConfirm} onCancel={() => {}}>
        <p>This cannot be undone.</p>
      </ConfirmDialog>,
    );
    const button = screen.getByRole('button', { name: 'Delete domain' }) as HTMLButtonElement;
    expect(button.disabled).toBe(true);
    fireEvent.input(screen.getByLabelText(/Type "example.com"/), { target: { value: 'example.com' } });
    expect(button.disabled).toBe(false);
    fireEvent.click(button);
    expect(onConfirm).toHaveBeenCalledOnce();
  });
  it('shows an error from the action', () => {
    render(
      <ConfirmDialog title="x" confirmLabel="Go" error={new ApiError({ status: 403, code: 'forbidden' })} onConfirm={() => {}} onCancel={() => {}}>
        body
      </ConfirmDialog>,
    );
    expect(screen.getByRole('alert').textContent).toMatch(/permission/);
  });
});

describe('Tabs', () => {
  it('has tab semantics and moves with the arrow keys', () => {
    function Host() {
      const [active, setActive] = useState('text');
      return <Tabs label="Content" active={active} onChange={setActive} tabs={[{ id: 'text', label: 'Text' }, { id: 'html', label: 'HTML' }, { id: 'att', label: 'Attachments' }]} />;
    }
    render(<Host />);
    const tabs = screen.getAllByRole('tab');
    expect(tabs[0].getAttribute('aria-selected')).toBe('true');
    expect(tabs[1].getAttribute('tabindex')).toBe('-1');
    fireEvent.keyDown(tabs[0], { key: 'ArrowRight' });
    expect(screen.getAllByRole('tab')[1].getAttribute('aria-selected')).toBe('true');
    fireEvent.keyDown(screen.getAllByRole('tab')[1], { key: 'End' });
    expect(screen.getAllByRole('tab')[2].getAttribute('aria-selected')).toBe('true');
    fireEvent.keyDown(screen.getAllByRole('tab')[2], { key: 'ArrowRight' });
    expect(screen.getAllByRole('tab')[0].getAttribute('aria-selected')).toBe('true');
  });
});

describe('forms', () => {
  it('wires label, hint and error to the control', () => {
    render(<TextField label="Domain" value="" onInput={() => {}} hint="Hostname only" error="Required" />);
    const input = screen.getByLabelText('Domain');
    expect(input.getAttribute('aria-invalid')).toBe('true');
    const described = input.getAttribute('aria-describedby')!.split(' ');
    expect(described).toHaveLength(2);
    expect(document.getElementById(described[0])?.textContent).toBe('Hostname only');
    expect(document.getElementById(described[1])?.textContent).toBe('Required');
  });
  it('Field passes ids to custom controls', () => {
    render(<Field label="Mode">{({ id }) => <select id={id}><option>a</option></select>}</Field>);
    expect(screen.getByLabelText('Mode').tagName).toBe('SELECT');
  });
});

describe('feedback components', () => {
  it('ErrorNotice shows a friendly text, the request id and a retry button', () => {
    const retry = vi.fn();
    render(<ErrorNotice error={new ApiError({ status: 503, code: 'not_ready', request_id: 'req_9' })} onRetry={retry} />);
    expect(screen.getByRole('alert').textContent).toMatch(/not ready/i);
    expect(screen.getByRole('alert').textContent).toContain('req_9');
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    expect(retry).toHaveBeenCalled();
  });
  it('EmptyState renders title, body and action', () => {
    render(<EmptyState title="Nothing here" action={<a href="/x">Add one</a>}>Explanation</EmptyState>);
    expect(screen.getByRole('heading', { name: 'Nothing here' })).toBeTruthy();
    expect(screen.getByText('Explanation')).toBeTruthy();
    expect(screen.getByRole('link', { name: 'Add one' })).toBeTruthy();
  });
});
