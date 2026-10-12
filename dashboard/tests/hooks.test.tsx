import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/preact';
import { ErrorBoundary } from '../src/components/ErrorBoundary';
import { useAction, useApi, useCooldown, usePolling } from '../src/lib/hooks';

afterEach(() => {
  vi.useRealTimers();
});

describe('useApi', () => {
  it('loads data, exposes loading and error states and reloads on demand', async () => {
    let n = 0;
    const fn = vi.fn(async () => {
      n += 1;
      if (n === 2) throw new Error('boom');
      return `value-${n}`;
    });
    function Host() {
      const { data, error, loading, reload } = useApi(fn, []);
      return (
        <div>
          <p data-testid="state">{loading ? 'loading' : error ? `error:${(error as Error).message}` : (data as string)}</p>
          <button onClick={reload}>reload</button>
        </div>
      );
    }
    render(<Host />);
    expect(screen.getByTestId('state').textContent).toBe('loading');
    await waitFor(() => expect(screen.getByTestId('state').textContent).toBe('value-1'));
    fireEvent.click(screen.getByText('reload'));
    await waitFor(() => expect(screen.getByTestId('state').textContent).toBe('error:boom'));
    fireEvent.click(screen.getByText('reload'));
    await waitFor(() => expect(screen.getByTestId('state').textContent).toBe('value-3'));
  });

  it('refetches when dependencies change and aborts the superseded request', async () => {
    const signals: AbortSignal[] = [];
    function Host({ id }: { id: string }) {
      const { data } = useApi(async (signal) => {
        signals.push(signal);
        return id;
      }, [id]);
      return <p data-testid="v">{data}</p>;
    }
    const { rerender } = render(<Host id="a" />);
    await waitFor(() => expect(screen.getByTestId('v').textContent).toBe('a'));
    rerender(<Host id="b" />);
    await waitFor(() => expect(screen.getByTestId('v').textContent).toBe('b'));
    expect(signals).toHaveLength(2);
    expect(signals[0].aborted).toBe(true);
  });
});

describe('useAction', () => {
  it('tracks busy and error without throwing', async () => {
    function Host() {
      const act = useAction(async (fail: boolean) => {
        if (fail) throw new Error('nope');
        return 'ok';
      });
      return (
        <div>
          <button onClick={() => void act.run(true)}>fail</button>
          <button onClick={() => void act.run(false)}>pass</button>
          <p data-testid="s">{act.busy ? 'busy' : act.error ? (act.error as Error).message : 'idle'}</p>
        </div>
      );
    }
    render(<Host />);
    fireEvent.click(screen.getByText('fail'));
    await waitFor(() => expect(screen.getByTestId('s').textContent).toBe('nope'));
    fireEvent.click(screen.getByText('pass'));
    await waitFor(() => expect(screen.getByTestId('s').textContent).toBe('idle'));
  });
});

describe('useCooldown', () => {
  it('counts down in whole seconds and returns to zero', async () => {
    vi.useFakeTimers();
    function Host() {
      const { remaining, start } = useCooldown();
      return (
        <div>
          <button onClick={() => start(3)}>go</button>
          <p data-testid="r">{remaining}</p>
        </div>
      );
    }
    render(<Host />);
    expect(screen.getByTestId('r').textContent).toBe('0');
    fireEvent.click(screen.getByText('go'));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10);
    });
    expect(screen.getByTestId('r').textContent).toBe('3');
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1100);
    });
    expect(screen.getByTestId('r').textContent).toBe('2');
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2500);
    });
    expect(screen.getByTestId('r').textContent).toBe('0');
  });
});

describe('usePolling', () => {
  it('polls until the callback returns false', async () => {
    vi.useFakeTimers();
    const cb = vi.fn().mockResolvedValueOnce(true).mockResolvedValueOnce(false).mockResolvedValue(true);
    function Host() {
      usePolling(cb, 1000);
      return <p>poll</p>;
    }
    render(<Host />);
    await vi.advanceTimersByTimeAsync(5500);
    expect(cb).toHaveBeenCalledTimes(2);
  });
  it('does nothing when disabled', async () => {
    vi.useFakeTimers();
    const cb = vi.fn();
    function Host() {
      usePolling(cb, 1000, false);
      return <p>poll</p>;
    }
    render(<Host />);
    await vi.advanceTimersByTimeAsync(3000);
    expect(cb).not.toHaveBeenCalled();
  });
});

describe('ErrorBoundary', () => {
  it('shows a recoverable message instead of a blank page and resets when the key changes', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    function Bomb({ explode }: { explode: boolean }) {
      if (explode) throw new Error('kaput');
      return <p>fine</p>;
    }
    const { rerender } = render(
      <ErrorBoundary resetKey="/a">
        <Bomb explode />
      </ErrorBoundary>,
    );
    expect(screen.getByRole('alert').textContent).toContain('This page crashed');
    expect(screen.getByRole('alert').textContent).toContain('kaput');
    rerender(
      <ErrorBoundary resetKey="/b">
        <Bomb explode={false} />
      </ErrorBoundary>,
    );
    await waitFor(() => expect(screen.getByText('fine')).toBeTruthy());
  });

  it('offers a retry button', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    let explode = true;
    function Bomb() {
      if (explode) throw new Error('first');
      return <p>recovered</p>;
    }
    render(
      <ErrorBoundary>
        <Bomb />
      </ErrorBoundary>,
    );
    explode = false;
    fireEvent.click(screen.getByRole('button', { name: 'Try again' }));
    await waitFor(() => expect(screen.getByText('recovered')).toBeTruthy());
  });
});
