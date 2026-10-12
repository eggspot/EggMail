import { Component } from 'preact';
import type { ComponentChildren } from 'preact';

interface Props {
  children: ComponentChildren;
  /** Changing this value resets the boundary (for example the route path). */
  resetKey?: string;
}

interface State {
  error: Error | null;
}

/** Global error boundary: a crashed page shows a message and a way back instead of a blank screen. */
export class ErrorBoundary extends Component<Props, State> {
  override state: State = { error: null };

  static override getDerivedStateFromError(error: unknown): State {
    return { error: error instanceof Error ? error : new Error(String(error)) };
  }

  override componentDidCatch(error: unknown) {
    // No remote reporting: the dashboard talks to the same-origin API only.
    console.error('Dashboard error', error);
  }

  override componentDidUpdate(prev: Props) {
    if (this.state.error && prev.resetKey !== this.props.resetKey) this.setState({ error: null });
  }

  override render() {
    if (!this.state.error) return this.props.children;
    return (
      <div class="notice notice-bad" role="alert">
        <h1>This page crashed</h1>
        <p>An unexpected error stopped this page from rendering. Your data is not affected.</p>
        <p class="muted small">{this.state.error.message}</p>
        <div class="row">
          <button type="button" class="btn" onClick={() => this.setState({ error: null })}>
            Try again
          </button>
          <button type="button" class="btn" onClick={() => location.reload()}>
            Reload the dashboard
          </button>
        </div>
      </div>
    );
  }
}
