import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, render, screen } from '@testing-library/preact';
import { PressureIndicators } from '../src/components/PressureIndicators';

afterEach(cleanup);

describe('PressureIndicators', () => {
  it('judges the figures against the thresholds the server sends', () => {
    render(
      <PressureIndicators
        showLink={false}
        pressure={{ writerQueueDepth: 300, writerQueueOverThresholdSeconds: 90, commitP99Ms: 45, advisory: false, queueDepthThreshold: 250, queueThresholdSeconds: 120, commitP99ThresholdMs: 40 }}
      />,
    );
    expect(screen.getByText('at or above 250')).toBeTruthy();
    expect(screen.getByText('above 40 ms')).toBeTruthy();
    expect(screen.getByText(/Threshold: 250 or more for 2 minutes/)).toBeTruthy();
  });

  it('shows a duration that is not whole minutes in seconds', () => {
    render(<PressureIndicators showLink={false} pressure={{ writerQueueDepth: 1, writerQueueOverThresholdSeconds: 0, commitP99Ms: 1, advisory: false, queueThresholdSeconds: 30 }} />);
    expect(screen.getByText(/or more for 30 seconds/)).toBeTruthy();
  });

  it('falls back to the default thresholds when the server does not send them', () => {
    render(<PressureIndicators showLink={false} pressure={{ writerQueueDepth: 12, writerQueueOverThresholdSeconds: 0, commitP99Ms: 9, advisory: false }} />);
    expect(screen.getByText('below 1,000')).toBeTruthy();
    expect(screen.getByText('at or below 100 ms')).toBeTruthy();
    expect(screen.getByText(/Threshold: 1,000 or more for 5 minutes/)).toBeTruthy();
  });

  it('renders nothing without figures (a backend that does not measure them)', () => {
    const { container } = render(<PressureIndicators pressure={undefined} />);
    expect(container.textContent).toBe('');
  });
});
