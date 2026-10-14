import { describe, expect, it } from 'vitest';
import { render } from '@testing-library/preact';
import { FRAME_CSP, MessageHtmlFrame, buildSrcDoc } from '../src/components/MessageHtmlFrame';

describe('buildSrcDoc', () => {
  it('puts the CSP meta first in <head> and the message only inside <body>', () => {
    const doc = buildSrcDoc('<p>hello</p>');
    expect(doc.startsWith('<!doctype html>')).toBe(true);
    const csp = doc.indexOf('http-equiv="Content-Security-Policy"');
    expect(csp).toBeGreaterThan(-1);
    expect(csp).toBeLessThan(doc.indexOf('<p>hello</p>'));
    expect(doc.indexOf('<body>')).toBeLessThan(doc.indexOf('<p>hello</p>'));
    expect(doc).toContain(`content="${FRAME_CSP}"`);
  });

  it('blocks everything except data images', () => {
    expect(FRAME_CSP).toContain("default-src 'none'");
    expect(FRAME_CSP).toContain('img-src data:');
    expect(FRAME_CSP).not.toContain('unsafe-inline');
    expect(FRAME_CSP).not.toMatch(/script-src|connect-src|frame-src/);
  });

  it('drops meta http-equiv (refresh or a competing CSP) and <base> from the message', () => {
    const hostile =
      '<meta http-equiv="refresh" content="0;url=https://evil.example/"><META HTTP-EQUIV=Content-Security-Policy content="default-src *"><base href="https://evil.example/"><p>x</p>';
    const doc = buildSrcDoc(hostile);
    expect(doc.match(/http-equiv/gi)).toHaveLength(1);
    expect(doc).not.toMatch(/refresh/i);
    expect(doc).not.toContain('<base');
    expect(doc).not.toContain('evil.example');
    expect(doc).toContain('<p>x</p>');
  });

  it('keeps an attempt to close the body and open a new head after the real CSP', () => {
    const doc = buildSrcDoc('</body></html><head><meta http-equiv="Content-Security-Policy" content="default-src *"></head><body>again');
    const first = doc.indexOf('Content-Security-Policy');
    expect(first).toBeGreaterThan(-1);
    expect(doc.indexOf('Content-Security-Policy', first + 1)).toBe(-1);
  });
});

describe('MessageHtmlFrame', () => {
  it('renders one iframe with an empty sandbox attribute and no allow-* flags', () => {
    const { container } = render(<MessageHtmlFrame html="<b>hi</b>" />);
    const frames = container.querySelectorAll('iframe');
    expect(frames).toHaveLength(1);
    const f = frames[0];
    expect(f.getAttribute('sandbox')).toBe('');
    expect(f.getAttribute('sandbox')).not.toContain('allow-');
    expect(f.getAttribute('referrerpolicy')).toBe('no-referrer');
    expect(f.getAttribute('src')).toBeNull();
    expect(f.classList.contains('html-frame')).toBe(true);
    // The markup is only reachable as an attribute string, never as elements in the app DOM.
    expect(container.querySelector('b')).toBeNull();
  });

  it('explains that remote content is blocked', () => {
    const { container } = render(<MessageHtmlFrame html="x" />);
    expect(container.textContent).toContain('Remote content, scripts, forms, links and styling are blocked');
  });
});
