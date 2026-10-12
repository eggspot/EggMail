import { describe, expect, it } from 'vitest';
import { chunk, daysUntil, formatBytes, formatDuration, formatNumber, formatPercent, formatRelative, shortId, toIsoOrUndefined } from '../src/lib/format';

describe('format helpers', () => {
  it('formats bytes in binary units', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(2048)).toBe('2.0 KiB');
    expect(formatBytes(26214400)).toBe('25.0 MiB');
    expect(formatBytes(undefined)).toBe('-');
  });
  it('formats numbers, percentages and durations', () => {
    expect(formatNumber(1234567)).toBe('1,234,567');
    expect(formatPercent(1, 3)).toBe('33%');
    expect(formatPercent(1, 0)).toBe('-');
    expect(formatDuration(250)).toBe('250 ms');
    expect(formatDuration(1500)).toBe('1.5 s');
    expect(formatDuration(125000)).toBe('2 min 5 s');
  });
  it('formats relative times in both directions', () => {
    const now = Date.parse('2026-10-12T08:00:00Z');
    expect(formatRelative('2026-10-12T09:00:00Z', now)).toBe('in 1 hour');
    expect(formatRelative('2026-10-10T08:00:00Z', now)).toBe('2 days ago');
    expect(formatRelative('2026-10-12T08:00:01Z', now)).toBe('just now');
    expect(formatRelative(null, now)).toBe('-');
  });
  it('counts whole days until a date', () => {
    const now = Date.parse('2026-10-12T08:00:00Z');
    expect(daysUntil('2026-10-22T08:00:00Z', now)).toBe(10);
    expect(daysUntil('2026-10-11T08:00:00Z', now)).toBe(-1);
  });
  it('converts local datetimes to ISO and ignores bad input', () => {
    expect(toIsoOrUndefined('')).toBeUndefined();
    expect(toIsoOrUndefined('nope')).toBeUndefined();
    expect(toIsoOrUndefined('2026-10-12T08:00')).toMatch(/^2026-10-12T/);
  });
  it('shortens ids and chunks strings', () => {
    expect(shortId('0123456789abcdef0123456789abcdef')).toBe('01234567...cdef');
    expect(shortId('short')).toBe('short');
    expect(chunk('abcdef', 4)).toEqual(['abcd', 'ef']);
  });
});
