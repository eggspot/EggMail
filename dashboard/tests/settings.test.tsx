import { describe, expect, it } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/preact';
import Settings from '../src/pages/Settings';
import { isKeepForever, validateSetting } from '../src/components/SettingField';
import type { SettingItem } from '../src/api/types';
import { json, mockFetch, problem, renderWithApp } from './helpers';

const tenantItems: SettingItem[] = [
  { key: 'Content:StoreAttachments', value: false, type: 'boolean', description: 'Store attachments.' },
  { key: 'Content:RetentionDays', value: 7, type: 'number', description: 'Days content is kept.' },
  { key: 'Retention:MetadataDays', value: 30, type: 'number' },
  { key: 'Tls:RequireOutbound', value: 'may', type: 'enum', options: ['none', 'may', 'encrypt', 'verify'] },
  { key: 'Smtp:MaxRecipients', value: 50, type: 'number', locked: true },
];
const globalItems: SettingItem[] = [
  { key: 'Queue:MaxLifetimeDays', value: 5, type: 'number' },
  { key: 'Stats:DailyRetentionDays', value: 400, type: 'number', locked: true },
];

describe('validateSetting / isKeepForever', () => {
  it('checks numbers and the Content:RetentionDays range', () => {
    const n: SettingItem = { key: 'X', value: 1, type: 'number' };
    const c: SettingItem = { key: 'Content:RetentionDays', value: 7, type: 'number' };
    expect(validateSetting(n, '5')).toBeUndefined();
    expect(validateSetting(n, '-1')).toMatch(/whole number/);
    expect(validateSetting(n, '1.5')).toMatch(/whole number/);
    expect(validateSetting(c, '5')).toMatch(/between 6 and 30/);
    expect(validateSetting(c, '31')).toMatch(/between 6 and 30/);
    expect(validateSetting(c, '0')).toMatch(/no unlimited/);
    expect(validateSetting(c, '30')).toBeUndefined();
  });
  it('flags 0 only on keep-forever knobs', () => {
    expect(isKeepForever({ key: 'Retention:MetadataDays', value: 0, type: 'number' }, '0')).toBe(true);
    expect(isKeepForever({ key: 'Retention:MetadataDays', value: 0, type: 'number' }, 5)).toBe(false);
    expect(isKeepForever({ key: 'Content:RetentionDays', value: 0, type: 'number' }, '0')).toBe(false);
  });
});

describe('Settings page', () => {
  it('shows tenant settings with hints, a locked indicator and read-only locked fields', async () => {
    mockFetch({ 'GET /api/v1/settings': { items: tenantItems } });
    renderWithApp(<Settings />);
    expect(await screen.findByText('Content:RetentionDays')).toBeTruthy();
    expect(screen.getByText(/Days content is kept/)).toBeTruthy();
    const locked = screen.getByLabelText('Smtp:MaxRecipients') as HTMLInputElement;
    expect(locked.readOnly).toBe(true);
    expect(screen.getAllByText('Locked by deployment configuration')).toHaveLength(1);
    expect(screen.queryByText('Global settings')).toBeNull();
  });

  it('saves only the changed, unlocked values (numbers as numbers)', async () => {
    const m = mockFetch({ 'GET /api/v1/settings': { items: tenantItems }, 'PUT /api/v1/settings': { items: tenantItems.map((i) => (i.key === 'Content:RetentionDays' ? { ...i, value: 14 } : i)) } });
    renderWithApp(<Settings />);
    const save = (await screen.findByRole('button', { name: 'Save settings' })) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.input(screen.getByLabelText('Content:RetentionDays'), { target: { value: '14' } });
    fireEvent.change(screen.getByLabelText('Tls:RequireOutbound'), { target: { value: 'encrypt' } });
    expect(save.disabled).toBe(false);
    fireEvent.submit(save.closest('form')!);
    await waitFor(() => expect(m.callsTo('PUT', '/api/v1/settings')).toHaveLength(1));
    expect(m.callsTo('PUT', '/api/v1/settings')[0].body).toEqual({ values: { 'Content:RetentionDays': 14, 'Tls:RequireOutbound': 'encrypt' } });
    expect(await screen.findByText('Saved 2 settings.')).toBeTruthy();
  });

  it('rejects Content:RetentionDays outside 6-30 without calling the server', async () => {
    const m = mockFetch({ 'GET /api/v1/settings': { items: tenantItems } });
    renderWithApp(<Settings />);
    fireEvent.input(await screen.findByLabelText('Content:RetentionDays'), { target: { value: '3' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save settings' }));
    expect(await screen.findByText(/between 6 and 30 days/)).toBeTruthy();
    expect(m.callsTo('PUT', '/api/v1/settings')).toHaveLength(0);
  });

  it('warns that 0 keeps data forever on retention knobs', async () => {
    mockFetch({ 'GET /api/v1/settings': { items: tenantItems } });
    renderWithApp(<Settings />);
    fireEvent.input(await screen.findByLabelText('Retention:MetadataDays'), { target: { value: '0' } });
    expect(await screen.findByText(/0 keeps data forever; disk use grows without bound and cleanup is manual/)).toBeTruthy();
  });

  it('maps server validation errors to the field', async () => {
    mockFetch({
      'GET /api/v1/settings': { items: tenantItems },
      'PUT /api/v1/settings': () => problem(400, 'validation_failed', { errors: [{ field: 'Retention:MetadataDays', message: 'Must be at most 3650.' }] }),
    });
    renderWithApp(<Settings />);
    fireEvent.input(await screen.findByLabelText('Retention:MetadataDays'), { target: { value: '99999' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save settings' }));
    expect(await screen.findByText('Must be at most 3650.')).toBeTruthy();
  });

  it('shows global settings only to admins, with the locked indicator, and saves them separately', async () => {
    const m = mockFetch({
      'GET /api/v1/settings': { items: tenantItems },
      'GET /api/v1/admin/settings': { items: globalItems },
      'PUT /api/v1/admin/settings': () => json({ items: globalItems.map((i) => (i.key === 'Queue:MaxLifetimeDays' ? { ...i, value: 4 } : i)) }),
    });
    renderWithApp(<Settings />, { role: 'admin' });
    const heading = await screen.findByRole('heading', { name: 'Global settings' });
    const section = heading.closest('section')!;
    expect(await within(section).findByLabelText('Queue:MaxLifetimeDays')).toBeTruthy();
    expect((within(section).getByLabelText('Stats:DailyRetentionDays') as HTMLInputElement).readOnly).toBe(true);
    expect(within(section).getByText('Locked by deployment configuration')).toBeTruthy();
    fireEvent.input(within(section).getByLabelText('Queue:MaxLifetimeDays'), { target: { value: '4' } });
    fireEvent.click(within(section).getByRole('button', { name: 'Save settings' }));
    await waitFor(() => expect(m.callsTo('PUT', '/api/v1/admin/settings')).toHaveLength(1));
    expect(m.callsTo('PUT', '/api/v1/admin/settings')[0].body).toEqual({ values: { 'Queue:MaxLifetimeDays': 4 } });
    expect(m.callsTo('PUT', '/api/v1/settings')).toHaveLength(0);
  });

  it('does not request global settings for tenant users', async () => {
    const m = mockFetch({ 'GET /api/v1/settings': { items: tenantItems } });
    renderWithApp(<Settings />, { role: 'tenant' });
    await screen.findByText('Content:RetentionDays');
    expect(m.callsTo('GET', '/api/v1/admin/settings')).toHaveLength(0);
  });

  it('looks the same for every history mode', async () => {
    mockFetch({ 'GET /api/v1/settings': { items: tenantItems } });
    renderWithApp(<Settings />, { mode: 'statsonly' });
    expect(await screen.findByText('Content:RetentionDays')).toBeTruthy();
  });
});

describe('Settings page: restart hint', () => {
  it('says when a stored value only applies at the next start', async () => {
    mockFetch({
      'GET /api/v1/settings': { items: [] },
      'GET /api/v1/admin/settings': { items: [{ key: 'Retention:MetadataDays', value: 30, type: 'number', description: 'Days to keep events.', requiresRestart: true }] },
    });
    renderWithApp(<Settings />, { role: 'admin' });
    expect(await screen.findByText(/Takes effect the next time the server starts/)).toBeTruthy();
  });
});
