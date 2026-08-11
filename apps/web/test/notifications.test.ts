import { describe, expect, it } from 'vitest';
import {
  EVENT_LABELS,
  NOTIFICATION_EVENTS,
  channelTypeLabel,
  eventLabel,
  eventsLabel,
  formatChannelRow,
  isChannelType,
  isNotificationEvent,
  isValidChannelUrl,
} from '../src/notifications.js';

describe('NOTIFICATION_EVENTS', () => {
  it('is exactly the four events the API contract fixes', () => {
    expect([...NOTIFICATION_EVENTS]).toEqual([
      'scan.completed',
      'scan.failed',
      'policy.violated',
      'schedule.failed',
    ]);
  });

  it('labels every event', () => {
    for (const event of NOTIFICATION_EVENTS) {
      expect(EVENT_LABELS[event].length).toBeGreaterThan(0);
    }
  });
});

describe('isChannelType', () => {
  it('accepts exactly the two channel types', () => {
    expect(isChannelType('webhook')).toBe(true);
    expect(isChannelType('slack')).toBe(true);
  });

  it('rejects anything else', () => {
    for (const value of ['email', 'WEBHOOK', '', undefined, null, 7, {}]) {
      expect(isChannelType(value)).toBe(false);
    }
  });
});

describe('isNotificationEvent', () => {
  it('accepts each event', () => {
    for (const event of NOTIFICATION_EVENTS) expect(isNotificationEvent(event)).toBe(true);
  });

  it('rejects anything else', () => {
    for (const value of ['scan.started', 'scan', '', undefined, null, 0]) {
      expect(isNotificationEvent(value)).toBe(false);
    }
  });
});

describe('channelTypeLabel', () => {
  it('labels each type and falls back for anything unrecognised', () => {
    expect(channelTypeLabel('webhook')).toBe('Webhook');
    expect(channelTypeLabel('slack')).toBe('Slack');
    expect(channelTypeLabel('pager')).toBe('Unknown');
    expect(channelTypeLabel(undefined)).toBe('Unknown');
  });
});

describe('eventLabel / eventsLabel', () => {
  it('labels a known event', () => {
    expect(eventLabel('policy.violated')).toBe('Policy violated');
  });

  it('shows an unknown event verbatim rather than hiding it', () => {
    // A server newer than this dashboard must not read as "no events".
    expect(eventLabel('scan.quarantined')).toBe('scan.quarantined');
  });

  it('joins a subscription list', () => {
    expect(eventsLabel(['scan.completed', 'schedule.failed'])).toBe(
      'Scan completed, Schedule failed',
    );
  });

  it('degrades an empty, missing or mistyped list to a dash', () => {
    expect(eventsLabel([])).toBe('—');
    expect(eventsLabel(undefined)).toBe('—');
    expect(eventsLabel('scan.completed')).toBe('—');
  });
});

describe('isValidChannelUrl', () => {
  it('accepts https anywhere', () => {
    expect(isValidChannelUrl('https://hooks.example.test/sentinel')).toBe(true);
    expect(isValidChannelUrl('https://example.test:8443/a/b?c=d')).toBe(true);
  });

  it('accepts plain http only for a loopback host', () => {
    expect(isValidChannelUrl('http://localhost:9000/hook')).toBe(true);
    expect(isValidChannelUrl('http://127.0.0.1:9000/hook')).toBe(true);
    expect(isValidChannelUrl('http://[::1]:9000/hook')).toBe(true);
  });

  it('rejects plain http elsewhere', () => {
    expect(isValidChannelUrl('http://example.test/hook')).toBe(false);
    // A loopback-looking hostname that is not loopback must not slip through.
    expect(isValidChannelUrl('http://localhost.example.test/hook')).toBe(false);
    expect(isValidChannelUrl('http://127.0.0.1.example.test/hook')).toBe(false);
  });

  it('rejects other schemes and non-URLs', () => {
    for (const value of [
      'file:///etc/passwd',
      'ftp://example.test/hook',
      'javascript:alert(1)',
      'hooks.example.test/sentinel',
      'not a url',
      '',
      '   ',
      undefined,
      null,
      42,
    ]) {
      expect(isValidChannelUrl(value), String(value)).toBe(false);
    }
  });
});

describe('formatChannelRow', () => {
  it('formats a complete record', () => {
    expect(
      formatChannelRow({
        id: 'c1',
        type: 'webhook',
        url: 'https://hooks.example.test/sentinel',
        events: ['scan.completed', 'policy.violated'],
        enabled: true,
        hasSecret: true,
        createdAt: '2026-08-11T09:00:00.000Z',
      }),
    ).toEqual({
      id: 'c1',
      type: 'webhook',
      typeLabel: 'Webhook',
      url: 'https://hooks.example.test/sentinel',
      events: 'Scan completed, Policy violated',
      enabled: true,
      status: 'Enabled',
      hasSecret: true,
      createdAt: '2026-08-11T09:00:00.000Z',
      lastError: '',
    });
  });

  it('marks a disabled channel and surfaces its last error', () => {
    const row = formatChannelRow({
      id: 'c2',
      type: 'slack',
      url: 'https://hooks.slack.test/services/x',
      events: ['scan.failed'],
      enabled: false,
      lastError: 'Receiver responded 503',
    });
    expect(row.enabled).toBe(false);
    expect(row.status).toBe('Disabled');
    expect(row.lastError).toBe('Receiver responded 503');
  });

  it('degrades missing or mistyped fields instead of rendering undefined', () => {
    expect(formatChannelRow({})).toEqual({
      id: '',
      type: '',
      typeLabel: 'Unknown',
      url: '—',
      events: '—',
      // Absent `enabled` reads as enabled, matching the API's default.
      enabled: true,
      status: 'Enabled',
      hasSecret: false,
      createdAt: '',
      lastError: '',
    });
    const odd = formatChannelRow({ id: 7, type: 'pager', url: 42, hasSecret: 'yes' });
    expect(odd.id).toBe('');
    expect(odd.typeLabel).toBe('Unknown');
    expect(odd.url).toBe('—');
    expect(odd.hasSecret).toBe(false);
  });

  it('never reports a secret value, only whether one is set', () => {
    // The API redacts it, but the row shape must make leaking one impossible
    // even if a server ever sent it back.
    const row = formatChannelRow({
      id: 'c3',
      type: 'webhook',
      url: 'https://hooks.example.test/sentinel',
      events: ['scan.completed'],
      hasSecret: true,
      secret: 'super-secret-EXAMPLE',
    } as Record<string, unknown>);
    expect(JSON.stringify(row)).not.toContain('super-secret-EXAMPLE');
    expect(row.hasSecret).toBe(true);
  });

  it('passes a hostile-looking url and error through verbatim', () => {
    // The view writes these with textContent, so they must arrive intact and
    // render as literal text — sanitizing here would corrupt a legitimate value
    // and would not be the thing keeping the page safe.
    const url = 'https://example.test/<img src=x onerror=alert(1)>';
    const lastError = '<script>alert(1)</script>';
    const row = formatChannelRow({ id: 'c4', type: 'webhook', url, events: [], lastError });
    expect(row.url).toBe(url);
    expect(row.lastError).toBe(lastError);
  });
});
