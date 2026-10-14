import { useEffect, useState } from 'preact/hooks';
import { api } from '../api/endpoints';
import { isCode } from '../api/errorMessages';
import type { AttachmentInfo, MessageDetail as MessageDetailData, ResendResponse } from '../api/types';
import { EventTimeline } from '../components/EventTimeline';
import { HistoryNotRecorded } from '../components/HistoryGate';
import { MessageHtmlFrame } from '../components/MessageHtmlFrame';
import { Button, Card, Chip, ConfirmDialog, EmptyState, ErrorNotice, KeyValue, Loading, Notice, PageHeader, StatusChip, Tabs } from '../components/ui';
import { formatBytes, formatDateTime } from '../lib/format';
import { useAction, useApi, useDocumentTitle } from '../lib/hooks';
import { useApp } from '../state/app';

type TabId = 'text' | 'html' | 'attachments';

function AttachmentList({ items, rawRetained, storeAttachments }: { items: AttachmentInfo[]; rawRetained: boolean; storeAttachments: boolean }) {
  return (
    <div class="stack">
      {items.length === 0 ? (
        <p class="muted">This message has no attachments.</p>
      ) : (
        <div class="table-wrap">
          <table>
            <caption class="sr-only">Attachments</caption>
            <thead>
              <tr>
                <th scope="col">File name</th>
                <th scope="col">Type</th>
                <th scope="col" class="num">
                  Size
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((a, i) => (
                <tr key={`${a.filename}-${i}`}>
                  <td class="wrap">{a.filename}</td>
                  <td>{a.content_type ?? a.contentType ?? '-'}</td>
                  <td class="num">{a.size !== undefined ? formatBytes(a.size) : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {items.length > 0 && !rawRetained && !storeAttachments && (
        <Notice tone="info">Attachment contents were not stored (only this index is kept), so they cannot be downloaded and the message cannot be resent.</Notice>
      )}
    </div>
  );
}

function ContentTabs({ detail, text, html }: { detail: MessageDetailData; text?: string; html?: string }) {
  const { capabilities } = useApp();
  const [tab, setTab] = useState<TabId>('text');
  const tabs = [
    { id: 'text', label: 'Text' },
    { id: 'html', label: 'HTML (sandboxed)' },
    { id: 'attachments', label: `Attachments (${detail.content.attachments.length})` },
  ];
  return (
    <>
      {detail.content.truncated && (
        <Notice tone="warn" title="The stored content is cut short">
          The server keeps a limited amount of each body, and this message was larger, so the text or HTML below ends early. The delivered message itself was not changed.
        </Notice>
      )}
      <Tabs tabs={tabs} active={tab} onChange={(t) => setTab(t as TabId)} label="Message content" />
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} tabIndex={0}>
        {tab === 'text' &&
          (text ? (
            <pre class="text-view" data-testid="text-view">
              {text}
            </pre>
          ) : (
            <p class="muted">
              This message has no plain-text part.{html ? ' Open the HTML tab to see the HTML part.' : ''}
            </p>
          ))}
        {tab === 'html' &&
          (html ? <MessageHtmlFrame html={html} /> : <p class="muted">This message has no HTML part.</p>)}
        {tab === 'attachments' && (
          <AttachmentList items={detail.content.attachments} rawRetained={detail.rawRetained} storeAttachments={!!capabilities?.content.storeAttachments} />
        )}
      </div>
    </>
  );
}

function Content({ id, detail }: { id: string; detail: MessageDetailData }) {
  const c = detail.content;
  const needsFetch = c.state === 'available' && c.text === undefined && c.html === undefined;
  const [fetched, setFetched] = useState<{ text?: string; html?: string } | null>(null);
  const [expired, setExpired] = useState(false);
  const [notRecorded, setNotRecorded] = useState(false);
  const [error, setError] = useState<unknown>(undefined);

  useEffect(() => {
    if (!needsFetch) return;
    let live = true;
    api
      .messageContent(id)
      .then((r) => live && setFetched(r))
      .catch((e) => {
        if (!live) return;
        if (isCode(e, 'body_expired')) setExpired(true);
        else if (isCode(e, 'content_not_recorded')) setNotRecorded(true);
        else setError(e);
      });
    return () => {
      live = false;
    };
  }, [id, needsFetch]);

  if (c.state === 'not_recorded' || notRecorded) {
    return (
      <Notice tone="info" title="The content of this message was not recorded">
        This server does not keep message content (<code>Content:Mode=None</code>), so there is no text, HTML or attachment index to show and the message cannot be resent. The delivery events above are available.
      </Notice>
    );
  }
  if (c.state === 'body_expired' || expired) {
    return (
      <Notice tone="warn" title="The message content has expired">
        The stored subject, text and HTML are removed after the content retention period. The delivery events above are still available.
      </Notice>
    );
  }
  if (error !== undefined) return <ErrorNotice error={error} />;
  if (needsFetch && !fetched) return <Loading label="Loading content" />;
  return <ContentTabs detail={detail} text={c.text ?? fetched?.text} html={c.html ?? fetched?.html} />;
}

function ResendControl({ id, disabled }: { id: string; disabled: boolean }) {
  const [open, setOpen] = useState(false);
  const [result, setResult] = useState<ResendResponse | null>(null);
  const action = useAction(() => api.resend(id));

  const confirm = async () => {
    const r = await action.run();
    if (r) {
      setResult(r);
      setOpen(false);
    }
  };
  return (
    <>
      <Button onClick={() => { setResult(null); action.clearError(); setOpen(true); }} disabled={disabled} title={disabled ? 'There is no stored content (expired or never recorded), so the message cannot be resent' : undefined}>
        Resend
      </Button>
      {open && (
        <ConfirmDialog
          title="Resend this message?"
          confirmLabel="Resend message"
          danger={false}
          busy={action.busy}
          error={action.error}
          onConfirm={confirm}
          onCancel={() => setOpen(false)}
        >
          <p>This queues a new message with the same content for all recipients. They will receive it again.</p>
          <p class="muted small">
            If the original raw message was not retained, it is re-composed from the stored subject and body, so headers will not be byte-identical.
          </p>
        </ConfirmDialog>
      )}
      {result && (
        <div class="resend-result">
          <Notice tone="ok" title="Resend queued">
            <p>
              New message <a href={`/messages/${result.id}`}>{result.id}</a> was queued.
            </p>
            {result.recomposed && <p>It was re-composed from the stored content, so its headers are not byte-identical to the original.</p>}
          </Notice>
        </div>
      )}
    </>
  );
}

function Detail({ id }: { id: string }) {
  const detail = useApi(() => api.message(id), [id]);
  const events = useApi(() => api.messageEvents(id), [id]);
  const d = detail.data;
  useDocumentTitle(d?.subject ? `Message: ${d.subject}` : 'Message');

  if (detail.error !== undefined) {
    if (isCode(detail.error, 'message_not_found')) {
      return (
        <EmptyState title="Message not found" action={<a href="/messages">Back to messages</a>}>
          <p>There is no message with this id. It may be older than the event retention period.</p>
        </EmptyState>
      );
    }
    if (isCode(detail.error, 'history_not_recorded')) return <HistoryNotRecorded what="Message details" />;
    return <ErrorNotice error={detail.error} onRetry={detail.reload} />;
  }
  if (!d) return <Loading label="Loading message" />;

  return (
    <>
      <PageHeader
        title={d.subject || '(no subject)'}
        subtitle={<a href="/messages">Back to messages</a>}
        actions={<ResendControl id={d.id} disabled={d.content.state !== 'available'} />}
      />
      <Card title="Details">
        <KeyValue
          items={[
            ['Status', <StatusChip status={d.status} />],
            ['Received', <time dateTime={d.receivedAt}>{formatDateTime(d.receivedAt)}</time>],
            ['From', d.from],
            ['Recipients', d.recipients.join(', ') + (d.recipientCount && d.recipientCount > d.recipients.length ? ` and ${d.recipientCount - d.recipients.length} more` : '')],
            ['Size', formatBytes(d.size)],
            ['Raw message retained', d.rawRetained ? <Chip tone="ok">yes</Chip> : <Chip tone="neutral">no</Chip>],
            ['Message id', <code>{d.id}</code>],
          ]}
        />
      </Card>
      <Card title="Delivery events">
        {events.error !== undefined ? (
          <ErrorNotice error={events.error} onRetry={events.reload} />
        ) : events.data ? (
          <EventTimeline events={events.data} />
        ) : (
          <Loading label="Loading events" />
        )}
      </Card>
      <Card title="Content">
        <Content id={d.id} detail={d} />
      </Card>
    </>
  );
}

export default function MessageDetail({ id }: { id?: string }) {
  const { historyMode } = useApp();
  if (historyMode === 'statsonly') {
    return (
      <>
        <PageHeader title="Message" />
        <HistoryNotRecorded what="Message details" />
      </>
    );
  }
  if (!id) return <EmptyState title="Message not found" action={<a href="/messages">Back to messages</a>} />;
  return <Detail id={id} />;
}
