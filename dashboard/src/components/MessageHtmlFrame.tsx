// The ONLY place where stored message HTML is rendered. It never touches the app DOM: it goes into a
// sandboxed iframe (empty sandbox attribute = no scripts, no forms, no popups, no top navigation, unique
// origin) as `srcdoc`, wrapped in a document that carries its own strict CSP.

/**
 * CSP of the framed document: nothing loads except data: images. A srcdoc document also inherits the host page's policy
 * (`style-src 'self'`), so inline styles, ours or the message's, are blocked whatever this policy says; it states what the frame
 * itself needs and cannot be loosened by message content.
 */
export const FRAME_CSP = "default-src 'none'; img-src data:; base-uri 'none'; form-action 'none'";

/**
 * Builds the srcdoc. The CSP meta comes first in <head>; the message HTML is only ever placed inside <body>,
 * and any <meta http-equiv> or <base> it carries is dropped, so message content cannot loosen the policy
 * (additional CSP policies can only tighten) or redirect the frame with a meta refresh.
 */
export function buildSrcDoc(html: string): string {
  const cleaned = html.replace(/<meta\b[^>]*\bhttp-equiv\b[^>]*>/gi, '').replace(/<base\b[^>]*>/gi, '');
  return (
    '<!doctype html><html><head><meta charset="utf-8">' +
    `<meta http-equiv="Content-Security-Policy" content="${FRAME_CSP}">` +
    '<meta name="referrer" content="no-referrer">' +
    '</head><body>' +
    cleaned +
    '</body></html>'
  );
}

export function MessageHtmlFrame({ html, title = 'Message HTML (sandboxed)' }: { html: string; title?: string }) {
  return (
    <div class="stack">
      <p class="muted small">Remote content, scripts, forms, links and styling are blocked. Use the Text tab if the layout looks plain.</p>
      <iframe sandbox="" referrerpolicy="no-referrer" title={title} class="html-frame" srcdoc={buildSrcDoc(html)} />
    </div>
  );
}
