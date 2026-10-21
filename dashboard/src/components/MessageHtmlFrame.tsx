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
  const cleaned = removeHeadTags(html);
  return (
    '<!doctype html><html><head><meta charset="utf-8">' +
    `<meta http-equiv="Content-Security-Policy" content="${FRAME_CSP}">` +
    '<meta name="referrer" content="no-referrer">' +
    '</head><body>' +
    cleaned +
    '</body></html>'
  );
}

/**
 * Removes every <meta>, <base> and <link> tag from the message HTML, however it is written: attribute values may contain `>` inside quotes, and an unterminated tag is neutralized
 * by turning its `<` into a character reference, so no HTML parser sees a tag start there. (A meta refresh or a base inside the body would still be honored by a browser; the sandbox
 * and the policies above do not rely on it being gone, this is the layer that makes it gone.)
 *
 * One left-to-right scan, linear in the input: a regex that looks for the closing `>` from every tag start reads to the end of the input for each unterminated one, and hostile
 * mail full of `<meta ` froze the tab for seconds. Once a tag runs to the end of the input, it and every later tag start are neutralized instead of removed.
 */
export function removeHeadTags(html: string): string {
  const start = /<\s*(?:meta|base|link)(?![A-Za-z0-9-])/gi;
  let out = '';
  let from = 0;
  for (let m = start.exec(html); m !== null; m = start.exec(html)) {
    const end = tagEnd(html, m.index + m[0].length);
    if (end < 0) break;
    out += html.slice(from, m.index);
    from = end;
    start.lastIndex = end;
  }
  out += html.slice(from);
  // What is left of such a tag (an unterminated quote, a start that removing a tag joined together) cannot be matched safely: make its `<` plain text.
  return out.replace(/<(?=\s*(?:meta|base|link)(?![A-Za-z0-9-]))/gi, '&lt;');
}

/** The index just after the `>` that closes a tag whose attributes start at `i` (a `>` inside a quoted value does not close it), or -1 when the input ends first. */
function tagEnd(html: string, i: number): number {
  let quote = '';
  for (; i < html.length; i++) {
    const c = html[i];
    if (quote !== '') {
      if (c === quote) quote = '';
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (c === '>') {
      return i + 1;
    }
  }
  return -1;
}

export function MessageHtmlFrame({ html, title = 'Message HTML (sandboxed)' }: { html: string; title?: string }) {
  return (
    <div class="stack">
      <p class="muted small">Remote content, scripts, forms, links and styling are blocked. Use the Text tab if the layout looks plain.</p>
      <iframe sandbox="" referrerpolicy="no-referrer" title={title} class="html-frame" srcdoc={buildSrcDoc(html)} />
    </div>
  );
}
