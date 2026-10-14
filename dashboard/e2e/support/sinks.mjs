import http from 'node:http';
import net from 'node:net';

/**
 * A minimal plaintext SMTP receiver standing in for the recipients' mail server. A recipient whose local part starts with
 * "reject" is refused with a permanent 550 (the message ends as bounced); every other message is accepted and recorded.
 */
export async function startSmtpSink() {
  const received = [];
  const server = net.createServer((socket) => {
    socket.setEncoding('latin1');
    let buffer = '';
    let inData = false;
    let current = { from: '', to: [], data: '' };
    const reply = (line) => socket.write(line + '\r\n');
    reply('220 sink.eggmail.test ESMTP e2e sink');
    socket.on('data', (chunk) => {
      buffer += chunk;
      for (;;) {
        if (inData) {
          const end = buffer.indexOf('\r\n.\r\n');
          if (end < 0) return;
          current.data = buffer.slice(0, end);
          buffer = buffer.slice(end + 5);
          inData = false;
          received.push(current);
          current = { from: '', to: [], data: '' };
          reply('250 2.0.0 queued');
          continue;
        }
        const eol = buffer.indexOf('\r\n');
        if (eol < 0) return;
        const line = buffer.slice(0, eol);
        buffer = buffer.slice(eol + 2);
        const verb = line.slice(0, 4).toUpperCase();
        if (verb === 'EHLO') {
          socket.write('250-sink.eggmail.test\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n250 SIZE 10485760\r\n');
        } else if (verb === 'HELO') reply('250 sink.eggmail.test');
        else if (verb === 'MAIL') {
          current.from = /<([^>]*)>/.exec(line)?.[1] ?? '';
          reply('250 2.1.0 ok');
        } else if (verb === 'RCPT') {
          const to = /<([^>]*)>/.exec(line)?.[1] ?? '';
          if (to.toLowerCase().startsWith('reject')) reply('550 5.1.1 user unknown (e2e sink)');
          else {
            current.to.push(to);
            reply('250 2.1.5 ok');
          }
        } else if (verb === 'DATA') {
          if (current.to.length === 0) reply('554 5.5.1 no valid recipients');
          else {
            inData = true;
            reply('354 end with <CRLF>.<CRLF>');
          }
        } else if (verb === 'RSET') {
          current = { from: '', to: [], data: '' };
          reply('250 2.0.0 ok');
        } else if (verb === 'NOOP') reply('250 2.0.0 ok');
        else if (verb === 'QUIT') {
          reply('221 2.0.0 bye');
          socket.end();
          return;
        } else reply('502 5.5.2 command not implemented');
      }
    });
    socket.on('error', () => {});
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port,
    received,
    close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); }),
  };
}

/** An HTTP receiver for webhook deliveries; it records every request (headers and body) and answers 200 unless told otherwise. */
export async function startWebhookReceiver() {
  const requests = [];
  let status = 200;
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      requests.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
      res.statusCode = status;
      res.end('ok');
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port,
    url: `http://127.0.0.1:${server.address().port}/hook`,
    requests,
    respondWith: (code) => { status = code; },
    close: () => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }),
  };
}
