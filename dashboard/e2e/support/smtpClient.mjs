import net from 'node:net';
import tls from 'node:tls';

// A small SMTP submission client for the end-to-end tests (no package: STARTTLS, implicit TLS, AUTH PLAIN, one message). It accepts any
// certificate on purpose (the first-run certificate is self-signed) and reports what the server presented, so a test can assert on it.

/** One connection read line by line; replies are collected until a final line ("250 ...", not "250-..."). */
class Connection {
  constructor(socket) {
    this.buffer = '';
    this.replies = [];
    this.waiting = null;
    this.error = null;
    this.attach(socket);
  }

  attach(socket) {
    this.socket = socket;
    socket.setEncoding('utf8');
    this.onData = (chunk) => {
      this.buffer += chunk;
      this.pump();
    };
    this.onError = (error) => {
      this.error = error;
      this.waiting?.reject(error);
    };
    socket.on('data', this.onData);
    socket.on('error', this.onError);
  }

  detach() {
    this.socket.off('data', this.onData);
    this.socket.off('error', this.onError);
    if (this.buffer.length > 0) throw new Error(`the server sent data before the TLS handshake: ${JSON.stringify(this.buffer)}`);
  }

  pump() {
    for (;;) {
      const eol = this.buffer.indexOf('\r\n');
      if (eol < 0) return;
      const line = this.buffer.slice(0, eol);
      this.buffer = this.buffer.slice(eol + 2);
      this.lines = [...(this.lines ?? []), line];
      if (/^\d{3} /.test(line) || /^\d{3}$/.test(line)) {
        const reply = { code: Number(line.slice(0, 3)), lines: this.lines };
        this.lines = [];
        this.replies.push(reply);
        this.waiting?.resolve(this.replies.shift());
        this.waiting = null;
      }
    }
  }

  reply(timeoutMs = 20_000) {
    if (this.error) return Promise.reject(this.error);
    if (this.replies.length > 0) return Promise.resolve(this.replies.shift());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timed out waiting for an SMTP reply')), timeoutMs);
      this.waiting = {
        resolve: (r) => { clearTimeout(timer); resolve(r); },
        reject: (e) => { clearTimeout(timer); reject(e); },
      };
    });
  }

  async command(line, expected) {
    this.socket.write(line + '\r\n');
    const reply = await this.reply();
    if (expected !== undefined && reply.code !== expected) throw new Error(`"${line.startsWith('AUTH') ? 'AUTH ...' : line}" -> ${reply.lines.join(' | ')} (expected ${expected})`);
    return reply;
  }
}

function describeCertificate(socket) {
  const c = socket.getPeerCertificate();
  return {
    subject: c.subject?.CN,
    issuer: c.issuer?.CN,
    subjectAltName: c.subjectaltname ?? '',
    // Node reports why the certificate does not verify (nothing is rejected here): a self-signed leaf is DEPTH_ZERO_SELF_SIGNED_CERT.
    selfSigned: socket.authorizationError === 'DEPTH_ZERO_SELF_SIGNED_CERT' || socket.authorizationError === 'SELF_SIGNED_CERT_IN_CHAIN',
    protocol: socket.getProtocol(),
    validTo: c.valid_to,
  };
}

/**
 * Connects, upgrades to TLS (`mode` "starttls" after the greeting and EHLO, or "implicit" from the first byte), authenticates with AUTH PLAIN and sends one
 * message. Resolves with `{ greeting, ehlo, certificate, accepted }`; with `send: false` it only connects and reports (for a reachability check).
 */
export async function submit({ host = '127.0.0.1', port, mode, user, password, from, to, data, send = true }) {
  const plain = mode === 'implicit' ? null : net.connect({ host, port });
  const secure = mode === 'implicit' ? tls.connect({ host, port, rejectUnauthorized: false, servername: 'mail.invalid' }) : null;
  const connection = new Connection(plain ?? secure);
  try {
    const greeting = await connection.reply();
    if (greeting.code !== 220) throw new Error(`greeting: ${greeting.lines.join(' | ')}`);
    let ehlo = await connection.command('EHLO e2e.client', 250);
    let certificate;
    if (mode === 'starttls') {
      if (!ehlo.lines.some((l) => /STARTTLS/i.test(l))) throw new Error(`STARTTLS is not offered: ${ehlo.lines.join(' | ')}`);
      await connection.command('STARTTLS', 220);
      connection.detach();
      const upgraded = tls.connect({ socket: plain, rejectUnauthorized: false, servername: 'mail.invalid' });
      await new Promise((resolve, reject) => { upgraded.once('secureConnect', resolve); upgraded.once('error', reject); });
      connection.attach(upgraded);
      certificate = describeCertificate(upgraded);
      ehlo = await connection.command('EHLO e2e.client', 250);
    } else {
      certificate = describeCertificate(secure);
    }
    if (!send) {
      await connection.command('QUIT');
      return { greeting, ehlo, certificate };
    }
    if (!ehlo.lines.some((l) => /AUTH .*PLAIN/i.test(l))) throw new Error(`AUTH PLAIN is not offered after TLS: ${ehlo.lines.join(' | ')}`);
    await connection.command('AUTH PLAIN ' + Buffer.from(`\0${user}\0${password}`).toString('base64'), 235);
    await connection.command(`MAIL FROM:<${from}>`, 250);
    for (const recipient of to) await connection.command(`RCPT TO:<${recipient}>`, 250);
    await connection.command('DATA', 354);
    const body = data.replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..');
    connection.socket.write(body + '\r\n.\r\n');
    const accepted = await connection.reply();
    if (accepted.code !== 250) throw new Error(`message refused: ${accepted.lines.join(' | ')}`);
    await connection.command('QUIT');
    return { greeting, ehlo, certificate, accepted };
  } finally {
    connection.socket.destroy();
  }
}
