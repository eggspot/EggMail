import dgram from 'node:dgram';

// A tiny authoritative DNS server for the end-to-end tests (UDP only; the server under test is pointed at it with Dns:Servers).
// A name that was never published answers NXDOMAIN; a published name answers the asked type, or NODATA. Records are added and
// removed while the tests run, so a test can publish exactly the records a domain asks for, or a wrong value.
const TYPES = { A: 1, CNAME: 5, PTR: 12, MX: 15, TXT: 16 };

function readName(buf, offset) {
  const labels = [];
  let pos = offset;
  while (buf[pos] !== 0) {
    const len = buf[pos];
    labels.push(buf.toString('ascii', pos + 1, pos + 1 + len));
    pos += len + 1;
  }
  return { name: labels.join('.').toLowerCase(), end: pos + 1 };
}

function encodeName(name) {
  const parts = [];
  for (const label of name.split('.').filter(Boolean)) parts.push(Buffer.from([label.length]), Buffer.from(label, 'ascii'));
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

/** One resource record whose owner name is a compression pointer to the question name (offset 12). */
function rr(type, rdata) {
  const out = Buffer.alloc(12 + rdata.length);
  out.writeUInt16BE(0xc00c, 0);
  out.writeUInt16BE(type, 2);
  out.writeUInt16BE(1, 4);
  out.writeUInt32BE(1, 6); // TTL 1 s (the resolver's own minimum cache time still applies)
  out.writeUInt16BE(rdata.length, 10);
  rdata.copy(out, 12);
  return out;
}

function txtRdata(text) {
  const bytes = Buffer.from(text, 'utf8');
  const chunks = [];
  for (let i = 0; i < Math.max(bytes.length, 1); i += 255) {
    const piece = bytes.subarray(i, i + 255);
    chunks.push(Buffer.from([piece.length]), piece);
  }
  return Buffer.concat(chunks);
}

const key = (name) => name.toLowerCase().replace(/\.$/, '');

export async function startFakeDns() {
  /** @type {Map<string, { txt: string[]; cname?: string; mx: { preference: number; host: string }[]; a: string[]; ptr: string[] }>} */
  const zone = new Map();
  const entry = (name) => {
    const k = key(name);
    if (!zone.has(k)) zone.set(k, { txt: [], mx: [], a: [], ptr: [] });
    return zone.get(k);
  };
  const queries = [];
  const socket = dgram.createSocket('udp4');

  socket.on('message', (msg, remote) => {
    if (msg.length < 12) return;
    const { name, end } = readName(msg, 12);
    const qtype = msg.readUInt16BE(end);
    const question = msg.subarray(12, end + 4);
    queries.push({ name, qtype });
    const node = zone.get(name);
    const answers = [];
    let rcode = 0;
    if (!node) {
      rcode = 3;
    } else if (node.cname) {
      answers.push(rr(TYPES.CNAME, encodeName(node.cname)));
    } else if (qtype === TYPES.TXT) {
      for (const t of node.txt) answers.push(rr(TYPES.TXT, txtRdata(t)));
    } else if (qtype === TYPES.MX) {
      for (const m of node.mx) {
        const pref = Buffer.alloc(2);
        pref.writeUInt16BE(m.preference);
        answers.push(rr(TYPES.MX, Buffer.concat([pref, encodeName(m.host)])));
      }
    } else if (qtype === TYPES.A) {
      for (const ip of node.a) answers.push(rr(TYPES.A, Buffer.from(ip.split('.').map(Number))));
    } else if (qtype === TYPES.PTR) {
      for (const target of node.ptr) answers.push(rr(TYPES.PTR, encodeName(target)));
    }

    // The query's additional section may carry an EDNS0 OPT record; answer with an empty one so the client sees EDNS support.
    const hasOpt = msg.readUInt16BE(10) > 0;
    const opt = hasOpt ? Buffer.from([0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]) : Buffer.alloc(0);
    const header = Buffer.alloc(12);
    header.writeUInt16BE(msg.readUInt16BE(0), 0);
    header.writeUInt16BE(0x8400 | (msg.readUInt16BE(2) & 0x0100) | 0x0080 | rcode, 2); // QR, AA, RD copied, RA
    header.writeUInt16BE(1, 4);
    header.writeUInt16BE(answers.length, 6);
    header.writeUInt16BE(hasOpt ? 1 : 0, 10);
    socket.send(Buffer.concat([header, question, ...answers, opt]), remote.port, remote.address);
  });

  await new Promise((resolve) => socket.bind(0, '127.0.0.1', resolve));
  const port = socket.address().port;
  return {
    port,
    endpoint: `127.0.0.1:${port}`,
    queries,
    setTxt: (name, ...values) => { entry(name).txt = values; },
    setCname: (name, target) => { entry(name).cname = target; },
    setMx: (name, host, preference = 10) => { entry(name).mx = [{ preference, host }]; },
    setA: (name, ip) => { entry(name).a = [ip]; },
    setPtr: (name, target) => { entry(name).ptr = [target]; },
    remove: (name) => { zone.delete(key(name)); },
    close: () => new Promise((resolve) => socket.close(resolve)),
  };
}
