// pcap-parser.js -- Client-side binary parser for .pcap and .pcapng files
// Registry-based protocol dissection — add new protocols by appending to APP_PROTOCOLS
// Link types: Ethernet (1), Linux SLL (113), Raw IP (101)
// Stores raw bytes per packet for hex dump view and TCP stream reassembly

const PcapParser = (() => {

  // --- Constants ---
  const MAX_PACKETS = 2_000_000; // Safety limit: prevent memory exhaustion from huge files
  const MAX_PCAPNG_BLOCKS = 10_000_000; // Safety limit: prevent DoS from tiny-block pcapng files

  // Reusable TextDecoder instance (avoid allocating ~25 new instances per packet)
  const _utf8Decoder = new TextDecoder('utf-8', { fatal: false });

  // --- Helper utilities ---

  function formatMAC(bytes, offset) {
    const parts = [];
    for (let i = 0; i < 6; i++) {
      parts.push(bytes[offset + i].toString(16).padStart(2, '0'));
    }
    return parts.join(':');
  }

  function formatIPv4(bytes, offset) {
    return `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
  }

  function formatIPv6(bytes, offset) {
    const groups = [];
    for (let i = 0; i < 16; i += 2) {
      groups.push(((bytes[offset + i] << 8) | bytes[offset + i + 1]).toString(16));
    }
    let best = { start: -1, len: 0 };
    let cur = { start: -1, len: 0 };
    for (let i = 0; i < groups.length; i++) {
      if (groups[i] === '0') {
        if (cur.start === -1) cur.start = i;
        cur.len++;
        if (cur.len > best.len) { best.start = cur.start; best.len = cur.len; }
      } else {
        cur = { start: -1, len: 0 };
      }
    }
    let raw = groups.join(':');
    if (best.len >= 2) {
      const before = groups.slice(0, best.start).join(':');
      const after = groups.slice(best.start + best.len).join(':');
      raw = before + '::' + after;
      if (raw.startsWith(':::')) raw = '::' + raw.slice(3);
      if (raw.endsWith(':::')) raw = raw.slice(0, -3) + '::';
    }
    return raw;
  }

  function getUint32BE(bytes, offset) {
    return ((bytes[offset] << 24) >>> 0) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
  }

  function getUint16BE(bytes, offset) {
    return (bytes[offset] << 8) | bytes[offset + 1];
  }

  function tcpFlagsStr(flags) {
    const parts = [];
    if (flags.SYN) parts.push('SYN');
    if (flags.ACK) parts.push('ACK');
    if (flags.FIN) parts.push('FIN');
    if (flags.RST) parts.push('RST');
    if (flags.PSH) parts.push('PSH');
    if (flags.URG) parts.push('URG');
    return parts.join(', ');
  }

  const ICMP_TYPES = {
    0: 'Echo Reply', 3: 'Destination Unreachable', 4: 'Source Quench',
    5: 'Redirect', 8: 'Echo Request', 9: 'Router Advertisement',
    10: 'Router Solicitation', 11: 'Time Exceeded',
    12: 'Parameter Problem', 13: 'Timestamp Request', 14: 'Timestamp Reply',
  };

  // --- Link + Network + Transport layer parsers ---

  function parseEthernet(bytes, offset) {
    if (bytes.length < offset + 14) return null;
    const dstMAC = formatMAC(bytes, offset);
    const srcMAC = formatMAC(bytes, offset + 6);
    let etherType = getUint16BE(bytes, offset + 12);
    let nextOffset = offset + 14;
    if (etherType === 0x8100) {
      if (bytes.length < offset + 18) return null;
      etherType = getUint16BE(bytes, offset + 16);
      nextOffset = offset + 18;
    }
    return { dstMAC, srcMAC, etherType, nextOffset };
  }

  function parseIPv4(bytes, offset) {
    if (bytes.length < offset + 20) return null;
    const versionIHL = bytes[offset];
    const ihl = versionIHL & 0x0F;
    const ipHeaderLen = ihl * 4;
    if (bytes.length < offset + ipHeaderLen) return null;
    const totalLength = getUint16BE(bytes, offset + 2);
    const identification = getUint16BE(bytes, offset + 4);
    const flagsFragment = getUint16BE(bytes, offset + 6);
    const ttl = bytes[offset + 8];
    const protocol = bytes[offset + 9];
    const checksum = getUint16BE(bytes, offset + 10);
    const srcIP = formatIPv4(bytes, offset + 12);
    const dstIP = formatIPv4(bytes, offset + 16);
    return {
      srcIP, dstIP, protocol, totalLength, ttl, identification, flagsFragment, checksum,
      headerLen: ipHeaderLen, transportOffset: offset + ipHeaderLen,
      dscp: (bytes[offset + 1] >> 2) & 0x3F,
    };
  }

  function parseIPv6(bytes, offset) {
    if (bytes.length < offset + 40) return null;
    const payloadLength = getUint16BE(bytes, offset + 4);
    let nextHeader = bytes[offset + 6];
    const hopLimit = bytes[offset + 7];
    const srcIP = formatIPv6(bytes, offset + 8);
    const dstIP = formatIPv6(bytes, offset + 24);
    let transportOffset = offset + 40;
    const extHeaders = new Set([0, 43, 44, 60, 51, 50]);
    let iterations = 0;
    while (extHeaders.has(nextHeader) && iterations < 10) {
      if (bytes.length < transportOffset + 2) break;
      const currentHeader = nextHeader;
      const extLen = bytes[transportOffset + 1];
      nextHeader = bytes[transportOffset];
      // AH (51) uses (len + 2) * 4; all others use (len + 1) * 8
      if (currentHeader === 51) {
        transportOffset += (extLen + 2) * 4;
      } else {
        transportOffset += (extLen + 1) * 8;
      }
      iterations++;
    }
    return {
      srcIP, dstIP, protocol: nextHeader, hopLimit, payloadLength,
      headerLen: 40, transportOffset, totalLength: 40 + payloadLength,
    };
  }

  function parseARP(bytes, offset) {
    if (bytes.length < offset + 28) return null;
    const operation = getUint16BE(bytes, offset + 6);
    const senderMAC = formatMAC(bytes, offset + 8);
    const senderIP = formatIPv4(bytes, offset + 14);
    const targetMAC = formatMAC(bytes, offset + 18);
    const targetIP = formatIPv4(bytes, offset + 24);
    return { operation, senderMAC, senderIP, targetMAC, targetIP };
  }

  function parseTCPOptions(bytes, offset, optionsLen) {
    const options = { mss: null, windowScale: null, sackPermitted: false, timestamps: null };
    let pos = offset;
    const end = offset + optionsLen;
    let iterations = 0;
    while (pos < end && iterations < 40) {
      iterations++;
      const kind = bytes[pos];
      if (kind === 0) break; // End of options
      if (kind === 1) { pos++; continue; } // NOP
      if (pos + 1 >= end) break;
      const len = bytes[pos + 1];
      if (len < 2 || pos + len > end) break;
      switch (kind) {
        case 2: if (len === 4 && pos + 4 <= end) options.mss = getUint16BE(bytes, pos + 2); break;
        case 3: if (len === 3 && pos + 3 <= end) options.windowScale = bytes[pos + 2]; break;
        case 4: options.sackPermitted = true; break;
        case 8: if (len === 10 && pos + 10 <= end) options.timestamps = { tsval: getUint32BE(bytes, pos + 2), tsecr: getUint32BE(bytes, pos + 6) }; break;
      }
      pos += len;
    }
    return options;
  }

  function parseTCP(bytes, offset) {
    if (bytes.length < offset + 20) return null;
    const srcPort = getUint16BE(bytes, offset);
    const dstPort = getUint16BE(bytes, offset + 2);
    const seqNum = getUint32BE(bytes, offset + 4);
    const ackNum = getUint32BE(bytes, offset + 8);
    const dataOffset = (bytes[offset + 12] >> 4) & 0x0F;
    const tcpHeaderLen = dataOffset * 4;
    const flags = {
      FIN: !!(bytes[offset + 13] & 0x01),
      SYN: !!(bytes[offset + 13] & 0x02),
      RST: !!(bytes[offset + 13] & 0x04),
      PSH: !!(bytes[offset + 13] & 0x08),
      ACK: !!(bytes[offset + 13] & 0x10),
      URG: !!(bytes[offset + 13] & 0x20),
    };
    const windowSize = getUint16BE(bytes, offset + 14);
    const checksum = getUint16BE(bytes, offset + 16);
    // Parse TCP options (bytes after the 20-byte fixed header)
    const optionsLen = tcpHeaderLen - 20;
    const options = optionsLen > 0 && bytes.length >= offset + tcpHeaderLen ? parseTCPOptions(bytes, offset + 20, optionsLen) : null;
    return {
      srcPort, dstPort, seqNum, ackNum, flags, windowSize, checksum, options,
      headerLen: tcpHeaderLen, payloadOffset: offset + tcpHeaderLen,
    };
  }

  function parseUDP(bytes, offset) {
    if (bytes.length < offset + 8) return null;
    const srcPort = getUint16BE(bytes, offset);
    const dstPort = getUint16BE(bytes, offset + 2);
    const length = getUint16BE(bytes, offset + 4);
    return { srcPort, dstPort, length, payloadOffset: offset + 8, payloadLength: length - 8 };
  }

  function parseICMP(bytes, offset) {
    if (bytes.length < offset + 4) return null;
    const type = bytes[offset];
    const code = bytes[offset + 1];
    const description = ICMP_TYPES[type] || `Type ${type}`;
    let extra = '';
    if ((type === 0 || type === 8) && bytes.length >= offset + 8) {
      const id = getUint16BE(bytes, offset + 4);
      const seq = getUint16BE(bytes, offset + 6);
      extra = ` id=0x${id.toString(16)} seq=${seq}`;
    }
    return { type, code, description, extra };
  }

  // --- Application layer parsers ---

  function parseDNSName(bytes, offset, maxOffset) {
    const labels = [];
    let pos = offset;
    let jumped = false;
    let iterations = 0;
    const visited = new Set();
    while (pos < maxOffset && iterations < 50) {
      iterations++;
      const len = bytes[pos];
      if (len === 0) { pos++; break; }
      if ((len & 0xC0) === 0xC0) {
        if (pos + 1 >= maxOffset) break;
        const ptr = ((len & 0x3F) << 8) | bytes[pos + 1];
        // Validate pointer: must point within the DNS message and not create a cycle
        if (ptr >= maxOffset || visited.has(ptr)) break;
        visited.add(ptr);
        if (!jumped) pos += 2;
        jumped = true;
        pos = ptr;
        continue;
      }
      pos++;
      if (pos + len > maxOffset) break;
      let label = '';
      for (let i = 0; i < len; i++) label += String.fromCharCode(bytes[pos + i]);
      labels.push(label);
      pos += len;
    }
    return labels.join('.');
  }

  function parseDNS(bytes, offset, length) {
    if (length < 12) return null;
    const maxOffset = offset + length;
    const flags = getUint16BE(bytes, offset + 2);
    const isResponse = !!(flags & 0x8000);
    const qdCount = getUint16BE(bytes, offset + 4);
    const anCount = getUint16BE(bytes, offset + 6);

    let queryName = '';
    if (qdCount > 0) queryName = parseDNSName(bytes, offset + 12, maxOffset);

    let qType = '';
    let nameEnd = offset + 12;
    let it = 0;
    while (nameEnd < maxOffset && it < 50) {
      it++;
      const b = bytes[nameEnd];
      if (b === 0) { nameEnd++; break; }
      if ((b & 0xC0) === 0xC0) { nameEnd += 2; break; }
      nameEnd += b + 1;
    }
    if (nameEnd + 2 <= maxOffset) {
      const typeNum = getUint16BE(bytes, nameEnd);
      const typeMap = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 255: 'ANY' };
      qType = typeMap[typeNum] || `Type${typeNum}`;
    }

    // Parse answer records for DNS resolution mapping
    const answers = [];
    if (isResponse && anCount > 0) {
      let pos = nameEnd + 4; // skip QTYPE + QCLASS
      for (let i = 0; i < anCount && pos + 12 <= maxOffset; i++) {
        const aName = parseDNSName(bytes, pos, maxOffset);
        // Skip name
        let npos = pos;
        let nit = 0;
        while (npos < maxOffset && nit < 50) {
          nit++;
          const b = bytes[npos];
          if (b === 0) { npos++; break; }
          if ((b & 0xC0) === 0xC0) { npos += 2; break; }
          npos += b + 1;
        }
        if (npos + 10 > maxOffset) break;
        const aType = getUint16BE(bytes, npos);
        const rdLength = getUint16BE(bytes, npos + 8);
        const rdataStart = npos + 10;
        if (rdataStart + rdLength > maxOffset) break;

        if (aType === 1 && rdLength === 4) {
          // A record
          answers.push({ name: aName, type: 'A', data: formatIPv4(bytes, rdataStart) });
        } else if (aType === 28 && rdLength === 16) {
          // AAAA record
          answers.push({ name: aName, type: 'AAAA', data: formatIPv6(bytes, rdataStart) });
        } else if (aType === 5) {
          // CNAME
          answers.push({ name: aName, type: 'CNAME', data: parseDNSName(bytes, rdataStart, maxOffset) });
        }
        pos = rdataStart + rdLength;
      }
    }

    // Extract RCODE from flags
    const rcode = flags & 0x000F;
    const rcodeMap = { 0: 'NoError', 1: 'FormErr', 2: 'ServFail', 3: 'NXDomain', 5: 'Refused' };
    const rcodeStr = rcodeMap[rcode] || `RCODE${rcode}`;

    return { isResponse, qdCount, anCount, queryName, qType, answers, rcode, rcodeStr };
  }

  function parseHTTP(bytes, offset, length) {
    if (length < 4) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 200, offset + length)));
      const firstLine = str.split('\r\n')[0] || str.split('\n')[0];
      if (/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s/.test(firstLine)) {
        const parts = firstLine.split(' ');
        return { isRequest: true, method: parts[0], url: parts[1] || '', statusCode: null, firstLine };
      }
      if (/^HTTP\/\d\.\d\s\d{3}/.test(firstLine)) {
        const parts = firstLine.split(' ');
        return { isRequest: false, method: null, url: null, statusCode: parseInt(parts[1], 10), firstLine };
      }
    } catch (e) { /* not HTTP */ }
    return null;
  }

  function parseDHCP(bytes, offset, length) {
    if (length < 240) return null;
    const op = bytes[offset];           // 1=BOOTREQUEST, 2=BOOTREPLY
    const xid = getUint32BE(bytes, offset + 4);
    const ciaddr = formatIPv4(bytes, offset + 12);  // client IP
    const yiaddr = formatIPv4(bytes, offset + 16);  // "your" IP (assigned)
    const siaddr = formatIPv4(bytes, offset + 20);  // server IP
    const chaddr = formatMAC(bytes, offset + 28);   // client MAC
    // Parse DHCP options (after 236-byte fixed + 4-byte magic cookie)
    let msgType = null;
    const DHCP_TYPES = { 1: 'Discover', 2: 'Offer', 3: 'Request', 4: 'Decline', 5: 'ACK', 6: 'NAK', 7: 'Release', 8: 'Inform' };
    if (length >= 240 && getUint32BE(bytes, offset + 236) === 0x63825363) {
      let pos = offset + 240;
      const end = offset + length;
      while (pos < end && pos + 1 < end) {
        const opt = bytes[pos];
        if (opt === 255) break;        // end
        if (opt === 0) { pos++; continue; } // pad
        if (pos + 1 >= end) break;
        const olen = bytes[pos + 1];
        if (pos + 2 + olen > end) break;
        if (opt === 53 && olen >= 1) msgType = DHCP_TYPES[bytes[pos + 2]] || `Type${bytes[pos + 2]}`;
        pos += 2 + olen;
      }
    }
    return { op: op === 1 ? 'Request' : 'Reply', xid: `0x${xid.toString(16)}`, clientMAC: chaddr,
      clientIP: ciaddr, assignedIP: yiaddr, serverIP: siaddr, messageType: msgType };
  }

  function parseNTP(bytes, offset, length) {
    if (length < 48) return null;
    const li_vn_mode = bytes[offset];
    const version = (li_vn_mode >> 3) & 0x07;
    const mode = li_vn_mode & 0x07;
    if (version < 1 || version > 4 || mode === 0) return null; // basic sanity
    const stratum = bytes[offset + 1];
    const MODES = { 1: 'Symmetric Active', 2: 'Symmetric Passive', 3: 'Client', 4: 'Server', 5: 'Broadcast', 6: 'Control', 7: 'Private' };
    return { version, mode: MODES[mode] || `Mode${mode}`, stratum,
      poll: bytes[offset + 2], precision: bytes[offset + 3] };
  }

  function parseTFTP(bytes, offset, length) {
    if (length < 4) return null;
    const opcode = getUint16BE(bytes, offset);
    const OPCODES = { 1: 'Read Request', 2: 'Write Request', 3: 'Data', 4: 'Acknowledgment', 5: 'Error' };
    const opName = OPCODES[opcode];
    if (!opName) return null;
    let filename = null;
    if ((opcode === 1 || opcode === 2) && length > 2) {
      let end = offset + 2;
      while (end < offset + length && bytes[end] !== 0) end++;
      try { filename = _utf8Decoder.decode(bytes.subarray(offset + 2, end)); } catch (e) { /* ignore */ }
    }
    let blockNum = null;
    if ((opcode === 3 || opcode === 4) && length >= 4) blockNum = getUint16BE(bytes, offset + 2);
    return { opcode, opName, filename, blockNum };
  }

  function parseTLS(bytes, offset, length) {
    if (length < 5) return null;
    const contentType = bytes[offset];
    // Validate TLS record: type 20-23, version 0x0300-0x0304
    if (contentType < 20 || contentType > 23) return null;
    const major = bytes[offset + 1], minor = bytes[offset + 2];
    if (major !== 3 || minor > 4) return null;
    const recordLen = getUint16BE(bytes, offset + 3);
    const TYPES = { 20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data' };
    const typeName = TYPES[contentType] || `Type${contentType}`;
    const version = minor === 0 ? 'SSL 3.0' : `TLS 1.${minor - 1}`;
    // If handshake, parse handshake message type
    let hsType = null;
    if (contentType === 22 && length >= 6) {
      const ht = bytes[offset + 5];
      const HS_TYPES = { 1: 'ClientHello', 2: 'ServerHello', 4: 'NewSessionTicket', 11: 'Certificate', 12: 'ServerKeyExchange', 14: 'ServerHelloDone', 16: 'ClientKeyExchange' };
      hsType = HS_TYPES[ht] || `HandshakeType${ht}`;
    }
    return { contentType: typeName, version, recordLength: recordLen, handshakeType: hsType };
  }

  function parseSSH(bytes, offset, length) {
    if (length < 4) return null;
    // SSH version banner: "SSH-2.0-..." or "SSH-1.x-..."
    if (bytes[offset] === 0x53 && bytes[offset + 1] === 0x53 && bytes[offset + 2] === 0x48 && bytes[offset + 3] === 0x2D) {
      const end = Math.min(offset + length, offset + 255);
      let str = '';
      for (let i = offset; i < end; i++) {
        const c = bytes[i];
        if (c === 0x0A || c === 0x0D) break;
        str += String.fromCharCode(c);
      }
      return { type: 'banner', version: str };
    }
    // SSH binary packet: uint32 packet_length, byte padding_length, byte msg_code
    if (length >= 6) {
      const pktLen = getUint32BE(bytes, offset);
      if (pktLen > 0 && pktLen < 100000) {
        const msgCode = bytes[offset + 5];
        const MSG_TYPES = { 20: 'KEXINIT', 21: 'NEWKEYS', 30: 'KEX_DH_INIT', 31: 'KEX_DH_REPLY', 50: 'USERAUTH_REQUEST', 51: 'USERAUTH_FAILURE', 52: 'USERAUTH_SUCCESS' };
        return { type: 'packet', messageType: MSG_TYPES[msgCode] || `Msg${msgCode}`, packetLength: pktLen };
      }
    }
    return null;
  }

  function parseSMTP(bytes, offset, length) {
    if (length < 4) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 200, offset + length)));
      const line = str.split('\r\n')[0] || str.split('\n')[0];
      // Server response: "220 ...", "250 ...", "354 ...", "550 ..."
      const respMatch = line.match(/^(\d{3})([ \-])(.*)$/);
      if (respMatch) return { type: 'response', code: parseInt(respMatch[1], 10), text: respMatch[3].slice(0, 80) };
      // Client command: EHLO, HELO, MAIL FROM, RCPT TO, DATA, QUIT, AUTH, STARTTLS
      const cmdMatch = line.match(/^(EHLO|HELO|MAIL FROM|RCPT TO|DATA|QUIT|RSET|NOOP|AUTH|STARTTLS|VRFY)\b/i);
      if (cmdMatch) return { type: 'command', command: cmdMatch[1].toUpperCase(), detail: line.slice(0, 80) };
    } catch (e) { /* not SMTP */ }
    return null;
  }

  function parseFTP(bytes, offset, length) {
    if (length < 3) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 200, offset + length)));
      const line = str.split('\r\n')[0] || str.split('\n')[0];
      // Server response: "220 Welcome", "230 Login successful", "550 No such file"
      const respMatch = line.match(/^(\d{3})([ \-])(.*)$/);
      if (respMatch) return { type: 'response', code: parseInt(respMatch[1], 10), text: respMatch[3].slice(0, 80) };
      // Client command
      const cmdMatch = line.match(/^(USER|PASS|LIST|RETR|STOR|CWD|PWD|QUIT|TYPE|PASV|PORT|DELE|MKD|RMD|SYST|FEAT|OPTS|SIZE|MDTM|EPSV|EPRT)\b/i);
      if (cmdMatch) return { type: 'command', command: cmdMatch[1].toUpperCase(), detail: line.slice(0, 80) };
    } catch (e) { /* not FTP */ }
    return null;
  }

  // --- Additional Application Layer Parsers (batch 2: 93 new protocols) ---

  function parseQUIC(bytes, offset, length) {
    if (length < 5) return null;
    const firstByte = bytes[offset];
    const isLong = !!(firstByte & 0x80);
    if (isLong) {
      if (length < 7) return null;
      const version = getUint32BE(bytes, offset + 1);
      const VER = { 0x00000001: '1', 0x6b3343cf: '2', 0xff000000: 'draft', 0: 'negotiation' };
      let verStr = VER[version] || `0x${version.toString(16)}`;
      if (!VER[version] && (version & 0xff000000) === 0xff000000) verStr = `draft-${version & 0xff}`;
      const dstConnIdLen = bytes[offset + 5];
      return { form: 'Long', version: verStr, dstConnIdLen };
    }
    return { form: 'Short', version: null, dstConnIdLen: null };
  }

  function parseMDNS(bytes, offset, length) {
    if (length < 12) return null;
    const dns = parseDNS(bytes, offset, length);
    if (!dns) return null;
    dns._isMDNS = true;
    return dns;
  }

  function parseSSD(bytes, offset, length) {
    if (length < 10) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 200, offset + length)));
      const line = str.split('\r\n')[0] || '';
      if (/^(M-SEARCH|NOTIFY|HTTP\/1\.1 200)/i.test(line)) {
        const method = line.startsWith('M-SEARCH') ? 'M-SEARCH' : line.startsWith('NOTIFY') ? 'NOTIFY' : 'Response';
        const stMatch = str.match(/ST:\s*([^\r\n]+)/i) || str.match(/NT:\s*([^\r\n]+)/i);
        return { method, serviceType: stMatch ? stMatch[1].trim().slice(0, 60) : null };
      }
    } catch (e) {}
    return null;
  }

  function parseNBNS(bytes, offset, length) {
    if (length < 12) return null;
    const flags = getUint16BE(bytes, offset + 2);
    const isResponse = !!(flags & 0x8000);
    const opcode = (flags >> 11) & 0xF;
    const OPS = { 0: 'Query', 5: 'Registration', 6: 'Release', 7: 'WACK', 8: 'Refresh' };
    let name = '';
    if (length > 12) {
      const nameLen = bytes[offset + 12];
      if (nameLen > 0 && nameLen <= 32 && offset + 13 + nameLen <= offset + length) {
        const raw = [];
        for (let i = 0; i < nameLen; i += 2) {
          if (offset + 13 + i + 1 < offset + length) {
            raw.push(String.fromCharCode(((bytes[offset + 13 + i] - 0x41) << 4) | (bytes[offset + 13 + i + 1] - 0x41)));
          }
        }
        name = raw.join('').trim();
      }
    }
    return { isResponse, opcode: OPS[opcode] || `Op${opcode}`, name };
  }

  function parseLLMNR(bytes, offset, length) {
    if (length < 12) return null;
    const dns = parseDNS(bytes, offset, length);
    if (!dns) return null;
    dns._isLLMNR = true;
    return dns;
  }

  function parseSNMP(bytes, offset, length) {
    if (length < 10) return null;
    if (bytes[offset] !== 0x30) return null; // ASN.1 SEQUENCE
    let pos = offset + 1;
    // Skip length
    if (bytes[pos] & 0x80) pos += (bytes[pos] & 0x7f) + 1; else pos++;
    // Version
    if (pos + 2 >= offset + length || bytes[pos] !== 0x02) return null;
    const vLen = bytes[pos + 1];
    if (vLen !== 1) return null;
    const version = bytes[pos + 2]; // 0=v1, 1=v2c, 3=v3
    pos += 3;
    // Community string
    let community = '';
    if (pos < offset + length && bytes[pos] === 0x04) {
      const cLen = bytes[pos + 1];
      if (cLen > 0 && pos + 2 + cLen <= offset + length) {
        try { community = _utf8Decoder.decode(bytes.subarray(pos + 2, pos + 2 + cLen)); } catch (e) {}
      }
      pos += 2 + cLen;
    }
    // PDU type
    let pduType = null;
    if (pos < offset + length) {
      const tag = bytes[pos] & 0xFF;
      const PDUS = { 0xa0: 'GetRequest', 0xa1: 'GetNextRequest', 0xa2: 'GetResponse', 0xa3: 'SetRequest', 0xa4: 'Trap', 0xa5: 'GetBulkRequest', 0xa6: 'InformRequest', 0xa7: 'SNMPv2-Trap' };
      pduType = PDUS[tag] || null;
    }
    const V = { 0: 'v1', 1: 'v2c', 3: 'v3' };
    return { version: V[version] || `v${version}`, community: community.slice(0, 30), pduType };
  }

  function parseSyslog(bytes, offset, length) {
    if (length < 3) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 200, offset + length)));
      const m = str.match(/^<(\d{1,3})>/);
      if (!m) return null;
      const pri = parseInt(m[1]);
      const facility = pri >> 3;
      const severity = pri & 7;
      const SEV = ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Info', 'Debug'];
      const msg = str.slice(m[0].length).slice(0, 80);
      return { facility, severity, severityName: SEV[severity] || `Sev${severity}`, message: msg };
    } catch (e) {}
    return null;
  }

  function parseSIPMsg(bytes, offset, length) {
    if (length < 10) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 300, offset + length)));
      const line = str.split('\r\n')[0] || str.split('\n')[0];
      const reqMatch = line.match(/^(INVITE|ACK|BYE|CANCEL|REGISTER|OPTIONS|SUBSCRIBE|NOTIFY|PUBLISH|INFO|REFER|MESSAGE|UPDATE|PRACK)\s+(.+)\s+SIP\/2\.0/);
      if (reqMatch) return { type: 'request', method: reqMatch[1], uri: reqMatch[2].slice(0, 60) };
      const respMatch = line.match(/^SIP\/2\.0\s+(\d{3})\s+(.*)/);
      if (respMatch) return { type: 'response', code: parseInt(respMatch[1]), reason: respMatch[2].slice(0, 40) };
    } catch (e) {}
    return null;
  }

  function parseRTP(bytes, offset, length) {
    if (length < 12) return null;
    const v = (bytes[offset] >> 6) & 3;
    if (v !== 2) return null;
    const p = !!(bytes[offset] & 0x20);
    const cc = bytes[offset] & 0x0F;
    const m = !!(bytes[offset + 1] & 0x80);
    const pt = bytes[offset + 1] & 0x7F;
    const seq = getUint16BE(bytes, offset + 2);
    const ts = getUint32BE(bytes, offset + 4);
    const ssrc = getUint32BE(bytes, offset + 8);
    const PT_NAMES = { 0: 'PCMU', 3: 'GSM', 4: 'G723', 8: 'PCMA', 9: 'G722', 14: 'MPA', 26: 'JPEG', 31: 'H261', 32: 'MPV', 33: 'MP2T', 34: 'H263', 96: 'Dynamic', 97: 'Dynamic', 98: 'Dynamic', 99: 'Dynamic', 100: 'Dynamic', 101: 'Dynamic', 111: 'Dynamic', 127: 'Dynamic' };
    return { version: v, payloadType: pt, payloadName: PT_NAMES[pt] || (pt >= 96 ? 'Dynamic' : `PT${pt}`), seq, timestamp: ts, ssrc, marker: m };
  }

  function parseSTUN(bytes, offset, length) {
    if (length < 20) return null;
    const msgType = getUint16BE(bytes, offset);
    const msgLen = getUint16BE(bytes, offset + 2);
    const magic = getUint32BE(bytes, offset + 4);
    if (magic !== 0x2112A442) return null;
    const TYPES = { 0x0001: 'Binding Request', 0x0101: 'Binding Success', 0x0111: 'Binding Error', 0x0003: 'Allocate Request', 0x0103: 'Allocate Success', 0x0113: 'Allocate Error' };
    return { messageType: TYPES[msgType] || `0x${msgType.toString(16)}`, messageLength: msgLen };
  }

  function parseRADIUS(bytes, offset, length) {
    if (length < 20) return null;
    const code = bytes[offset];
    const id = bytes[offset + 1];
    const pktLen = getUint16BE(bytes, offset + 2);
    const CODES = { 1: 'Access-Request', 2: 'Access-Accept', 3: 'Access-Reject', 4: 'Accounting-Request', 5: 'Accounting-Response', 11: 'Access-Challenge', 12: 'Status-Server', 13: 'Status-Client' };
    return { code: CODES[code] || `Code${code}`, id, length: pktLen };
  }

  function parseNetFlow(bytes, offset, length) {
    if (length < 4) return null;
    const version = getUint16BE(bytes, offset);
    if (version !== 5 && version !== 9 && version !== 10) return null;
    const count = getUint16BE(bytes, offset + 2);
    if (version === 10) return { version: 'IPFIX', count, name: 'IPFIX' };
    return { version: `v${version}`, count, name: 'NetFlow' };
  }

  function parseVXLAN(bytes, offset, length) {
    if (length < 8) return null;
    const flags = bytes[offset];
    if ((flags & 0x08) === 0) return null; // VNI flag must be set
    const vni = (bytes[offset + 4] << 16) | (bytes[offset + 5] << 8) | bytes[offset + 6];
    return { vni, flags };
  }

  function parseISAKMP(bytes, offset, length) {
    if (length < 28) return null;
    const nextPayload = bytes[offset + 16];
    const version = bytes[offset + 17];
    const major = (version >> 4) & 0xF;
    const minor = version & 0xF;
    const exchangeType = bytes[offset + 18];
    const flags = bytes[offset + 19];
    const EX = { 0: 'None', 1: 'Base', 2: 'Identity Protection', 4: 'Aggressive', 5: 'Informational', 34: 'IKE_SA_INIT', 35: 'IKE_AUTH', 36: 'CREATE_CHILD_SA', 37: 'INFORMATIONAL' };
    return { version: `${major}.${minor}`, exchangeType: EX[exchangeType] || `Type${exchangeType}`, initiator: !!(flags & 0x08) };
  }

  function parseDTLS(bytes, offset, length) {
    if (length < 13) return null;
    const contentType = bytes[offset];
    if (contentType < 20 || contentType > 25) return null;
    const major = bytes[offset + 1], minor = bytes[offset + 2];
    if (major !== 254) return null; // DTLS uses 254.253 for 1.2, 254.255 for 1.0
    const TYPES = { 20: 'ChangeCipherSpec', 21: 'Alert', 22: 'Handshake', 23: 'Application Data', 25: 'Heartbeat' };
    const version = minor === 253 ? 'DTLS 1.2' : minor === 255 ? 'DTLS 1.0' : `DTLS (${major}.${minor})`;
    let hsType = null;
    if (contentType === 22 && length >= 25) {
      const ht = bytes[offset + 13];
      const HS = { 1: 'ClientHello', 2: 'ServerHello', 3: 'HelloVerifyRequest', 11: 'Certificate', 12: 'ServerKeyExchange', 14: 'ServerHelloDone', 16: 'ClientKeyExchange' };
      hsType = HS[ht] || `Handshake${ht}`;
    }
    return { contentType: TYPES[contentType] || `Type${contentType}`, version, handshakeType: hsType };
  }

  function parseCoAP(bytes, offset, length) {
    if (length < 4) return null;
    const v = (bytes[offset] >> 6) & 3;
    if (v !== 1) return null;
    const type = (bytes[offset] >> 4) & 3;
    const tkl = bytes[offset] & 0xF;
    const code = bytes[offset + 1];
    const msgId = getUint16BE(bytes, offset + 2);
    const TYPES = { 0: 'CON', 1: 'NON', 2: 'ACK', 3: 'RST' };
    const cClass = (code >> 5) & 7;
    const cDetail = code & 0x1F;
    const METHODS = { '0.01': 'GET', '0.02': 'POST', '0.03': 'PUT', '0.04': 'DELETE' };
    const codeStr = `${cClass}.${cDetail.toString().padStart(2, '0')}`;
    return { version: v, type: TYPES[type] || `T${type}`, code: codeStr, method: METHODS[codeStr] || codeStr, messageId: msgId };
  }

  function parseDHCPv6(bytes, offset, length) {
    if (length < 4) return null;
    const msgType = bytes[offset];
    const TYPES = { 1: 'Solicit', 2: 'Advertise', 3: 'Request', 4: 'Confirm', 5: 'Renew', 6: 'Rebind', 7: 'Reply', 8: 'Release', 9: 'Decline', 10: 'Reconfigure', 11: 'Information-Request', 12: 'Relay-Forward', 13: 'Relay-Reply' };
    return { messageType: TYPES[msgType] || `Type${msgType}` };
  }

  function parseL2TP(bytes, offset, length) {
    if (length < 6) return null;
    const flags = getUint16BE(bytes, offset);
    const isControl = !!(flags & 0x8000);
    const version = flags & 0x000F;
    if (version !== 2 && version !== 3) return null;
    return { version, isControl, type: isControl ? 'Control' : 'Data' };
  }

  function parseRIPv2(bytes, offset, length) {
    if (length < 4) return null;
    const command = bytes[offset];
    const version = bytes[offset + 1];
    if (version !== 1 && version !== 2) return null;
    const CMD = { 1: 'Request', 2: 'Response' };
    const entries = Math.floor((length - 4) / 20);
    return { command: CMD[command] || `Cmd${command}`, version, entries };
  }

  function parseWireGuard(bytes, offset, length) {
    if (length < 4) return null;
    const msgType = bytes[offset];
    const TYPES = { 1: 'Initiation', 2: 'Response', 3: 'Cookie Reply', 4: 'Transport Data' };
    if (!TYPES[msgType]) return null;
    return { messageType: TYPES[msgType] };
  }

  function parseOpenVPN(bytes, offset, length) {
    if (length < 2) return null;
    const opcode = (bytes[offset] >> 3) & 0x1F;
    const keyId = bytes[offset] & 0x07;
    const OPS = { 1: 'CONTROL_HARD_RESET_CLIENT_V1', 2: 'CONTROL_HARD_RESET_SERVER_V1', 3: 'CONTROL_SOFT_RESET_V1', 4: 'CONTROL_V1', 5: 'ACK_V1', 6: 'DATA_V1', 7: 'CONTROL_HARD_RESET_CLIENT_V2', 8: 'CONTROL_HARD_RESET_SERVER_V2', 9: 'DATA_V2' };
    if (!OPS[opcode]) return null;
    return { opcode: OPS[opcode], keyId };
  }

  // --- TCP text-protocol parsers ---

  function parseIMAP(bytes, offset, length) {
    if (length < 4) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 200, offset + length)));
      const line = str.split('\r\n')[0] || str.split('\n')[0];
      // Untagged server responses: * OK, * NO, * FLAGS, * 5 EXISTS, etc.
      if (/^\*\s+(OK|NO|BAD|BYE|PREAUTH|FLAGS|LIST|LSUB|SEARCH|STATUS|CAPABILITY|EXISTS|RECENT|EXPUNGE|FETCH|\d+\s+(EXISTS|RECENT|EXPUNGE|FETCH))\b/i.test(line))
        return { type: 'response', detail: line.slice(0, 80) };
      // Tagged responses: A001 OK, A001 NO, A001 BAD
      const tagRespMatch = line.match(/^(\S+)\s+(OK|NO|BAD)\b/i);
      if (tagRespMatch) return { type: 'response', status: tagRespMatch[2].toUpperCase(), tag: tagRespMatch[1], detail: line.slice(0, 80) };
      // Client commands: A001 LOGIN, A002 SELECT, etc.
      const tagMatch = line.match(/^(\S+)\s+(LOGIN|SELECT|EXAMINE|CREATE|DELETE|RENAME|SUBSCRIBE|LIST|LSUB|STATUS|APPEND|CHECK|CLOSE|EXPUNGE|SEARCH|FETCH|STORE|COPY|UID|CAPABILITY|NOOP|LOGOUT|IDLE|AUTHENTICATE|STARTTLS)\b/i);
      if (tagMatch) return { type: 'command', command: tagMatch[2].toUpperCase(), tag: tagMatch[1], detail: line.slice(0, 80) };
      if (/^\+\s/.test(line)) return { type: 'continuation', detail: line.slice(0, 80) };
    } catch (e) {}
    return null;
  }

  function parsePOP3(bytes, offset, length) {
    if (length < 3) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 200, offset + length)));
      const line = str.split('\r\n')[0] || str.split('\n')[0];
      if (/^\+OK\b/i.test(line)) return { type: 'response', status: '+OK', detail: line.slice(3).trim().slice(0, 60) };
      if (/^-ERR\b/i.test(line)) return { type: 'response', status: '-ERR', detail: line.slice(4).trim().slice(0, 60) };
      const cmdMatch = line.match(/^(USER|PASS|STAT|LIST|RETR|DELE|NOOP|QUIT|RSET|TOP|UIDL|APOP|AUTH|STLS|CAPA)\b/i);
      if (cmdMatch) return { type: 'command', command: cmdMatch[1].toUpperCase(), detail: line.slice(0, 80) };
    } catch (e) {}
    return null;
  }

  function parseSMB(bytes, offset, length) {
    if (length < 4) return null;
    // SMB1: \xFFSMB, SMB2: \xFESMB
    if (bytes[offset] === 0xFF && bytes[offset + 1] === 0x53 && bytes[offset + 2] === 0x4D && bytes[offset + 3] === 0x42) {
      if (length < 33) return null;
      const cmd = bytes[offset + 4];
      const CMDS = { 0x72: 'Negotiate', 0x73: 'Session Setup', 0x74: 'Logoff', 0x75: 'Tree Connect', 0x71: 'Tree Disconnect', 0x32: 'Transaction2', 0x25: 'Transaction', 0x2e: 'Read', 0x2f: 'Write', 0x00: 'Create Directory', 0x06: 'Delete', 0xa2: 'NT Create' };
      return { version: 1, command: CMDS[cmd] || `Cmd0x${cmd.toString(16)}` };
    }
    if (bytes[offset] === 0xFE && bytes[offset + 1] === 0x53 && bytes[offset + 2] === 0x4D && bytes[offset + 3] === 0x42) {
      if (length < 64) return null;
      const cmd = getUint16BE(bytes, offset + 12);
      const CMDS2 = { 0: 'Negotiate', 1: 'Session Setup', 2: 'Logoff', 3: 'Tree Connect', 4: 'Tree Disconnect', 5: 'Create', 6: 'Close', 7: 'Flush', 8: 'Read', 9: 'Write', 10: 'Lock', 11: 'IOCTL', 12: 'Cancel', 13: 'Echo', 14: 'Query Directory', 16: 'Query Info', 17: 'Set Info', 18: 'Oplock Break' };
      return { version: 2, command: CMDS2[cmd] || `Cmd${cmd}` };
    }
    return null;
  }

  function parseRDP(bytes, offset, length) {
    if (length < 4) return null;
    // TPKT header: version=3, reserved=0
    if (bytes[offset] === 3 && bytes[offset + 1] === 0) {
      const tpktLen = getUint16BE(bytes, offset + 2);
      if (length >= 7) {
        const cotp = bytes[offset + 5]; // COTP PDU type
        const COTP = { 0xe0: 'Connection Request', 0xd0: 'Connection Confirm', 0xf0: 'Data', 0x80: 'Disconnect Request' };
        return { tpktLength: tpktLen, pduType: COTP[cotp] || `PDU0x${cotp.toString(16)}` };
      }
      return { tpktLength: tpktLen, pduType: 'TPKT' };
    }
    return null;
  }

  function parseLDAP(bytes, offset, length) {
    if (length < 6) return null;
    if (bytes[offset] !== 0x30) return null; // ASN.1 SEQUENCE
    let pos = offset + 1;
    if (bytes[pos] & 0x80) pos += (bytes[pos] & 0x7f) + 1; else pos++;
    // Message ID
    if (pos >= offset + length || bytes[pos] !== 0x02) return null;
    pos += 2 + bytes[pos + 1];
    if (pos >= offset + length) return null;
    const tag = bytes[pos] & 0xFF;
    const TAGS = { 0x60: 'BindRequest', 0x61: 'BindResponse', 0x42: 'UnbindRequest', 0x63: 'SearchRequest', 0x64: 'SearchResultEntry', 0x65: 'SearchResultDone', 0x66: 'ModifyRequest', 0x67: 'ModifyResponse', 0x68: 'AddRequest', 0x69: 'AddResponse', 0x4a: 'DeleteRequest', 0x6b: 'DeleteResponse', 0x6c: 'ModifyDNRequest', 0x6d: 'ModifyDNResponse', 0x77: 'ExtendedRequest', 0x78: 'ExtendedResponse' };
    return { operation: TAGS[tag] || `Op0x${tag.toString(16)}` };
  }

  function parseKerberos(bytes, offset, length) {
    if (length < 10) return null;
    // Kerberos uses ASN.1; first byte is application tag 0x6x
    const tag = bytes[offset];
    if ((tag & 0xE0) !== 0x60) return null;
    const msgType = tag & 0x1F;
    const TYPES = { 10: 'AS-REQ', 11: 'AS-REP', 12: 'TGS-REQ', 13: 'TGS-REP', 14: 'AP-REQ', 15: 'AP-REP', 20: 'KRB-SAFE', 21: 'KRB-PRIV', 22: 'KRB-CRED', 25: 'KRB-ERROR' };
    return { messageType: TYPES[msgType] || `Type${msgType}` };
  }

  function parseRTSP(bytes, offset, length) {
    if (length < 8) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 200, offset + length)));
      const line = str.split('\r\n')[0] || str.split('\n')[0];
      const reqMatch = line.match(/^(OPTIONS|DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN|ANNOUNCE|RECORD|GET_PARAMETER|SET_PARAMETER)\s+(.+)\s+RTSP\/1\.0/);
      if (reqMatch) return { type: 'request', method: reqMatch[1], url: reqMatch[2].slice(0, 60) };
      if (/^RTSP\/1\.0\s+(\d{3})/.test(line)) {
        const code = parseInt(line.match(/\d{3}/)[0]);
        return { type: 'response', statusCode: code };
      }
    } catch (e) {}
    return null;
  }

  function parseMySQL(bytes, offset, length) {
    if (length < 5) return null;
    const pktLen = bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16);
    const seqId = bytes[offset + 3];
    const cmd = bytes[offset + 4];
    if (pktLen < 1 || pktLen > 0xFFFFFF) return null;
    if (seqId === 0 && cmd === 0x0a) return { type: 'Greeting', seqId };
    const CMDS = { 0x01: 'Quit', 0x02: 'InitDB', 0x03: 'Query', 0x04: 'FieldList', 0x05: 'CreateDB', 0x06: 'DropDB', 0x0e: 'Ping', 0x16: 'StmtPrepare', 0x17: 'StmtExecute', 0x19: 'StmtClose', 0x1c: 'StmtReset' };
    if (seqId === 0 && CMDS[cmd]) return { type: CMDS[cmd], seqId };
    if (cmd === 0x00) return { type: 'OK', seqId };
    if (cmd === 0xFF) return { type: 'Error', seqId };
    return { type: `Cmd0x${cmd.toString(16)}`, seqId };
  }

  function parsePostgreSQL(bytes, offset, length) {
    if (length < 5) return null;
    const tag = bytes[offset];
    const msgLen = getUint32BE(bytes, offset + 1);
    // Note: 0x44='D' is DataRow (server) or Describe (client); 0x45='E' is ErrorResponse (server) or Execute (client)
    // In a packet analyzer we can't distinguish direction, so we use the server-side interpretation (more common)
    const TAGS = { 0x52: 'Authentication', 0x4b: 'BackendKeyData', 0x5a: 'ReadyForQuery', 0x54: 'RowDescription', 0x44: 'DataRow/Describe', 0x43: 'CommandComplete', 0x45: 'ErrorResponse/Execute', 0x4e: 'NoticeResponse', 0x51: 'Query', 0x50: 'Parse', 0x42: 'Bind', 0x53: 'ParameterStatus/Sync', 0x48: 'Flush', 0x70: 'PasswordMessage', 0x58: 'Terminate', 0x64: 'CopyData', 0x63: 'CopyDone', 0x66: 'CopyFail' };
    const name = TAGS[tag];
    if (!name && tag !== 0) return null;
    // Startup message (no type byte, starts with length then version 196608 = 3.0)
    if (!name && length >= 8) {
      const startLen = getUint32BE(bytes, offset);
      const ver = getUint32BE(bytes, offset + 4);
      if (ver === 196608) return { type: 'StartupMessage', version: '3.0' };
      if (ver === 80877103) return { type: 'SSLRequest' };
      return null;
    }
    return { type: name || `Tag${String.fromCharCode(tag)}`, msgLength: msgLen };
  }

  function parseRedis(bytes, offset, length) {
    if (length < 3) return null;
    const first = bytes[offset];
    // RESP protocol: +, -, :, $, *
    if (first !== 0x2B && first !== 0x2D && first !== 0x3A && first !== 0x24 && first !== 0x2A) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 100, offset + length)));
      const line = str.split('\r\n')[0] || '';
      const TYPES = { '+': 'SimpleString', '-': 'Error', ':': 'Integer', '$': 'BulkString', '*': 'Array' };
      const type = TYPES[String.fromCharCode(first)];
      if (first === 0x2A) {
        const count = parseInt(line.slice(1));
        if (isNaN(count)) return null;
        // Try to extract first command
        const parts = str.split('\r\n');
        let cmd = '';
        if (parts.length >= 4 && parts[2]) cmd = parts[2].toUpperCase();
        return { type, arrayCount: count, command: cmd.slice(0, 20) || null };
      }
      return { type, value: line.slice(1).slice(0, 40) };
    } catch (e) {}
    return null;
  }

  function parseMongoDB(bytes, offset, length) {
    if (length < 16) return null;
    const msgLen = bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
    if (msgLen < 16 || msgLen > 48000000) return null;
    const opCode = bytes[offset + 12] | (bytes[offset + 13] << 8) | (bytes[offset + 14] << 16) | (bytes[offset + 15] << 24);
    const OPS = { 1: 'OP_REPLY', 2001: 'OP_UPDATE', 2002: 'OP_INSERT', 2004: 'OP_QUERY', 2005: 'OP_GET_MORE', 2006: 'OP_DELETE', 2007: 'OP_KILL_CURSORS', 2012: 'OP_COMPRESSED', 2013: 'OP_MSG' };
    if (!OPS[opCode]) return null;
    return { opCode: OPS[opCode], messageLength: msgLen };
  }

  function parseMemcached(bytes, offset, length) {
    if (length < 3) return null;
    // Binary protocol: magic 0x80 (request) or 0x81 (response)
    if (bytes[offset] === 0x80 || bytes[offset] === 0x81) {
      if (length < 24) return null;
      const isReq = bytes[offset] === 0x80;
      const opcode = bytes[offset + 1];
      const OPS = { 0x00: 'Get', 0x01: 'Set', 0x02: 'Add', 0x03: 'Replace', 0x04: 'Delete', 0x05: 'Increment', 0x06: 'Decrement', 0x07: 'Quit', 0x08: 'Flush', 0x09: 'GetQ', 0x0a: 'Noop', 0x0b: 'Version', 0x0e: 'Append', 0x10: 'Stat' };
      return { protocol: 'binary', type: isReq ? 'request' : 'response', command: OPS[opcode] || `Op0x${opcode.toString(16)}` };
    }
    // Text protocol
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 100, offset + length)));
      const line = str.split('\r\n')[0] || '';
      const cmdMatch = line.match(/^(get|gets|set|add|replace|append|prepend|cas|delete|incr|decr|stats|flush_all|version|quit|touch)\b/i);
      if (cmdMatch) return { protocol: 'text', type: 'command', command: cmdMatch[1].toLowerCase() };
      if (/^(VALUE|END|STORED|NOT_STORED|EXISTS|NOT_FOUND|DELETED|ERROR|CLIENT_ERROR|SERVER_ERROR|VERSION|OK)\b/.test(line))
        return { protocol: 'text', type: 'response', command: line.split(' ')[0] };
    } catch (e) {}
    return null;
  }

  function parseMQTT(bytes, offset, length) {
    if (length < 2) return null;
    const type = (bytes[offset] >> 4) & 0x0F;
    if (type < 1 || type > 15) return null;
    const TYPES = { 1: 'CONNECT', 2: 'CONNACK', 3: 'PUBLISH', 4: 'PUBACK', 5: 'PUBREC', 6: 'PUBREL', 7: 'PUBCOMP', 8: 'SUBSCRIBE', 9: 'SUBACK', 10: 'UNSUBSCRIBE', 11: 'UNSUBACK', 12: 'PINGREQ', 13: 'PINGRESP', 14: 'DISCONNECT' };
    // Validate: CONNECT must have specific remaining length structure
    if (type === 1 && length >= 10) {
      // Check for MQTT magic string at correct offset
      let pos = offset + 1;
      let remLen = 0, mult = 1;
      for (let i = 0; i < 4 && pos < offset + length; i++) {
        remLen += (bytes[pos] & 0x7F) * mult;
        if (!(bytes[pos] & 0x80)) { pos++; break; }
        mult *= 128; pos++;
      }
      if (pos + 6 <= offset + length) {
        const protoNameLen = getUint16BE(bytes, pos);
        if (protoNameLen === 4 && pos + 2 + 4 <= offset + length) {
          try {
            const name = _utf8Decoder.decode(bytes.subarray(pos + 2, pos + 6));
            if (name !== 'MQTT' && name !== 'MQIs') return null;
          } catch (e) { return null; }
        }
      }
    }
    return { messageType: TYPES[type] || `Type${type}`, dup: !!(bytes[offset] & 0x08), qos: (bytes[offset] >> 1) & 3, retain: !!(bytes[offset] & 0x01) };
  }

  function parseAMQP(bytes, offset, length) {
    if (length < 8) return null;
    // AMQP 0-9-1: starts with "AMQP" for protocol header
    if (bytes[offset] === 0x41 && bytes[offset + 1] === 0x4D && bytes[offset + 2] === 0x51 && bytes[offset + 3] === 0x50) {
      return { type: 'ProtocolHeader', version: `${bytes[offset + 5]}.${bytes[offset + 6]}.${bytes[offset + 7]}` };
    }
    // AMQP frame: type byte, channel uint16, size uint32
    const frameType = bytes[offset];
    const FT = { 1: 'Method', 2: 'Header', 3: 'Body', 8: 'Heartbeat' };
    if (!FT[frameType]) return null;
    const channel = getUint16BE(bytes, offset + 1);
    const size = getUint32BE(bytes, offset + 3);
    return { type: FT[frameType], channel, size };
  }

  function parseBGP(bytes, offset, length) {
    if (length < 19) return null;
    // 16-byte marker (all 0xFF)
    for (let i = 0; i < 16; i++) { if (bytes[offset + i] !== 0xFF) return null; }
    const msgLen = getUint16BE(bytes, offset + 16);
    const type = bytes[offset + 18];
    const TYPES = { 1: 'OPEN', 2: 'UPDATE', 3: 'NOTIFICATION', 4: 'KEEPALIVE', 5: 'ROUTE-REFRESH' };
    return { messageType: TYPES[type] || `Type${type}`, messageLength: msgLen };
  }

  function parseTelnet(bytes, offset, length) {
    if (length < 2) return null;
    // IAC commands
    if (bytes[offset] === 0xFF && length >= 3) {
      const cmd = bytes[offset + 1];
      const CMDS = { 251: 'WILL', 252: 'WONT', 253: 'DO', 254: 'DONT', 250: 'SB', 240: 'SE', 241: 'NOP', 246: 'AYT' };
      const opt = bytes[offset + 2];
      const OPTS = { 0: 'BinaryTransmission', 1: 'Echo', 3: 'SuppressGoAhead', 5: 'Status', 24: 'TerminalType', 31: 'WindowSize', 34: 'Linemode', 39: 'NewEnviron' };
      return { type: 'negotiation', command: CMDS[cmd] || `Cmd${cmd}`, option: OPTS[opt] || `Opt${opt}` };
    }
    // Text data
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 60, offset + length)));
      if (/[^\x00-\x1F\x7F-\xFF]/.test(str)) return { type: 'data', preview: str.replace(/[\x00-\x1F\x7F-\xFF]/g, '.').slice(0, 40) };
    } catch (e) {}
    return null;
  }

  function parseIRC(bytes, offset, length) {
    if (length < 4) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 200, offset + length)));
      const line = str.split('\r\n')[0] || str.split('\n')[0];
      const prefixMatch = line.match(/^:(\S+)\s+(\S+)\s*(.*)/);
      if (prefixMatch) return { type: 'message', prefix: prefixMatch[1].slice(0, 30), command: prefixMatch[2], params: prefixMatch[3].slice(0, 50) };
      const cmdMatch = line.match(/^(NICK|USER|JOIN|PART|QUIT|PRIVMSG|NOTICE|PING|PONG|MODE|KICK|TOPIC|WHO|WHOIS|LIST|CAP|PASS)\b/i);
      if (cmdMatch) return { type: 'command', command: cmdMatch[1].toUpperCase(), params: line.slice(cmdMatch[1].length).trim().slice(0, 50) };
      if (/^\d{3}\s/.test(line)) return { type: 'numeric', code: line.slice(0, 3), detail: line.slice(4).slice(0, 50) };
    } catch (e) {}
    return null;
  }

  function parseXMPP(bytes, offset, length) {
    if (length < 5) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 300, offset + length)));
      if (/<\?xml/.test(str) && /jabber|xmpp/i.test(str)) return { type: 'stream', element: 'xml-declaration' };
      if (/<stream:stream/.test(str)) return { type: 'stream', element: 'stream:stream' };
      const tagMatch = str.match(/<(message|presence|iq)\b([^>]*)>/);
      if (tagMatch) {
        const typeMatch = tagMatch[2].match(/type=['"]([^'"]+)['"]/);
        return { type: 'stanza', element: tagMatch[1], stanzaType: typeMatch ? typeMatch[1] : null };
      }
      // SASL/auth elements
      if (/<(auth|response|challenge|success|failure|abort)\b/i.test(str)) {
        const authMatch = str.match(/<(auth|response|challenge|success|failure|abort)\b/i);
        return { type: 'sasl', element: authMatch[1].toLowerCase() };
      }
      // Features and other XMPP elements
      if (/<(stream:features|starttls|mechanisms|bind|session)\b/i.test(str)) {
        const featMatch = str.match(/<(stream:features|starttls|mechanisms|bind|session)\b/i);
        return { type: 'features', element: featMatch[1] };
      }
    } catch (e) {}
    return null;
  }

  function parseSOCKS(bytes, offset, length) {
    if (length < 3) return null;
    const ver = bytes[offset];
    if (ver === 5) {
      if (bytes[offset + 1] <= 10 && length >= 2 + bytes[offset + 1])
        return { version: 5, type: 'AuthMethods', methodCount: bytes[offset + 1] };
      const cmd = bytes[offset + 1];
      const CMDS = { 1: 'Connect', 2: 'Bind', 3: 'UDP Associate' };
      if (CMDS[cmd] && bytes[offset + 2] === 0) return { version: 5, type: CMDS[cmd] };
      if (cmd === 0) return { version: 5, type: 'AuthSuccess' };
    }
    if (ver === 4 && (bytes[offset + 1] === 1 || bytes[offset + 1] === 2)) {
      return { version: 4, type: bytes[offset + 1] === 1 ? 'Connect' : 'Bind' };
    }
    return null;
  }

  function parseModbus(bytes, offset, length) {
    if (length < 8) return null;
    // Modbus/TCP: transaction ID (2), protocol ID (2, must be 0), length (2), unit ID (1), function code (1)
    const protoId = getUint16BE(bytes, offset + 2);
    if (protoId !== 0) return null;
    const mbLen = getUint16BE(bytes, offset + 4);
    const unitId = bytes[offset + 6];
    const fc = bytes[offset + 7];
    const isException = !!(fc & 0x80);
    const funcCode = fc & 0x7F;
    const FCS = { 1: 'Read Coils', 2: 'Read Discrete Inputs', 3: 'Read Holding Registers', 4: 'Read Input Registers', 5: 'Write Single Coil', 6: 'Write Single Register', 15: 'Write Multiple Coils', 16: 'Write Multiple Registers', 43: 'Read Device ID' };
    return { transactionId: getUint16BE(bytes, offset), unitId, functionCode: funcCode, functionName: FCS[funcCode] || `FC${funcCode}`, isException };
  }

  function parseDNP3(bytes, offset, length) {
    if (length < 10) return null;
    // DNP3 over TCP: start bytes 0x0564
    if (bytes[offset] !== 0x05 || bytes[offset + 1] !== 0x64) return null;
    const len = bytes[offset + 2];
    const ctrl = bytes[offset + 3];
    const dst = getUint16BE(bytes, offset + 4);
    const src = getUint16BE(bytes, offset + 6);
    const dir = (ctrl & 0x80) ? 'Master→Outstation' : 'Outstation→Master';
    const FC = { 0: 'Confirm', 1: 'Read', 2: 'Write', 3: 'Select', 4: 'Operate', 129: 'Response', 130: 'Unsolicited Response' };
    const fc = ctrl & 0x0F;
    return { direction: dir, src, dst, functionCode: FC[fc] || `FC${fc}`, length: len };
  }

  function parseEtherNetIP(bytes, offset, length) {
    if (length < 24) return null;
    const cmd = getUint16BE(bytes, offset);
    const cmdLen = getUint16BE(bytes, offset + 2);
    const CMDS = { 0x0001: 'ListServices', 0x0004: 'ListIdentity', 0x0063: 'ListInterfaces', 0x0065: 'RegisterSession', 0x0066: 'UnregisterSession', 0x006F: 'SendRRData', 0x0070: 'SendUnitData' };
    if (!CMDS[cmd]) return null;
    return { command: CMDS[cmd], dataLength: cmdLen };
  }

  function parseS7comm(bytes, offset, length) {
    // S7comm runs over TPKT (4 bytes) + COTP (variable), then S7comm starts with 0x32
    if (length < 10) return null;
    let pos = offset;
    // Skip TPKT header: version(3), reserved, length(2)
    if (bytes[pos] === 0x03 && bytes[pos + 1] === 0x00) {
      const tpktLen = getUint16BE(bytes, pos + 2);
      pos += 4; // skip TPKT header
      // Skip COTP header: length byte + data
      if (pos < offset + length) {
        const cotpLen = bytes[pos]; // COTP header length (not including the length byte itself)
        pos += 1 + cotpLen;
      }
    }
    // Now check for S7comm magic byte
    if (pos >= offset + length || bytes[pos] !== 0x32) return null;
    if (offset + length - pos < 8) return null;
    const msgType = bytes[pos + 1];
    const TYPES = { 0x01: 'Job', 0x02: 'Ack', 0x03: 'Ack-Data', 0x07: 'Userdata' };
    const funcCode = pos + 8 < offset + length ? bytes[pos + 8] : 0;
    const FCS = { 0x04: 'Read Var', 0x05: 'Write Var', 0xf0: 'Setup Communication', 0x00: 'CPU Services' };
    return { messageType: TYPES[msgType] || `Type${msgType}`, functionCode: FCS[funcCode] || `FC0x${funcCode.toString(16)}` };
  }

  function parseBACnet(bytes, offset, length) {
    if (length < 4) return null;
    const type = bytes[offset];
    if (type !== 0x81) return null; // BACnet/IP (BVLL type)
    const func = bytes[offset + 1];
    const bvllLen = getUint16BE(bytes, offset + 2);
    const FUNCS = { 0x00: 'BVLC-Result', 0x01: 'Write-BDT', 0x02: 'Read-BDT', 0x03: 'Read-BDT-Ack', 0x04: 'Forwarded-NPDU', 0x05: 'Register-FD', 0x0a: 'Original-Unicast', 0x0b: 'Original-Broadcast' };
    return { function: FUNCS[func] || `Func0x${func.toString(16)}`, length: bvllLen };
  }

  // --- Batch 3: 17 additional protocols to reach 100 ---

  function parseDICOM(bytes, offset, length) {
    if (length < 10) return null;
    const pduType = bytes[offset];
    const pduLen = getUint32BE(bytes, offset + 2);
    const TYPES = { 0x01: 'A-ASSOCIATE-RQ', 0x02: 'A-ASSOCIATE-AC', 0x03: 'A-ASSOCIATE-RJ', 0x04: 'P-DATA-TF', 0x05: 'A-RELEASE-RQ', 0x06: 'A-RELEASE-RP', 0x07: 'A-ABORT' };
    if (!TYPES[pduType]) return null;
    return { pduType: TYPES[pduType], pduLength: pduLen };
  }

  function parseHL7(bytes, offset, length) {
    if (length < 4) return null;
    // HL7 MLLP: starts with 0x0B, ends with 0x1C 0x0D
    // Or check for MSH| segment
    if (bytes[offset] === 0x0B) {
      if (length >= 7 && bytes[offset + 1] === 0x4D && bytes[offset + 2] === 0x53 && bytes[offset + 3] === 0x48)
        return { type: 'MLLP', segment: 'MSH' };
      return { type: 'MLLP', segment: 'Unknown' };
    }
    if (bytes[offset] === 0x4D && bytes[offset + 1] === 0x53 && bytes[offset + 2] === 0x48 && bytes[offset + 3] === 0x7C)
      return { type: 'Raw', segment: 'MSH' };
    return null;
  }

  function parseRTCP(bytes, offset, length) {
    if (length < 8) return null;
    const v = (bytes[offset] >> 6) & 3;
    if (v !== 2) return null;
    const pt = bytes[offset + 1];
    const TYPES = { 200: 'SR', 201: 'RR', 202: 'SDES', 203: 'BYE', 204: 'APP', 205: 'RTPFB', 206: 'PSFB', 207: 'XR' };
    if (!TYPES[pt]) return null;
    const pktLen = getUint16BE(bytes, offset + 2);
    return { payloadType: TYPES[pt], length: pktLen };
  }

  function parseHSRP(bytes, offset, length) {
    if (length < 20) return null;
    const version = bytes[offset];
    const opcode = bytes[offset + 1];
    const state = bytes[offset + 2];
    const group = bytes[offset + 5];
    const priority = bytes[offset + 6];
    const OPS = { 0: 'Hello', 1: 'Coup', 2: 'Resign' };
    const STATES = { 0: 'Initial', 1: 'Learn', 2: 'Listen', 4: 'Speak', 8: 'Standby', 16: 'Active' };
    return { version, opcode: OPS[opcode] || `Op${opcode}`, state: STATES[state] || `State${state}`, group, priority };
  }

  function parseGTP(bytes, offset, length) {
    if (length < 8) return null;
    const flags = bytes[offset];
    const version = (flags >> 5) & 7;
    const msgType = bytes[offset + 1];
    const teid = getUint32BE(bytes, offset + 4);
    if (version === 1) {
      const V1_TYPES = { 1: 'Echo Request', 2: 'Echo Response', 16: 'Create PDP Request', 17: 'Create PDP Response', 18: 'Update PDP Request', 19: 'Update PDP Response', 20: 'Delete PDP Request', 21: 'Delete PDP Response', 255: 'G-PDU' };
      return { version: 'v1', messageType: V1_TYPES[msgType] || `Type${msgType}`, teid };
    }
    if (version === 2) {
      const V2_TYPES = { 1: 'Echo Request', 2: 'Echo Response', 32: 'Create Session Request', 33: 'Create Session Response', 34: 'Modify Bearer Request', 35: 'Modify Bearer Response', 36: 'Delete Session Request', 37: 'Delete Session Response' };
      return { version: 'v2', messageType: V2_TYPES[msgType] || `Type${msgType}`, teid };
    }
    return null;
  }

  function parseDiameter(bytes, offset, length) {
    if (length < 20) return null;
    const version = bytes[offset];
    if (version !== 1) return null;
    const msgLen = (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3];
    const flags = bytes[offset + 4];
    const cmdCode = (bytes[offset + 5] << 16) | (bytes[offset + 6] << 8) | bytes[offset + 7];
    const isReq = !!(flags & 0x80);
    const CMDS = { 257: 'Capabilities-Exchange', 258: 'Re-Auth', 271: 'Accounting', 272: 'Credit-Control', 274: 'Abort-Session', 275: 'Session-Termination', 280: 'Device-Watchdog', 282: 'Disconnect-Peer' };
    return { version, commandCode: CMDS[cmdCode] || `Cmd${cmdCode}`, isRequest: isReq, messageLength: msgLen };
  }

  function parseTACACS(bytes, offset, length) {
    if (length < 12) return null;
    const majorVer = (bytes[offset] >> 4) & 0xF;
    const minorVer = bytes[offset] & 0xF;
    const type = bytes[offset + 1];
    const seqNo = bytes[offset + 2];
    const TYPES = { 1: 'Authentication', 2: 'Authorization', 3: 'Accounting' };
    if (majorVer !== 0xC) return null; // TACACS+ major version = 12
    return { version: `${majorVer}.${minorVer}`, type: TYPES[type] || `Type${type}`, sequenceNumber: seqNo };
  }

  function parseSunRPC(bytes, offset, length) {
    if (length < 24) return null;
    const xid = getUint32BE(bytes, offset);
    const msgType = getUint32BE(bytes, offset + 4);
    if (msgType === 0) {
      // Call
      const rpcVer = getUint32BE(bytes, offset + 8);
      const program = getUint32BE(bytes, offset + 12);
      const progVer = getUint32BE(bytes, offset + 16);
      const procedure = getUint32BE(bytes, offset + 20);
      const PROGS = { 100003: 'NFS', 100005: 'MOUNT', 100000: 'PORTMAP', 100021: 'NLM', 100024: 'STATUS' };
      return { type: 'Call', program: PROGS[program] || `Prog${program}`, version: progVer, procedure };
    }
    if (msgType === 1) {
      const replyState = getUint32BE(bytes, offset + 8);
      return { type: 'Reply', accepted: replyState === 0 };
    }
    return null;
  }

  function parseVNC(bytes, offset, length) {
    if (length < 4) return null;
    // VNC protocol version: "RFB 003.008\n"
    if (bytes[offset] === 0x52 && bytes[offset + 1] === 0x46 && bytes[offset + 2] === 0x42 && bytes[offset + 3] === 0x20) {
      try {
        const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 20, offset + length)));
        return { type: 'ProtocolVersion', version: str.trim() };
      } catch (e) {}
    }
    // Security type handshake
    if (length >= 1 && length <= 4) {
      return { type: 'Handshake' };
    }
    // Client message types
    const msgType = bytes[offset];
    const CLIENT_MSGS = { 0: 'SetPixelFormat', 2: 'SetEncodings', 3: 'FramebufferUpdateRequest', 4: 'KeyEvent', 5: 'PointerEvent', 6: 'ClientCutText' };
    const SERVER_MSGS = { 0: 'FramebufferUpdate', 1: 'SetColourMapEntries', 2: 'Bell', 3: 'ServerCutText' };
    if (CLIENT_MSGS[msgType]) return { type: CLIENT_MSGS[msgType] };
    if (SERVER_MSGS[msgType]) return { type: SERVER_MSGS[msgType] };
    return null;
  }

  function parseWHOIS(bytes, offset, length) {
    if (length < 3) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 200, offset + length)));
      const line = str.split('\r\n')[0] || str.split('\n')[0];
      // Query is a single domain/IP line
      if (/^[a-zA-Z0-9.\-]+\s*$/.test(line) && line.length < 80) return { type: 'query', domain: line.trim() };
      // Response contains "Domain Name:", "Registrar:", "WHOIS", etc.
      if (/^%|^#|Domain Name:|Registrar:|WHOIS|NetRange:|OrgName:/i.test(str)) return { type: 'response', preview: line.slice(0, 60) };
    } catch (e) {}
    return null;
  }

  function parseTFTPData(bytes, offset, length) {
    // TFTP data transfer on ephemeral ports — same format as TFTP
    return parseTFTP(bytes, offset, length);
  }

  function parseSMTP_Submission(bytes, offset, length) {
    // SMTP submission on port 587 - reuse SMTP parser
    return parseSMTP(bytes, offset, length);
  }

  function parseHTTPProxy(bytes, offset, length) {
    if (length < 8) return null;
    try {
      const str = _utf8Decoder.decode(bytes.subarray(offset, Math.min(offset + 200, offset + length)));
      const line = str.split('\r\n')[0] || '';
      if (/^CONNECT\s+\S+:\d+\s+HTTP\/1\.[01]/.test(line)) return { type: 'CONNECT', target: line.split(' ')[1] || '' };
    } catch (e) {}
    return parseHTTP(bytes, offset, length);
  }

  function parseNTP_Control(bytes, offset, length) {
    if (length < 12) return null;
    const li_vn_mode = bytes[offset];
    const mode = li_vn_mode & 0x07;
    if (mode !== 6 && mode !== 7) return null; // Mode 6=control, 7=private
    const version = (li_vn_mode >> 3) & 0x07;
    return { version, mode: mode === 6 ? 'Control' : 'Private' };
  }

  function parseCassandra(bytes, offset, length) {
    if (length < 9) return null;
    const version = bytes[offset] & 0x7F;
    const isResponse = !!(bytes[offset] & 0x80);
    const flags = bytes[offset + 1];
    const stream = getUint16BE(bytes, offset + 2);
    const opcode = bytes[offset + 4];
    const bodyLen = getUint32BE(bytes, offset + 5);
    if (version < 3 || version > 5) return null;
    const OPS = { 0x00: 'ERROR', 0x01: 'STARTUP', 0x02: 'READY', 0x03: 'AUTHENTICATE', 0x05: 'OPTIONS', 0x06: 'SUPPORTED', 0x07: 'QUERY', 0x08: 'RESULT', 0x09: 'PREPARE', 0x0A: 'EXECUTE', 0x0B: 'REGISTER', 0x0C: 'EVENT', 0x0D: 'BATCH', 0x0E: 'AUTH_CHALLENGE', 0x0F: 'AUTH_RESPONSE', 0x10: 'AUTH_SUCCESS' };
    return { version: `v${version}`, isResponse, opcode: OPS[opcode] || `Op0x${opcode.toString(16)}`, stream };
  }

  function parseZeroMQ(bytes, offset, length) {
    if (length < 10) return null;
    // ZMTP 3.0 greeting: signature starts with 0xFF, 8 padding bytes, then 0x7F
    if (bytes[offset] === 0xFF && length >= 10 && bytes[offset + 9] === 0x7F) {
      const major = bytes[offset + 10];
      const minor = length > 11 ? bytes[offset + 11] : 0;
      return { type: 'Greeting', version: `${major}.${minor}` };
    }
    // ZMTP command frame
    if (bytes[offset] === 0x04 && length >= 2) {
      const cmdLen = bytes[offset + 1];
      if (cmdLen > 0 && cmdLen < length) {
        try {
          const cmdName = _utf8Decoder.decode(bytes.subarray(offset + 2, Math.min(offset + 2 + cmdLen, offset + 20)));
          return { type: 'Command', command: cmdName };
        } catch (e) {}
      }
    }
    return null;
  }

  function parseCDP(bytes, offset, length) {
    if (length < 4) return null;
    const version = bytes[offset];
    const ttl = bytes[offset + 1];
    if (version !== 1 && version !== 2) return null;
    // Parse TLVs for device ID
    let deviceId = '';
    let pos = offset + 4; // skip version, ttl, checksum
    const end = offset + length;
    while (pos + 4 <= end) {
      const tlvType = getUint16BE(bytes, pos);
      const tlvLen = getUint16BE(bytes, pos + 2);
      if (tlvLen < 4 || pos + tlvLen > end) break;
      if (tlvType === 1) { // Device ID
        try { deviceId = _utf8Decoder.decode(bytes.subarray(pos + 4, pos + tlvLen)); } catch (e) {}
      }
      pos += tlvLen;
    }
    return { version, ttl, deviceId: deviceId.slice(0, 40) };
  }

  function parseMSSQLTDS(bytes, offset, length) {
    if (length < 8) return null;
    const type = bytes[offset];
    const status = bytes[offset + 1];
    const tdsLen = getUint16BE(bytes, offset + 2);
    const TYPES = { 1: 'SQL Batch', 2: 'Pre-TDS7 Login', 3: 'RPC', 4: 'Tabular Result', 6: 'Attention', 7: 'Bulk Load', 14: 'Transaction Manager', 15: 'Unknown', 16: 'TDS7 Login', 17: 'SSPI', 18: 'Pre-Login' };
    if (!TYPES[type]) return null;
    return { messageType: TYPES[type], status, length: tdsLen };
  }

  function parseOracle(bytes, offset, length) {
    if (length < 8) return null;
    const pktLen = getUint16BE(bytes, offset);
    const pktType = bytes[offset + 4];
    const TYPES = { 1: 'Connect', 2: 'Accept', 3: 'Acknowledge', 4: 'Refuse', 5: 'Redirect', 6: 'Data', 7: 'Null', 9: 'Abort', 11: 'Resend', 12: 'Marker', 13: 'Attention', 14: 'Control' };
    if (!TYPES[pktType]) return null;
    return { messageType: TYPES[pktType], packetLength: pktLen };
  }

  function parseElasticsearch(bytes, offset, length) {
    // ES uses HTTP REST API - detect via HTTP methods + /_index patterns or root endpoint
    const http = parseHTTP(bytes, offset, length);
    if (!http) return null;
    if (http.url && (/^\/((_search|_cat|_cluster|_nodes|_bulk|_count|_mapping|_settings|_aliases|_analyze|_reindex|_msearch|_mget|_tasks|_ingest|_snapshot|_recovery)|[a-z0-9_.-]+\/(_search|_doc|_mapping|_settings|_count|_bulk))/.test(http.url) || http.url === '/')) {
      return { ...http, esEndpoint: http.url.split('?')[0].slice(0, 60) };
    }
    return null;
  }

  function parseRTMP(bytes, offset, length) {
    if (length < 12) return null;
    // RTMP handshake: C0 = version byte (0x03)
    if (bytes[offset] === 0x03 && length >= 1537) return { type: 'Handshake C0+C1' };
    // RTMP chunk
    const fmt = (bytes[offset] >> 6) & 3;
    const csId = bytes[offset] & 0x3F;
    if (csId >= 2 && length >= 12) {
      const msgTypeId = bytes[offset + 7];
      const MSG = { 1: 'SetChunkSize', 2: 'Abort', 3: 'Acknowledgement', 4: 'UserControl', 5: 'WindowAckSize', 6: 'SetPeerBW', 8: 'Audio', 9: 'Video', 15: 'DataAMF3', 17: 'CommandAMF3', 18: 'DataAMF0', 20: 'CommandAMF0' };
      return { type: MSG[msgTypeId] || `MsgType${msgTypeId}`, fmt, chunkStreamId: csId };
    }
    return null;
  }

  function parsePPTP(bytes, offset, length) {
    if (length < 12) return null;
    const pptpLen = getUint16BE(bytes, offset);
    const pptpType = getUint16BE(bytes, offset + 2);
    const magic = getUint32BE(bytes, offset + 4);
    if (magic !== 0x1A2B3C4D) return null;
    const ctrlType = getUint16BE(bytes, offset + 8);
    const TYPES = { 1: 'Start-Control-Connection-Request', 2: 'Start-Control-Connection-Reply', 3: 'Stop-Control-Connection-Request', 4: 'Stop-Control-Connection-Reply', 7: 'Outgoing-Call-Request', 8: 'Outgoing-Call-Reply', 15: 'Set-Link-Info' };
    return { controlType: TYPES[ctrlType] || `Type${ctrlType}`, length: pptpLen };
  }

  function parseBitTorrent(bytes, offset, length) {
    if (length < 20) return null;
    // BitTorrent handshake: 0x13 + "BitTorrent protocol"
    if (bytes[offset] === 0x13 && length >= 68) {
      try {
        const proto = _utf8Decoder.decode(bytes.subarray(offset + 1, offset + 20));
        if (proto === 'BitTorrent protocol') return { type: 'Handshake' };
      } catch (e) {}
    }
    // Peer message: 4-byte length prefix + 1-byte type
    if (length >= 5) {
      const msgLen = getUint32BE(bytes, offset);
      if (msgLen === 0) return { type: 'KeepAlive' };
      if (msgLen >= 1 && msgLen < 1000000) {
        const msgType = bytes[offset + 4];
        const TYPES = { 0: 'Choke', 1: 'Unchoke', 2: 'Interested', 3: 'NotInterested', 4: 'Have', 5: 'Bitfield', 6: 'Request', 7: 'Piece', 8: 'Cancel', 9: 'Port', 20: 'Extended' };
        if (TYPES[msgType] !== undefined) return { type: TYPES[msgType] };
      }
    }
    return null;
  }

  // --- IP Protocol Number parsers ---

  function parseGRE(bytes, offset, length) {
    if (length < 4) return null;
    const flags = getUint16BE(bytes, offset);
    const protocol = getUint16BE(bytes, offset + 2);
    const C = !!(flags & 0x8000), K = !!(flags & 0x2000), S = !!(flags & 0x1000);
    const ver = flags & 7;
    const PROTOS = { 0x0800: 'IPv4', 0x86DD: 'IPv6', 0x880B: 'PPP', 0x6558: 'Transparent Ethernet' };
    let key = null;
    if (K && length >= 8) key = getUint32BE(bytes, offset + 4);
    return { version: ver, protocol: PROTOS[protocol] || `0x${protocol.toString(16)}`, checksum: C, keyPresent: K, key, seqPresent: S };
  }

  function parseIGMP(bytes, offset, length) {
    if (length < 8) return null;
    const type = bytes[offset];
    const maxResp = bytes[offset + 1];
    const group = formatIPv4(bytes, offset + 4);
    const TYPES = { 0x11: 'Membership Query', 0x12: 'V1 Membership Report', 0x16: 'V2 Membership Report', 0x17: 'Leave Group', 0x22: 'V3 Membership Report' };
    return { type: TYPES[type] || `Type0x${type.toString(16)}`, group, maxResponseTime: maxResp };
  }

  function parseOSPF(bytes, offset, length) {
    if (length < 24) return null;
    const version = bytes[offset];
    const type = bytes[offset + 1];
    const pktLen = getUint16BE(bytes, offset + 2);
    const routerId = formatIPv4(bytes, offset + 4);
    const areaId = formatIPv4(bytes, offset + 8);
    const TYPES = { 1: 'Hello', 2: 'Database Description', 3: 'Link State Request', 4: 'Link State Update', 5: 'Link State Ack' };
    return { version, type: TYPES[type] || `Type${type}`, routerId, areaId, length: pktLen };
  }

  function parseESP(bytes, offset, length) {
    if (length < 8) return null;
    const spi = getUint32BE(bytes, offset);
    const seq = getUint32BE(bytes, offset + 4);
    return { spi: `0x${spi.toString(16)}`, sequenceNumber: seq };
  }

  function parseAH(bytes, offset, length) {
    if (length < 12) return null;
    const nextHeader = bytes[offset];
    const payloadLen = bytes[offset + 1];
    const spi = getUint32BE(bytes, offset + 4);
    const seq = getUint32BE(bytes, offset + 8);
    return { nextHeader, spi: `0x${spi.toString(16)}`, sequenceNumber: seq, payloadLength: payloadLen };
  }

  function parseVRRP(bytes, offset, length) {
    if (length < 8) return null;
    const verType = bytes[offset];
    const version = (verType >> 4) & 0xF;
    const type = verType & 0xF;
    const vrId = bytes[offset + 1];
    const priority = bytes[offset + 2];
    const addrCount = bytes[offset + 3];
    const TYPES = { 1: 'Advertisement' };
    return { version, type: TYPES[type] || `Type${type}`, virtualRouterId: vrId, priority, addressCount: addrCount };
  }

  function parseSCTP(bytes, offset, length) {
    if (length < 12) return null;
    const srcPort = getUint16BE(bytes, offset);
    const dstPort = getUint16BE(bytes, offset + 2);
    const verTag = getUint32BE(bytes, offset + 4);
    // Parse first chunk type
    let chunkType = null;
    if (length >= 16) {
      const ct = bytes[offset + 12];
      const CHUNKS = { 0: 'DATA', 1: 'INIT', 2: 'INIT-ACK', 3: 'SACK', 4: 'HEARTBEAT', 5: 'HEARTBEAT-ACK', 6: 'ABORT', 7: 'SHUTDOWN', 8: 'SHUTDOWN-ACK', 9: 'ERROR', 10: 'COOKIE-ECHO', 11: 'COOKIE-ACK', 14: 'SHUTDOWN-COMPLETE', 15: 'AUTH', 64: 'FORWARD-TSN' };
      chunkType = CHUNKS[ct] || `Chunk${ct}`;
    }
    return { srcPort, dstPort, verificationTag: `0x${verTag.toString(16)}`, chunkType };
  }

  function parsePIM(bytes, offset, length) {
    if (length < 4) return null;
    const verType = bytes[offset];
    const version = (verType >> 4) & 0xF;
    const type = verType & 0xF;
    const TYPES = { 0: 'Hello', 1: 'Register', 2: 'Register-Stop', 3: 'Join/Prune', 4: 'Bootstrap', 5: 'Assert', 6: 'Graft', 7: 'Graft-Ack', 8: 'Candidate-RP-Adv' };
    return { version, type: TYPES[type] || `Type${type}` };
  }

  function parseEIGRP(bytes, offset, length) {
    if (length < 20) return null;
    const version = bytes[offset];
    const opcode = bytes[offset + 1];
    const OPCODES = { 1: 'Update', 2: 'Request', 3: 'Query', 4: 'Reply', 5: 'Hello', 6: 'IPX SAP', 10: 'SIA Query', 11: 'SIA Reply' };
    const as = getUint16BE(bytes, offset + 2);
    return { version, opcode: OPCODES[opcode] || `Op${opcode}`, autonomousSystem: as };
  }

  // --- EtherType protocol parsers ---

  function parseLLDP(bytes, offset, length) {
    if (length < 2) return null;
    // Parse TLVs
    let chassisId = '', portId = '', sysName = '';
    let pos = offset;
    const end = offset + length;
    let iterations = 0;
    while (pos + 2 <= end && iterations < 30) {
      iterations++;
      const typeLen = getUint16BE(bytes, pos);
      const tlvType = (typeLen >> 9) & 0x7F;
      const tlvLen = typeLen & 0x01FF;
      if (tlvType === 0) break; // End
      const dataStart = pos + 2;
      if (dataStart + tlvLen > end) break;
      if (tlvType === 1 && tlvLen > 1) {
        // Chassis ID
        try { chassisId = _utf8Decoder.decode(bytes.subarray(dataStart + 1, dataStart + tlvLen)); } catch (e) {}
      }
      if (tlvType === 2 && tlvLen > 1) {
        try { portId = _utf8Decoder.decode(bytes.subarray(dataStart + 1, dataStart + tlvLen)); } catch (e) {}
      }
      if (tlvType === 5) {
        try { sysName = _utf8Decoder.decode(bytes.subarray(dataStart, dataStart + tlvLen)); } catch (e) {}
      }
      pos = dataStart + tlvLen;
    }
    return { chassisId: chassisId.slice(0, 40), portId: portId.slice(0, 40), systemName: sysName.slice(0, 40) };
  }

  function parseMPLS(bytes, offset, length) {
    if (length < 4) return null;
    const labelEntry = getUint32BE(bytes, offset);
    const label = labelEntry >>> 12;
    const exp = (labelEntry >> 9) & 7;
    const bos = (labelEntry >> 8) & 1;
    const ttl = labelEntry & 0xFF;
    return { label, exp, bottomOfStack: !!bos, ttl };
  }

  function parseEAPOL(bytes, offset, length) {
    if (length < 4) return null;
    const version = bytes[offset];
    const type = bytes[offset + 1];
    const bodyLen = getUint16BE(bytes, offset + 2);
    const TYPES = { 0: 'EAP-Packet', 1: 'EAPOL-Start', 2: 'EAPOL-Logoff', 3: 'EAPOL-Key', 4: 'EAPOL-ASF-Alert' };
    return { version, type: TYPES[type] || `Type${type}`, bodyLength: bodyLen };
  }

  function parsePPPoE(bytes, offset, length) {
    if (length < 6) return null;
    const verType = bytes[offset];
    const code = bytes[offset + 1];
    const sessionId = getUint16BE(bytes, offset + 2);
    const payloadLen = getUint16BE(bytes, offset + 4);
    const CODES = { 0x00: 'Session Data', 0x07: 'PADO', 0x09: 'PADI', 0x19: 'PADR', 0x65: 'PADS', 0xa7: 'PADT' };
    return { code: CODES[code] || `Code0x${code.toString(16)}`, sessionId, payloadLength: payloadLen };
  }

  function parseLACP(bytes, offset, length) {
    if (length < 4) return null;
    const subtype = bytes[offset];
    const version = bytes[offset + 1];
    if (subtype !== 1) return null; // LACP subtype
    return { version, subtype: 'LACP' };
  }

  // =====================================================================
  // Protocol Registry — add new protocols by appending to this array.
  // Supports transport:'tcp'|'udp' (port-based), transport:'ip' (IP protocol number),
  // transport:'ether' (EtherType dispatch).
  //   parse()  — returns parsed object or null if not this protocol
  //   apply()  — copies parsed fields into the packet + sets info string
  // Order matters: first match wins for shared ports (e.g., TLS before SMTP on 465).
  // =====================================================================

  const APP_PROTOCOLS = [
    // === UDP protocols ===
    { name:'DNS', transport:'udp', ports:[53], parse:parseDNS,
      apply(dns,pkt){ pkt.dnsQueryName=dns.queryName; pkt.dnsIsResponse=dns.isResponse; pkt.dnsAnswers=dns.answers||[]; pkt.dnsRcode=dns.rcode;
        const dir=dns.isResponse?'response':'query'; pkt.info=`Standard ${dir} ${dns.qType} ${dns.queryName}${dns.isResponse&&dns.rcode!==0?' ['+dns.rcodeStr+']':''}`;
        pkt.layers.dns={type:dir,queryName:dns.queryName,queryType:dns.qType,questionCount:dns.qdCount,answerCount:dns.anCount,rcode:dns.rcodeStr,answers:dns.answers}; }},
    { name:'DHCP', transport:'udp', ports:[67,68], parse:parseDHCP,
      apply(d,pkt){ const mt=d.messageType||d.op; const ip=d.assignedIP!=='0.0.0.0'?` ${d.assignedIP}`:''; pkt.info=`DHCP ${mt}${ip}`; pkt.layers.dhcp=d; }},
    { name:'NTP', transport:'udp', ports:[123], parse:parseNTP,
      apply(n,pkt){ pkt.info=`NTPv${n.version} ${n.mode}${n.stratum>0?' stratum '+n.stratum:''}`; pkt.layers.ntp=n; }},
    { name:'TFTP', transport:'udp', ports:[69], parse:parseTFTP,
      apply(t,pkt){ let i=`TFTP ${t.opName}`; if(t.filename)i+=` "${t.filename}"`; if(t.blockNum!==null)i+=` Block ${t.blockNum}`; pkt.info=i; pkt.layers.tftp=t; }},
    { name:'QUIC', transport:'udp', ports:[443,8443], parse:parseQUIC,
      apply(q,pkt){ pkt.info=`QUIC ${q.form}${q.version?' v'+q.version:''}`; pkt.layers.quic=q; }},
    { name:'mDNS', transport:'udp', ports:[5353], parse:parseMDNS,
      apply(d,pkt){ pkt.dnsQueryName=d.queryName; pkt.dnsIsResponse=d.isResponse; pkt.dnsAnswers=d.answers||[]; pkt.dnsRcode=d.rcode;
        const dir=d.isResponse?'response':'query'; pkt.info=`mDNS ${dir} ${d.qType} ${d.queryName}`; pkt.layers.mdns={type:dir,queryName:d.queryName,queryType:d.qType}; }},
    { name:'SSDP', transport:'udp', ports:[1900], parse:parseSSD,
      apply(s,pkt){ pkt.info=`SSDP ${s.method}${s.serviceType?' '+s.serviceType:''}`; pkt.layers.ssdp=s; }},
    { name:'NBNS', transport:'udp', ports:[137], parse:parseNBNS,
      apply(n,pkt){ pkt.info=`NBNS ${n.opcode}${n.name?' '+n.name:''} ${n.isResponse?'response':'request'}`; pkt.layers.nbns=n; }},
    { name:'LLMNR', transport:'udp', ports:[5355], parse:parseLLMNR,
      apply(d,pkt){ const dir=d.isResponse?'response':'query'; pkt.info=`LLMNR ${dir} ${d.qType} ${d.queryName}`; pkt.layers.llmnr={type:dir,queryName:d.queryName}; }},
    { name:'SNMP', transport:'udp', ports:[161,162], parse:parseSNMP,
      apply(s,pkt){ pkt.info=`SNMP ${s.version} ${s.pduType||''}${s.community?' community='+s.community:''}`; pkt.layers.snmp=s; }},
    { name:'Syslog', transport:'udp', ports:[514], parse:parseSyslog,
      apply(s,pkt){ pkt.info=`Syslog ${s.severityName}: ${s.message}`; pkt.layers.syslog=s; }},
    { name:'SIP', transport:'udp', ports:[5060,5061], parse:parseSIPMsg,
      apply(s,pkt){ if(s.type==='request')pkt.info=`SIP ${s.method} ${s.uri}`; else pkt.info=`SIP ${s.code} ${s.reason}`; pkt.layers.sip=s; }},
    { name:'RTP', transport:'udp', ports:[5004,5005], parse:parseRTP,
      apply(r,pkt){ pkt.info=`RTP ${r.payloadName} seq=${r.seq}${r.marker?' [M]':''}`; pkt.layers.rtp=r; }},
    { name:'STUN', transport:'udp', ports:[3478,3479,5349], parse:parseSTUN,
      apply(s,pkt){ pkt.info=`STUN ${s.messageType}`; pkt.layers.stun=s; }},
    { name:'RADIUS', transport:'udp', ports:[1812,1813,1645,1646], parse:parseRADIUS,
      apply(r,pkt){ pkt.info=`RADIUS ${r.code} id=${r.id}`; pkt.layers.radius=r; }},
    { name:'NetFlow', transport:'udp', ports:[2055,9995,9996], parse:parseNetFlow,
      apply(n,pkt){ pkt.info=`${n.name} ${n.version} ${n.count} records`; pkt.layers.netflow=n; }},
    { name:'VXLAN', transport:'udp', ports:[4789,8472], parse:parseVXLAN,
      apply(v,pkt){ pkt.info=`VXLAN VNI=${v.vni}`; pkt.layers.vxlan=v; }},
    { name:'ISAKMP', transport:'udp', ports:[500,4500], parse:parseISAKMP,
      apply(i,pkt){ pkt.info=`IKE ${i.version} ${i.exchangeType}`; pkt.layers.isakmp=i; }},
    { name:'DTLS', transport:'udp', ports:[443,4433,5684], parse:parseDTLS,
      apply(d,pkt){ const hs=d.handshakeType?' '+d.handshakeType:''; pkt.info=`${d.version} ${d.contentType}${hs}`; pkt.layers.dtls=d; }},
    { name:'CoAP', transport:'udp', ports:[5683,5684], parse:parseCoAP,
      apply(c,pkt){ pkt.info=`CoAP ${c.type} ${c.method} MID=${c.messageId}`; pkt.layers.coap=c; }},
    { name:'DHCPv6', transport:'udp', ports:[546,547], parse:parseDHCPv6,
      apply(d,pkt){ pkt.info=`DHCPv6 ${d.messageType}`; pkt.layers.dhcpv6=d; }},
    { name:'L2TP', transport:'udp', ports:[1701], parse:parseL2TP,
      apply(l,pkt){ pkt.info=`L2TP v${l.version} ${l.type}`; pkt.layers.l2tp=l; }},
    { name:'RIPv2', transport:'udp', ports:[520], parse:parseRIPv2,
      apply(r,pkt){ pkt.info=`RIP v${r.version} ${r.command} ${r.entries} entries`; pkt.layers.rip=r; }},
    { name:'WireGuard', transport:'udp', ports:[51820], parse:parseWireGuard,
      apply(w,pkt){ pkt.info=`WireGuard ${w.messageType}`; pkt.layers.wireguard=w; }},
    { name:'OpenVPN', transport:'udp', ports:[1194], parse:parseOpenVPN,
      apply(o,pkt){ pkt.info=`OpenVPN ${o.opcode}`; pkt.layers.openvpn=o; }},
    { name:'BACnet', transport:'udp', ports:[47808], parse:parseBACnet,
      apply(b,pkt){ pkt.info=`BACnet ${b.function}`; pkt.layers.bacnet=b; }},
    { name:'NetBIOS-DGM', transport:'udp', ports:[138], parse(b,o,l){ if(l<10)return null; const mt=b[o]; const T={0x10:'Direct Unique',0x11:'Direct Group',0x12:'Broadcast'}; if(!T[mt])return null; return{messageType:T[mt]}; },
      apply(n,pkt){ pkt.info=`NetBIOS-DGM ${n.messageType}`; pkt.layers['netbios-dgm']=n; }},

    // === TCP protocols (order: TLS first for encrypted port sharing) ===
    { name:'TLS', transport:'tcp', ports:[443,993,995,465,8443,636,989,990,992,5061,853], parse:parseTLS,
      apply(t,pkt){ const hs=t.handshakeType?' '+t.handshakeType:''; pkt.info=`${t.version} ${t.contentType}${hs}`; pkt.layers.tls=t; }},
    { name:'HTTP', transport:'tcp', ports:[80,8080,8000,8888,3000,8081,8443], parse:parseHTTP,
      apply(h,pkt){ pkt.httpMethod=h.method; pkt.httpUrl=h.url; pkt.httpStatusCode=h.statusCode; pkt.info=h.firstLine;
        pkt.layers.http={method:h.method,url:h.url,statusCode:h.statusCode,firstLine:h.firstLine}; }},
    { name:'SSH', transport:'tcp', ports:[22], parse:parseSSH,
      apply(s,pkt){ pkt.info=s.type==='banner'?s.version:`SSH ${s.messageType}`; pkt.layers.ssh=s; }},
    { name:'SMTP', transport:'tcp', ports:[25,587,465], parse:parseSMTP,
      apply(s,pkt){ pkt.info=s.type==='command'?`SMTP ${s.detail}`:`SMTP ${s.code} ${s.text}`; pkt.layers.smtp=s; }},
    { name:'FTP', transport:'tcp', ports:[21], parse:parseFTP,
      apply(f,pkt){ pkt.info=f.type==='command'?`FTP ${f.detail}`:`FTP ${f.code} ${f.text}`; pkt.layers.ftp=f; }},
    { name:'IMAP', transport:'tcp', ports:[143,993], parse:parseIMAP,
      apply(i,pkt){ pkt.info=i.type==='command'?`IMAP ${i.command} [${i.tag}]`:`IMAP ${i.detail}`; pkt.layers.imap=i; }},
    { name:'POP3', transport:'tcp', ports:[110,995], parse:parsePOP3,
      apply(p,pkt){ pkt.info=p.type==='command'?`POP3 ${p.command}`:`POP3 ${p.status} ${p.detail}`; pkt.layers.pop3=p; }},
    { name:'SMB', transport:'tcp', ports:[445,139], parse:parseSMB,
      apply(s,pkt){ pkt.info=`SMB${s.version} ${s.command}`; pkt.layers.smb=s; }},
    { name:'RDP', transport:'tcp', ports:[3389], parse:parseRDP,
      apply(r,pkt){ pkt.info=`RDP ${r.pduType}`; pkt.layers.rdp=r; }},
    { name:'LDAP', transport:'tcp', ports:[389,636,3268,3269], parse:parseLDAP,
      apply(l,pkt){ pkt.info=`LDAP ${l.operation}`; pkt.layers.ldap=l; }},
    { name:'Kerberos', transport:'tcp', ports:[88], parse:parseKerberos,
      apply(k,pkt){ pkt.info=`Kerberos ${k.messageType}`; pkt.layers.kerberos=k; }},
    { name:'RTSP', transport:'tcp', ports:[554,8554], parse:parseRTSP,
      apply(r,pkt){ pkt.info=r.type==='request'?`RTSP ${r.method} ${r.url}`:`RTSP ${r.statusCode}`; pkt.layers.rtsp=r; }},
    { name:'MySQL', transport:'tcp', ports:[3306], parse:parseMySQL,
      apply(m,pkt){ pkt.info=`MySQL ${m.type}`; pkt.layers.mysql=m; }},
    { name:'PostgreSQL', transport:'tcp', ports:[5432], parse:parsePostgreSQL,
      apply(p,pkt){ pkt.info=`PostgreSQL ${p.type}${p.version?' v'+p.version:''}`; pkt.layers.postgresql=p; }},
    { name:'Redis', transport:'tcp', ports:[6379], parse:parseRedis,
      apply(r,pkt){ pkt.info=r.command?`Redis ${r.command}`:`Redis ${r.type}${r.value?' '+r.value:''}`; pkt.layers.redis=r; }},
    { name:'MongoDB', transport:'tcp', ports:[27017,27018,27019], parse:parseMongoDB,
      apply(m,pkt){ pkt.info=`MongoDB ${m.opCode}`; pkt.layers.mongodb=m; }},
    { name:'Memcached', transport:'tcp', ports:[11211], parse:parseMemcached,
      apply(m,pkt){ pkt.info=`Memcached ${m.protocol} ${m.command}`; pkt.layers.memcached=m; }},
    { name:'MQTT', transport:'tcp', ports:[1883,8883], parse:parseMQTT,
      apply(m,pkt){ pkt.info=`MQTT ${m.messageType}${m.qos?' QoS='+m.qos:''}`; pkt.layers.mqtt=m; }},
    { name:'AMQP', transport:'tcp', ports:[5672], parse:parseAMQP,
      apply(a,pkt){ pkt.info=a.version?`AMQP Protocol ${a.version}`:`AMQP ${a.type} ch=${a.channel}`; pkt.layers.amqp=a; }},
    { name:'BGP', transport:'tcp', ports:[179], parse:parseBGP,
      apply(b,pkt){ pkt.info=`BGP ${b.messageType}`; pkt.layers.bgp=b; }},
    { name:'Telnet', transport:'tcp', ports:[23], parse:parseTelnet,
      apply(t,pkt){ pkt.info=t.type==='negotiation'?`Telnet ${t.command} ${t.option}`:`Telnet Data: ${t.preview||''}`; pkt.layers.telnet=t; }},
    { name:'IRC', transport:'tcp', ports:[6667,6668,6669,6697], parse:parseIRC,
      apply(i,pkt){ pkt.info=`IRC ${i.command||i.code||''} ${i.params||i.detail||''}`; pkt.layers.irc=i; }},
    { name:'XMPP', transport:'tcp', ports:[5222,5269,5280], parse:parseXMPP,
      apply(x,pkt){ pkt.info=`XMPP ${x.element}${x.stanzaType?' type='+x.stanzaType:''}`; pkt.layers.xmpp=x; }},
    { name:'SOCKS', transport:'tcp', ports:[1080], parse:parseSOCKS,
      apply(s,pkt){ pkt.info=`SOCKS${s.version} ${s.type}`; pkt.layers.socks=s; }},
    { name:'Modbus', transport:'tcp', ports:[502], parse:parseModbus,
      apply(m,pkt){ pkt.info=`Modbus ${m.functionName}${m.isException?' [Exception]':''} unit=${m.unitId}`; pkt.layers.modbus=m; }},
    { name:'DNP3', transport:'tcp', ports:[20000], parse:parseDNP3,
      apply(d,pkt){ pkt.info=`DNP3 ${d.functionCode} ${d.direction}`; pkt.layers.dnp3=d; }},
    { name:'EtherNet/IP', transport:'tcp', ports:[44818,2222], parse:parseEtherNetIP,
      apply(e,pkt){ pkt.info=`EtherNet/IP ${e.command}`; pkt.layers.enip=e; }},
    { name:'S7comm', transport:'tcp', ports:[102], parse:parseS7comm,
      apply(s,pkt){ pkt.info=`S7comm ${s.messageType} ${s.functionCode}`; pkt.layers.s7comm=s; }},
    { name:'MSSQL', transport:'tcp', ports:[1433,1434], parse:parseMSSQLTDS,
      apply(m,pkt){ pkt.info=`TDS ${m.messageType}`; pkt.layers.mssql=m; }},
    { name:'Oracle', transport:'tcp', ports:[1521], parse:parseOracle,
      apply(o,pkt){ pkt.info=`Oracle TNS ${o.messageType}`; pkt.layers.oracle=o; }},
    { name:'Elasticsearch', transport:'tcp', ports:[9200,9300], parse:parseElasticsearch,
      apply(e,pkt){ pkt.httpMethod=e.method; pkt.httpUrl=e.url; pkt.httpStatusCode=e.statusCode;
        pkt.info=e.isRequest?`ES ${e.method} ${e.esEndpoint}`:`ES ${e.statusCode}`; pkt.layers.elasticsearch=e; }},
    { name:'SIP', transport:'tcp', ports:[5060,5061], parse:parseSIPMsg,
      apply(s,pkt){ if(s.type==='request')pkt.info=`SIP ${s.method} ${s.uri}`; else pkt.info=`SIP ${s.code} ${s.reason}`; pkt.layers.sip=s; }},
    { name:'RTMP', transport:'tcp', ports:[1935], parse:parseRTMP,
      apply(r,pkt){ pkt.info=`RTMP ${r.type}`; pkt.layers.rtmp=r; }},
    { name:'PPTP', transport:'tcp', ports:[1723], parse:parsePPTP,
      apply(p,pkt){ pkt.info=`PPTP ${p.controlType}`; pkt.layers.pptp=p; }},
    { name:'BitTorrent', transport:'tcp', ports:[6881,6882,6883,6884,6885,6886,6887,6888,6889], parse:parseBitTorrent,
      apply(b,pkt){ pkt.info=`BitTorrent ${b.type}`; pkt.layers.bittorrent=b; }},
    { name:'NetBIOS-SSN', transport:'tcp', ports:[139], parse(b,o,l){ if(l<4)return null; const t=b[o]; const T={0x00:'Session Message',0x81:'Session Request',0x82:'Positive Response',0x83:'Negative Response',0x85:'Session Keep Alive'}; if(!T[t])return null; return{messageType:T[t],length:getUint16BE(b,o+2)|(b[o+1]&1)<<16}; },
      apply(n,pkt){ pkt.info=`NetBIOS-SSN ${n.messageType}`; pkt.layers['netbios-ssn']=n; }},
    { name:'Kerberos', transport:'udp', ports:[88], parse:parseKerberos,
      apply(k,pkt){ pkt.info=`Kerberos ${k.messageType}`; pkt.layers.kerberos=k; }},
    { name:'STUN', transport:'tcp', ports:[3478], parse:parseSTUN,
      apply(s,pkt){ pkt.info=`STUN ${s.messageType}`; pkt.layers.stun=s; }},
    { name:'OpenVPN', transport:'tcp', ports:[1194], parse:parseOpenVPN,
      apply(o,pkt){ pkt.info=`OpenVPN ${o.opcode}`; pkt.layers.openvpn=o; }},
    { name:'Memcached', transport:'udp', ports:[11211], parse:parseMemcached,
      apply(m,pkt){ pkt.info=`Memcached ${m.protocol} ${m.command}`; pkt.layers.memcached=m; }},
    { name:'EtherNet/IP', transport:'udp', ports:[2222], parse:parseEtherNetIP,
      apply(e,pkt){ pkt.info=`EtherNet/IP ${e.command}`; pkt.layers.enip=e; }},

    // === Batch 3: Additional protocols to reach 100 ===
    // TCP
    { name:'DICOM', transport:'tcp', ports:[104,11112], parse:parseDICOM,
      apply(d,pkt){ pkt.info=`DICOM ${d.pduType}`; pkt.layers.dicom=d; }},
    { name:'HL7', transport:'tcp', ports:[2575], parse:parseHL7,
      apply(h,pkt){ pkt.info=`HL7 ${h.type} ${h.segment}`; pkt.layers.hl7=h; }},
    { name:'VNC', transport:'tcp', ports:[5900,5901,5902,5903], parse:parseVNC,
      apply(v,pkt){ pkt.info=`VNC ${v.type}${v.version?' '+v.version:''}`; pkt.layers.vnc=v; }},
    { name:'Cassandra', transport:'tcp', ports:[9042], parse:parseCassandra,
      apply(c,pkt){ pkt.info=`Cassandra ${c.version} ${c.opcode}${c.isResponse?' Response':''}`; pkt.layers.cassandra=c; }},
    { name:'ZeroMQ', transport:'tcp', ports:[5555,5556], parse:parseZeroMQ,
      apply(z,pkt){ pkt.info=`ZeroMQ ${z.type}${z.version?' v'+z.version:''}${z.command?' '+z.command:''}`; pkt.layers.zeromq=z; }},
    { name:'WHOIS', transport:'tcp', ports:[43], parse:parseWHOIS,
      apply(w,pkt){ pkt.info=w.type==='query'?`WHOIS Query ${w.domain}`:`WHOIS Response: ${w.preview||''}`; pkt.layers.whois=w; }},
    { name:'HTTP-Proxy', transport:'tcp', ports:[3128,8118], parse:parseHTTPProxy,
      apply(h,pkt){ if(h.type==='CONNECT'){pkt.info=`HTTP CONNECT ${h.target}`;}else{pkt.httpMethod=h.method;pkt.httpUrl=h.url;pkt.httpStatusCode=h.statusCode;pkt.info=h.firstLine;} pkt.layers['http-proxy']=h; }},
    { name:'SunRPC', transport:'tcp', ports:[111,2049], parse:parseSunRPC,
      apply(r,pkt){ pkt.info=r.type==='Call'?`RPC Call ${r.program} v${r.version} proc=${r.procedure}`:`RPC Reply${r.accepted?' OK':' Error'}`; pkt.layers.sunrpc=r; }},
    { name:'TACACS+', transport:'tcp', ports:[49], parse:parseTACACS,
      apply(t,pkt){ pkt.info=`TACACS+ ${t.type} seq=${t.sequenceNumber}`; pkt.layers.tacacs=t; }},
    { name:'Diameter', transport:'tcp', ports:[3868], parse:parseDiameter,
      apply(d,pkt){ pkt.info=`Diameter ${d.commandCode}${d.isRequest?' Request':' Answer'}`; pkt.layers.diameter=d; }},
    // UDP
    { name:'RTCP', transport:'udp', ports:[5005], parse:parseRTCP,
      apply(r,pkt){ pkt.info=`RTCP ${r.payloadType}`; pkt.layers.rtcp=r; }},
    { name:'HSRP', transport:'udp', ports:[1985], parse:parseHSRP,
      apply(h,pkt){ pkt.info=`HSRP ${h.opcode} group=${h.group} state=${h.state} pri=${h.priority}`; pkt.layers.hsrp=h; }},
    { name:'GTP', transport:'udp', ports:[2152,2123], parse:parseGTP,
      apply(g,pkt){ pkt.info=`GTP-${g.version} ${g.messageType}`; pkt.layers.gtp=g; }},
    { name:'SunRPC', transport:'udp', ports:[111], parse:parseSunRPC,
      apply(r,pkt){ pkt.info=r.type==='Call'?`RPC Call ${r.program} v${r.version} proc=${r.procedure}`:`RPC Reply${r.accepted?' OK':' Error'}`; pkt.layers.sunrpc=r; }},
    { name:'Diameter', transport:'udp', ports:[3868], parse:parseDiameter,
      apply(d,pkt){ pkt.info=`Diameter ${d.commandCode}${d.isRequest?' Request':' Answer'}`; pkt.layers.diameter=d; }},
    { name:'RADIUS-Acct', transport:'udp', ports:[1813,1646], parse:parseRADIUS,
      apply(r,pkt){ pkt.info=`RADIUS-Acct ${r.code} id=${r.id}`; pkt.layers['radius-acct']=r; }},
    { name:'NTP-Control', transport:'udp', ports:[123], parse:parseNTP_Control,
      apply(n,pkt){ pkt.info=`NTP ${n.mode} v${n.version}`; pkt.layers['ntp-control']=n; }},

    // Inline simple port-based protocols (6 more to reach 100)
    { name:'FTPS', transport:'tcp', ports:[990,989], parse:parseTLS,
      apply(t,pkt){ const hs=t.handshakeType?' '+t.handshakeType:''; pkt.info=`FTPS ${t.version} ${t.contentType}${hs}`; pkt.layers.ftps=t; }},
    { name:'LDAPS', transport:'tcp', ports:[636], parse:parseTLS,
      apply(t,pkt){ const hs=t.handshakeType?' '+t.handshakeType:''; pkt.info=`LDAPS ${t.version} ${t.contentType}${hs}`; pkt.layers.ldaps=t; }},
    { name:'IMAPS', transport:'tcp', ports:[993], parse:parseTLS,
      apply(t,pkt){ const hs=t.handshakeType?' '+t.handshakeType:''; pkt.info=`IMAPS ${t.version} ${t.contentType}${hs}`; pkt.layers.imaps=t; }},
    { name:'POP3S', transport:'tcp', ports:[995], parse:parseTLS,
      apply(t,pkt){ const hs=t.handshakeType?' '+t.handshakeType:''; pkt.info=`POP3S ${t.version} ${t.contentType}${hs}`; pkt.layers.pop3s=t; }},
    { name:'Finger', transport:'tcp', ports:[79], parse(b,o,l){ if(l<2)return null; try{ const s=_utf8Decoder.decode(b.slice(o,Math.min(o+80,o+l))); const line=s.split('\r\n')[0]||s.split('\n')[0]; if(/^[a-zA-Z0-9@.\- ]*$/.test(line))return{query:line.trim()}; }catch(e){} return null; },
      apply(f,pkt){ pkt.info=`Finger${f.query?' '+f.query:''}`; pkt.layers.finger=f; }},
    { name:'Gopher', transport:'tcp', ports:[70], parse(b,o,l){ if(l<1)return null; try{ const s=_utf8Decoder.decode(b.slice(o,Math.min(o+80,o+l))); const line=s.split('\r\n')[0]||s.split('\n')[0]; return{selector:line.slice(0,60)}; }catch(e){} return null; },
      apply(g,pkt){ pkt.info=`Gopher ${g.selector||'/'}`; pkt.layers.gopher=g; }},
  ];

  // === IP Protocol number protocols (dispatched by IP protocol field, not ports) ===
  const IP_PROTO_PROTOCOLS = [
    { name:'GRE', ipProto:47, parse:parseGRE,
      apply(g,pkt){ pkt.info=`GRE v${g.version} ${g.protocol}${g.key!=null?' key='+g.key:''}`; pkt.layers.gre=g; }},
    { name:'IGMP', ipProto:2, parse:parseIGMP,
      apply(i,pkt){ pkt.info=`IGMP ${i.type} ${i.group}`; pkt.layers.igmp=i; }},
    { name:'OSPF', ipProto:89, parse:parseOSPF,
      apply(o,pkt){ pkt.info=`OSPFv${o.version} ${o.type} Router=${o.routerId}`; pkt.layers.ospf=o; }},
    { name:'ESP', ipProto:50, parse:parseESP,
      apply(e,pkt){ pkt.info=`ESP SPI=${e.spi} Seq=${e.sequenceNumber}`; pkt.layers.esp=e; }},
    { name:'AH', ipProto:51, parse:parseAH,
      apply(a,pkt){ pkt.info=`AH SPI=${a.spi} Seq=${a.sequenceNumber}`; pkt.layers.ah=a; }},
    { name:'VRRP', ipProto:112, parse:parseVRRP,
      apply(v,pkt){ pkt.info=`VRRPv${v.version} ${v.type} VRID=${v.virtualRouterId} pri=${v.priority}`; pkt.layers.vrrp=v; }},
    { name:'SCTP', ipProto:132, parse:parseSCTP,
      apply(s,pkt){ pkt.srcPort=s.srcPort; pkt.dstPort=s.dstPort; pkt.info=`SCTP ${s.srcPort} \u2192 ${s.dstPort} ${s.chunkType||''}`; pkt.layers.sctp=s; }},
    { name:'PIM', ipProto:103, parse:parsePIM,
      apply(p,pkt){ pkt.info=`PIMv${p.version} ${p.type}`; pkt.layers.pim=p; }},
    { name:'EIGRP', ipProto:88, parse:parseEIGRP,
      apply(e,pkt){ pkt.info=`EIGRP v${e.version} ${e.opcode} AS=${e.autonomousSystem}`; pkt.layers.eigrp=e; }},
  ];

  // === EtherType protocols (dispatched at link layer) ===
  const ETHERTYPE_PROTOCOLS = [
    { name:'LLDP', etherType:0x88CC, parse:parseLLDP,
      apply(l,pkt){ pkt.info=`LLDP${l.systemName?' '+l.systemName:''}${l.portId?' port='+l.portId:''}`; pkt.layers.lldp=l; }},
    { name:'MPLS', etherType:0x8847, parse:parseMPLS,
      apply(m,pkt){ pkt.info=`MPLS Label=${m.label} TTL=${m.ttl}${m.bottomOfStack?' [S]':''}`; pkt.layers.mpls=m; }},
    { name:'MPLS-MC', etherType:0x8848, parse:parseMPLS,
      apply(m,pkt){ pkt.info=`MPLS-MC Label=${m.label} TTL=${m.ttl}`; pkt.layers.mpls=m; }},
    { name:'EAPOL', etherType:0x888E, parse:parseEAPOL,
      apply(e,pkt){ pkt.info=`EAPOL v${e.version} ${e.type}`; pkt.layers.eapol=e; }},
    { name:'PPPoE-D', etherType:0x8863, parse:parsePPPoE,
      apply(p,pkt){ pkt.info=`PPPoE Discovery ${p.code}`; pkt.layers.pppoe=p; }},
    { name:'PPPoE-S', etherType:0x8864, parse:parsePPPoE,
      apply(p,pkt){ pkt.info=`PPPoE Session id=${p.sessionId}`; pkt.layers.pppoe=p; }},
    { name:'LACP', etherType:0x8809, parse:parseLACP,
      apply(l,pkt){ pkt.info=`LACP v${l.version}`; pkt.layers.lacp=l; }},
  ];

  // Build O(1) port → [protocol candidates] lookup maps
  const TCP_PORT_PROTOCOLS = new Map();
  const UDP_PORT_PROTOCOLS = new Map();
  for (const proto of APP_PROTOCOLS) {
    const map = proto.transport === 'tcp' ? TCP_PORT_PROTOCOLS : UDP_PORT_PROTOCOLS;
    for (const port of proto.ports) {
      if (!map.has(port)) map.set(port, []);
      map.get(port).push(proto);
    }
  }
  // Build IP protocol → protocol def lookup
  const IP_PROTO_MAP = new Map();
  for (const proto of IP_PROTO_PROTOCOLS) IP_PROTO_MAP.set(proto.ipProto, proto);
  // Build EtherType → protocol def lookup
  const ETHERTYPE_MAP = new Map();
  for (const proto of ETHERTYPE_PROTOCOLS) ETHERTYPE_MAP.set(proto.etherType, proto);


  // --- Main packet dissection ---

  function dissectPacket(bytes, linkType) {
    const packet = {
      rawBytes: new Uint8Array(bytes), // copy packet bytes to release file ArrayBuffer for GC
      srcMAC: null, dstMAC: null, etherType: null,
      srcIP: null, dstIP: null, ipVersion: null, ttl: null,
      srcPort: null, dstPort: null, tcpFlags: null,
      tcpSeqNum: null, tcpAckNum: null,
      protocol: 'Other', info: '',
      arpOperation: null, arpSenderIP: null, arpTargetIP: null,
      dnsQueryName: null, dnsIsResponse: null, dnsAnswers: [], dnsRcode: null,
      httpMethod: null, httpUrl: null, httpStatusCode: null,
      tcpOptions: null,
      // Layer detail objects for packet detail pane
      layers: {},
      // TCP payload range for stream reassembly
      tcpPayloadOffset: null, tcpPayloadLength: 0,
      // Anomaly flags
      anomalies: [],
    };

    let etherType = 0;
    let ipOffset = 0;

    if (linkType === 1) {
      const eth = parseEthernet(bytes, 0);
      if (!eth) return packet;
      packet.srcMAC = eth.srcMAC;
      packet.dstMAC = eth.dstMAC;
      packet.etherType = eth.etherType;
      etherType = eth.etherType;
      ipOffset = eth.nextOffset;
      packet.layers.ethernet = { srcMAC: eth.srcMAC, dstMAC: eth.dstMAC, etherType: `0x${eth.etherType.toString(16).padStart(4, '0')}`, headerLen: eth.nextOffset };
    } else if (linkType === 113) {
      if (bytes.length < 16) return packet;
      etherType = getUint16BE(bytes, 14);
      ipOffset = 16;
      packet.layers.sll = { etherType: `0x${etherType.toString(16).padStart(4, '0')}` };
    } else if (linkType === 101) {
      if (bytes.length < 1) return packet;
      const version = (bytes[0] >> 4) & 0x0F;
      etherType = version === 6 ? 0x86DD : 0x0800;
      ipOffset = 0;
    } else {
      packet.protocol = 'Other';
      packet.info = `Unsupported link type ${linkType}`;
      return packet;
    }

    if (etherType === 0x0800) {
      const ip = parseIPv4(bytes, ipOffset);
      if (!ip) { packet.info = 'Malformed IPv4'; return packet; }
      packet.srcIP = ip.srcIP;
      packet.dstIP = ip.dstIP;
      packet.ipVersion = 4;
      packet.ttl = ip.ttl;
      packet.layers.ipv4 = {
        version: 4, headerLen: ip.headerLen, totalLength: ip.totalLength,
        identification: ip.identification, ttl: ip.ttl, protocol: ip.protocol,
        checksum: `0x${ip.checksum.toString(16)}`, srcIP: ip.srcIP, dstIP: ip.dstIP,
        dscp: ip.dscp,
      };
      dissectTransport(bytes, ip.transportOffset, ip.protocol, ip.totalLength - ip.headerLen, packet);
    } else if (etherType === 0x86DD) {
      const ip6 = parseIPv6(bytes, ipOffset);
      if (!ip6) { packet.info = 'Malformed IPv6'; return packet; }
      packet.srcIP = ip6.srcIP;
      packet.dstIP = ip6.dstIP;
      packet.ipVersion = 6;
      packet.ttl = ip6.hopLimit;
      packet.layers.ipv6 = {
        version: 6, payloadLength: ip6.payloadLength, nextHeader: ip6.protocol,
        hopLimit: ip6.hopLimit, srcIP: ip6.srcIP, dstIP: ip6.dstIP,
      };
      dissectTransport(bytes, ip6.transportOffset, ip6.protocol, ip6.payloadLength, packet);
    } else if (etherType === 0x0806) {
      const arp = parseARP(bytes, ipOffset);
      if (!arp) { packet.info = 'Malformed ARP'; return packet; }
      packet.protocol = 'ARP';
      packet.arpOperation = arp.operation === 1 ? 'Request' : 'Reply';
      packet.arpSenderIP = arp.senderIP;
      packet.arpTargetIP = arp.targetIP;
      packet.srcIP = arp.senderIP;
      packet.dstIP = arp.targetIP;
      packet.layers.arp = {
        operation: packet.arpOperation, senderMAC: arp.senderMAC, senderIP: arp.senderIP,
        targetMAC: arp.targetMAC, targetIP: arp.targetIP,
      };
      packet.info = arp.operation === 1
        ? `Who has ${arp.targetIP}? Tell ${arp.senderIP}`
        : `${arp.senderIP} is at ${arp.senderMAC}`;
    } else {
      // Registry-based EtherType protocol detection
      const ethProto = ETHERTYPE_MAP.get(etherType);
      if (ethProto) {
        try {
          const remainLen = bytes.length - ipOffset;
          const parsed = remainLen > 0 ? ethProto.parse(bytes, ipOffset, remainLen) : null;
          if (parsed) {
            packet.protocol = ethProto.name;
            ethProto.apply(parsed, packet);
          } else {
            packet.protocol = 'Other';
            packet.info = `EtherType 0x${etherType.toString(16).padStart(4, '0')}`;
          }
        } catch (e) {
          packet.protocol = 'Other';
          packet.info = `EtherType 0x${etherType.toString(16).padStart(4, '0')}`;
        }
      } else {
        packet.protocol = 'Other';
        packet.info = `EtherType 0x${etherType.toString(16).padStart(4, '0')}`;
      }
    }

    return packet;
  }

  function dissectTransport(bytes, offset, protocol, remainingLen, packet) {
    if (protocol === 6) {
      const tcp = parseTCP(bytes, offset);
      if (!tcp) { packet.protocol = 'TCP'; packet.info = 'Malformed TCP'; return; }
      packet.srcPort = tcp.srcPort;
      packet.dstPort = tcp.dstPort;
      packet.tcpFlags = tcp.flags;
      packet.tcpSeqNum = tcp.seqNum;
      packet.tcpAckNum = tcp.ackNum;
      packet.protocol = 'TCP';
      const payloadLen = Math.max(0, remainingLen - tcp.headerLen);
      packet.tcpPayloadOffset = tcp.payloadOffset;
      packet.tcpPayloadLength = payloadLen;

      packet.tcpOptions = tcp.options;
      packet.layers.tcp = {
        srcPort: tcp.srcPort, dstPort: tcp.dstPort, seqNum: tcp.seqNum,
        ackNum: tcp.ackNum, flags: tcpFlagsStr(tcp.flags), windowSize: tcp.windowSize,
        headerLen: tcp.headerLen, checksum: `0x${tcp.checksum.toString(16)}`, payloadLen,
      };
      if (tcp.options) {
        const o = tcp.options;
        packet.layers.tcp.options = {};
        if (o.mss !== null) packet.layers.tcp.options.MSS = o.mss;
        if (o.windowScale !== null) packet.layers.tcp.options.WindowScale = o.windowScale;
        if (o.sackPermitted) packet.layers.tcp.options.SACKPermitted = true;
        if (o.timestamps) packet.layers.tcp.options.Timestamps = `TSval=${o.timestamps.tsval} TSecr=${o.timestamps.tsecr}`;
      }

      packet.info = `${tcp.srcPort} \u2192 ${tcp.dstPort} [${tcpFlagsStr(tcp.flags)}] Seq=${tcp.seqNum} Ack=${tcp.ackNum} Win=${tcp.windowSize} Len=${payloadLen}`;

      // Registry-based application protocol detection
      if (payloadLen > 0) {
        const srcCandidates = TCP_PORT_PROTOCOLS.get(tcp.srcPort);
        const dstCandidates = TCP_PORT_PROTOCOLS.get(tcp.dstPort);
        // Merge both port candidate lists (dedup via Set for shared-port protocols)
        const seen = new Set();
        const candidates = [];
        for (const list of [dstCandidates, srcCandidates]) {
          if (list) for (const p of list) { if (!seen.has(p)) { seen.add(p); candidates.push(p); } }
        }
        if (candidates.length > 0) {
          for (const proto of candidates) {
            try {
              const parsed = proto.parse(bytes, tcp.payloadOffset, payloadLen);
              if (parsed) {
                packet.protocol = proto.name;
                proto.apply(parsed, packet);
                break;
              }
            } catch (e) {
              // Silently skip parse errors for protocol candidates
            }
          }
        }
      }
    } else if (protocol === 17) {
      const udp = parseUDP(bytes, offset);
      if (!udp) { packet.protocol = 'UDP'; packet.info = 'Malformed UDP'; return; }
      packet.srcPort = udp.srcPort;
      packet.dstPort = udp.dstPort;
      packet.protocol = 'UDP';
      packet.layers.udp = { srcPort: udp.srcPort, dstPort: udp.dstPort, length: udp.length };
      packet.info = `${udp.srcPort} \u2192 ${udp.dstPort} Len=${udp.payloadLength}`;

      // Registry-based application protocol detection
      if (udp.payloadLength > 0) {
        const srcCandidates = UDP_PORT_PROTOCOLS.get(udp.srcPort);
        const dstCandidates = UDP_PORT_PROTOCOLS.get(udp.dstPort);
        const seen = new Set();
        const candidates = [];
        for (const list of [dstCandidates, srcCandidates]) {
          if (list) for (const p of list) { if (!seen.has(p)) { seen.add(p); candidates.push(p); } }
        }
        if (candidates.length > 0) {
          for (const proto of candidates) {
            try {
              const parsed = proto.parse(bytes, udp.payloadOffset, udp.payloadLength);
              if (parsed) {
                packet.protocol = proto.name;
                proto.apply(parsed, packet);
                break;
              }
            } catch (e) {
              // Silently skip parse errors for protocol candidates
            }
          }
        }
      }
    } else if (protocol === 1) {
      const icmp = parseICMP(bytes, offset);
      if (!icmp) { packet.protocol = 'ICMP'; packet.info = 'Malformed ICMP'; return; }
      packet.protocol = 'ICMP';
      packet.info = `${icmp.description}${icmp.extra}`;
      packet.layers.icmp = { type: icmp.type, code: icmp.code, description: icmp.description };
    } else if (protocol === 58) {
      const icmp = parseICMP(bytes, offset);
      if (!icmp) { packet.protocol = 'ICMPv6'; packet.info = 'Malformed ICMPv6'; return; }
      packet.protocol = 'ICMPv6';
      packet.info = `ICMPv6 ${icmp.description}${icmp.extra}`;
      packet.layers.icmpv6 = { type: icmp.type, code: icmp.code, description: icmp.description };
    } else {
      // Registry-based IP protocol number detection
      const ipProto = IP_PROTO_MAP.get(protocol);
      if (ipProto) {
        try {
          const remainLen = Math.max(0, remainingLen);
          const parsed = remainLen > 0 ? ipProto.parse(bytes, offset, remainLen) : null;
          if (parsed) {
            packet.protocol = ipProto.name;
            ipProto.apply(parsed, packet);
          } else {
            packet.protocol = 'Other';
            packet.info = `IP Protocol ${protocol}`;
          }
        } catch (e) {
          packet.protocol = 'Other';
          packet.info = `IP Protocol ${protocol}`;
        }
      } else {
        packet.protocol = 'Other';
        packet.info = `IP Protocol ${protocol}`;
      }
    }
  }

  // --- File format parsers ---

  function parsePcap(buffer) {
    const dv = new DataView(buffer);
    const magic = dv.getUint32(0, false);
    let le, isNano;
    switch (magic) {
      case 0xA1B2C3D4: le = false; isNano = false; break;
      case 0xD4C3B2A1: le = true;  isNano = false; break;
      case 0xA1B23C4D: le = false; isNano = true;  break;
      case 0x4D3CB2A1: le = true;  isNano = true;  break;
      default: throw new Error('Not a valid pcap file');
    }
    const versionMajor = dv.getUint16(4, le);
    const versionMinor = dv.getUint16(6, le);
    const snapLen = dv.getUint32(16, le);
    const linkType = dv.getUint32(20, le);
    const packets = [];
    let offset = 24;
    let index = 1;
    while (offset + 16 <= buffer.byteLength && packets.length < MAX_PACKETS) {
      const tsSec = dv.getUint32(offset, le);
      const tsUSec = dv.getUint32(offset + 4, le);
      const inclLen = dv.getUint32(offset + 8, le);
      const origLen = dv.getUint32(offset + 12, le);
      if (offset + 16 + inclLen > buffer.byteLength) break;
      if (inclLen > snapLen + 1000) break;
      const timestamp = tsSec * 1000 + (isNano ? tsUSec / 1e6 : tsUSec / 1000);
      const rawBytes = new Uint8Array(buffer, offset + 16, inclLen);
      const packet = dissectPacket(rawBytes, linkType);
      packet.number = index++;
      packet.timestamp = timestamp;
      packet.capturedLength = inclLen;
      packet.originalLength = origLen;
      packets.push(packet);
      offset += 16 + inclLen;
    }
    return { packets, fileInfo: { format: 'pcap', version: `${versionMajor}.${versionMinor}`, linkType, snapLen } };
  }

  function parsePcapng(buffer) {
    const dv = new DataView(buffer);
    let le = true;
    const interfaces = [];
    const packets = [];
    let index = 1;
    let offset = 0;
    let blockCount = 0;
    while (offset + 8 <= buffer.byteLength && blockCount < MAX_PCAPNG_BLOCKS && packets.length < MAX_PACKETS) {
      blockCount++;
      let blockType = dv.getUint32(offset, le);
      let blockLen = dv.getUint32(offset + 4, le);
      if (blockType === 0x0A0D0D0A || blockType === 0x0D0D0A0A) {
        const bom = dv.getUint32(offset + 8, false);
        le = bom !== 0x1A2B3C4D;
        blockLen = dv.getUint32(offset + 4, le);
        blockType = 0x0A0D0D0A;
        interfaces.length = 0;
      }
      if (blockLen < 12 || offset + blockLen > buffer.byteLength) break;
      switch (blockType) {
        case 0x0A0D0D0A: break;
        case 0x00000001: {
          const lt = dv.getUint16(offset + 8, le);
          const sl = dv.getUint32(offset + 12, le);
          let tsResolution = 1e6;
          let optOffset = offset + 16;
          const optEnd = offset + blockLen - 4;
          while (optOffset + 4 <= optEnd) {
            const optCode = dv.getUint16(optOffset, le);
            const optLen = dv.getUint16(optOffset + 2, le);
            if (optCode === 0) break;
            if (optCode === 9 && optLen >= 1) {
              const tsresol = dv.getUint8(optOffset + 4);
              tsResolution = (tsresol & 0x80) ? Math.pow(2, tsresol & 0x7F) : Math.pow(10, tsresol);
            }
            optOffset += 4 + Math.ceil(optLen / 4) * 4;
          }
          interfaces.push({ linkType: lt, snapLen: sl, tsResolution });
          break;
        }
        case 0x00000006: {
          const ifaceID = dv.getUint32(offset + 8, le);
          const tsHigh = dv.getUint32(offset + 12, le);
          const tsLow = dv.getUint32(offset + 16, le);
          const capturedLen = dv.getUint32(offset + 20, le);
          const origLen = dv.getUint32(offset + 24, le);
          if (offset + 28 + capturedLen > buffer.byteLength) break;
          const iface = interfaces[ifaceID] || interfaces[0] || { linkType: 1, tsResolution: 1e6 };
          const tsValue = tsHigh * 4294967296 + tsLow;
          const timestampMs = (tsValue / iface.tsResolution) * 1000;
          const rawBytes = new Uint8Array(buffer, offset + 28, capturedLen);
          const packet = dissectPacket(rawBytes, iface.linkType);
          packet.number = index++;
          packet.timestamp = timestampMs;
          packet.capturedLength = capturedLen;
          packet.originalLength = origLen;
          packets.push(packet);
          break;
        }
        case 0x00000003: {
          const origLen = dv.getUint32(offset + 8, le);
          const iface = interfaces[0] || { linkType: 1, snapLen: 65535, tsResolution: 1e6 };
          const capturedLen = Math.min(origLen, iface.snapLen, blockLen - 16);
          if (offset + 12 + capturedLen > buffer.byteLength) break;
          const rawBytes = new Uint8Array(buffer, offset + 12, capturedLen);
          const packet = dissectPacket(rawBytes, iface.linkType);
          packet.number = index++;
          packet.timestamp = 0;
          packet.capturedLength = capturedLen;
          packet.originalLength = origLen;
          packets.push(packet);
          break;
        }
      }
      offset += blockLen;
    }
    return { packets, fileInfo: { format: 'pcapng', linkType: interfaces[0]?.linkType || 1 } };
  }

  return {
    parse(arrayBuffer) {
      if (arrayBuffer.byteLength < 24) throw new Error('File too small to be a valid capture file');
      const dv = new DataView(arrayBuffer);
      const magic = dv.getUint32(0, false);
      const pcapMagics = new Set([0xA1B2C3D4, 0xD4C3B2A1, 0xA1B23C4D, 0x4D3CB2A1]);
      if (pcapMagics.has(magic)) return parsePcap(arrayBuffer);
      const magicLE = dv.getUint32(0, true);
      if (magic === 0x0A0D0D0A || magicLE === 0x0A0D0D0A) return parsePcapng(arrayBuffer);
      throw new Error('Unrecognized file format. Expected .pcap or .pcapng');
    }
  };
})();
