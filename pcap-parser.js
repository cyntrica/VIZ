// pcap-parser.js -- Client-side binary parser for .pcap and .pcapng files
// Supports: Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS, HTTP
// Link types: Ethernet (1), Linux SLL (113), Raw IP (101)
// Stores raw bytes per packet for hex dump view and TCP stream reassembly

const PcapParser = (() => {

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

  // --- Protocol dissection ---

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
      const extLen = bytes[transportOffset + 1];
      nextHeader = bytes[transportOffset];
      transportOffset += (extLen + 1) * 8;
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

  function parseDNSName(bytes, offset, maxOffset) {
    const labels = [];
    let pos = offset;
    let jumped = false;
    let iterations = 0;
    while (pos < maxOffset && iterations < 50) {
      iterations++;
      const len = bytes[pos];
      if (len === 0) { pos++; break; }
      if ((len & 0xC0) === 0xC0) {
        if (pos + 1 >= maxOffset) break;
        const ptr = ((len & 0x3F) << 8) | bytes[pos + 1];
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
      const str = new TextDecoder('ascii').decode(bytes.slice(offset, Math.min(offset + 200, offset + length)));
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

  // --- Main packet dissection ---

  function dissectPacket(bytes, linkType) {
    const packet = {
      rawBytes: bytes, // keep view reference (no copy) for hex dump
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
      packet.protocol = 'Other';
      packet.info = `EtherType 0x${etherType.toString(16).padStart(4, '0')}`;
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

      if (payloadLen > 0) {
        const httpPorts = new Set([80, 8080, 8000, 8888, 3000]);
        if (httpPorts.has(tcp.srcPort) || httpPorts.has(tcp.dstPort)) {
          const http = parseHTTP(bytes, tcp.payloadOffset, payloadLen);
          if (http) {
            packet.protocol = 'HTTP';
            packet.httpMethod = http.method;
            packet.httpUrl = http.url;
            packet.httpStatusCode = http.statusCode;
            packet.info = http.firstLine;
            packet.layers.http = { method: http.method, url: http.url, statusCode: http.statusCode, firstLine: http.firstLine };
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

      if (udp.srcPort === 53 || udp.dstPort === 53) {
        const dns = parseDNS(bytes, udp.payloadOffset, udp.payloadLength);
        if (dns) {
          packet.protocol = 'DNS';
          packet.dnsQueryName = dns.queryName;
          packet.dnsIsResponse = dns.isResponse;
          packet.dnsAnswers = dns.answers || [];
          packet.dnsRcode = dns.rcode;
          const dir = dns.isResponse ? 'response' : 'query';
          packet.info = `Standard ${dir} ${dns.qType} ${dns.queryName}${dns.isResponse && dns.rcode !== 0 ? ' [' + dns.rcodeStr + ']' : ''}`;
          packet.layers.dns = {
            type: dir, queryName: dns.queryName, queryType: dns.qType,
            questionCount: dns.qdCount, answerCount: dns.anCount,
            rcode: dns.rcodeStr, answers: dns.answers,
          };
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
      packet.protocol = 'Other';
      packet.info = `IP Protocol ${protocol}`;
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
    while (offset + 16 <= buffer.byteLength) {
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
    while (offset + 8 <= buffer.byteLength) {
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
