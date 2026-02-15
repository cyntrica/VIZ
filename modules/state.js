// modules/state.js — Shared state, constants, utilities, filter engine, coloring
'use strict';

// ===== Constants =====
export const PROTOCOL_COLORS = { TCP:'#4fc3f7', UDP:'#81c784', DNS:'#ffb74d', HTTP:'#e57373', ICMP:'#ba68c8', ICMPv6:'#9575cd', ARP:'#fff176', IPv6:'#4dd0e1', Other:'#90a4ae' };
export const protoColor = p => PROTOCOL_COLORS[p] || PROTOCOL_COLORS.Other;
export const ROW_HEIGHT = 24, BUFFER = 10;

export const DARKWEB_PORTS = {
  9050:'Tor SOCKS',9051:'Tor Control',9150:'Tor Browser SOCKS',9001:'Tor Relay',9030:'Tor Directory',
  7656:'I2P SAM',7657:'I2P Router Console',7658:'I2P HTTP Proxy',4444:'I2P HTTP Proxy',4445:'I2P HTTPS Proxy',
  6668:'I2P IRC',2827:'I2P BOB',
  1080:'SOCKS Proxy',3128:'HTTP Proxy',8080:'HTTP Proxy Alt',8118:'Privoxy',
  9418:'Git (dark repo)',5222:'XMPP (Jabber)',
};
export const HTTP_PORTS = new Set([80, 8080, 8000, 8888, 3000]);

// P8: Hoisted regex constants for extraction (avoid recompilation per packet)
export const RE_BASIC_AUTH = /Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i;
export const RE_BEARER = /Authorization:\s*Bearer\s+(\S{8})/i;
export const RE_COOKIE = /Cookie:\s*([^\r\n]{0,120})/i;
export const RE_CONTENT_TYPE = /Content-Type:\s*([^\r\n;]+)/i;
export const RE_CONTENT_LENGTH = /Content-Length:\s*(\d+)/i;
export const RE_CONTENT_DISP = /Content-Disposition:.*filename="?([^"\r\n;]+)"?/i;
export const RE_FTP_USER = /^USER\s+(\S+)/mi;
export const RE_FTP_PASS = /^PASS\s+(\S+)/mi;
export const RE_SMTP_AUTH = /^AUTH\s+(LOGIN|PLAIN)\s*(.*)/mi;
export const RE_SMTP_MAIL = /^MAIL FROM:\s*<([^>]+)>/mi;
export const RE_PASSWORD_FIELD = /passw|passwd|pwd|secret|credential/i;
export const RE_SANITIZE_PASS = /(passw[^=&]*=)[^&\r\n]*/gi;
export const RE_SESSION_COOKIE = /session|token|auth|sid|jwt/i;
export const FILE_EXTS = new Set(['pdf','zip','gz','tar','exe','dmg','pkg','msi','iso','doc','docx','xls','xlsx','ppt','pptx','csv','json','xml','svg','png','jpg','jpeg','gif','webp','mp3','mp4','avi','mov','wav','apk','deb','rpm','jar','war','bin','dat','plist','ipa']);

export const SUBNET_COLORS=['#6366f1','#f59e0b','#22c55e','#ef4444','#8b5cf6','#ec4899','#14b8a6','#f97316','#06b6d4','#84cc16'];

export const DEFAULT_ALERT_RULES=[
  {name:'High RST Rate',type:'rst_flood',threshold:50,window:10,severity:'high',enabled:true},
  {name:'DNS Non-Standard Port',type:'dns_nonstandard',threshold:0,window:0,severity:'medium',enabled:true},
  {name:'Dark Web Port Activity',type:'darkweb_ports',threshold:1,window:0,severity:'high',enabled:true},
  {name:'Large Data Transfer',type:'large_transfer',threshold:10485760,window:0,severity:'medium',enabled:true},
  {name:'Port Scan Detection',type:'port_scan',threshold:20,window:60,severity:'critical',enabled:true},
];

export const COLORING_PRESETS={
  security:[{name:'RST',field:'tcp.flags.rst',operator:'==',value:'true',color:'#ef4444',enabled:true},{name:'SYN-only',field:'tcp.flags.syn',operator:'==',value:'true',color:'#f59e0b',enabled:true}],
  web:[{name:'HTTP',field:'protocol',operator:'==',value:'HTTP',color:'#22c55e',enabled:true},{name:'DNS',field:'protocol',operator:'==',value:'DNS',color:'#3b82f6',enabled:true}],
};

// ===== Utilities =====
export function formatBytes(b) { if (b < 1024) return b + ' B'; if (b < 1048576) return (b/1024).toFixed(1) + ' KB'; return (b/1048576).toFixed(1) + ' MB'; }
export function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
export function escapeHTML(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
export function hexToRGBA(hex, a) { const r=parseInt(hex.slice(1,3),16),g=parseInt(hex.slice(3,5),16),b=parseInt(hex.slice(5,7),16); return `rgba(${r},${g},${b},${a})`; }
export const $ = id => document.getElementById(id);

// S2: ReDoS-safe regex execution with nested quantifier rejection
export function safeRegexTest(pattern, str) {
  if (String(pattern).length > 200) return false;
  if (/(\+|\*|\{)\s*\??(\+|\*|\{)/.test(pattern)) return false;
  if (/\([^)]*(\+|\*)\)[^)]*(\+|\*|\{)/.test(pattern)) return false;
  try { return new RegExp(pattern, 'i').test(String(str)); } catch { return false; }
}

export function isPrivateIP(ip){
  if(!ip||ip.includes(':'))return false;
  const p=ip.split('.').map(Number);
  return(p[0]===10)||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168)||(p[0]===127);
}
export function getSubnet(ip){
  if(!ip||ip.includes(':'))return null;
  const parts=ip.split('.');
  return parts.slice(0,3).join('.')+'.0/24';
}
export function getDarkWebLabel(port){return DARKWEB_PORTS[port]||null;}

// ===== Display Filter Parser (Feature 9) =====
export const FILTER_FIELDS = {
  'ip.src':{get:p=>p.srcIP,type:'string'},'ip.dst':{get:p=>p.dstIP,type:'string'},
  'tcp.port':{get:p=>(p.protocol==='TCP'||p.protocol==='HTTP')?[p.srcPort,p.dstPort]:null,type:'port'},
  'udp.port':{get:p=>(p.protocol==='UDP'||p.protocol==='DNS')?[p.srcPort,p.dstPort]:null,type:'port'},
  'tcp.srcport':{get:p=>p.srcPort,type:'number'},'tcp.dstport':{get:p=>p.dstPort,type:'number'},
  'tcp.flags.syn':{get:p=>p.tcpFlags?p.tcpFlags.SYN:false,type:'boolean'},
  'tcp.flags.rst':{get:p=>p.tcpFlags?p.tcpFlags.RST:false,type:'boolean'},
  'tcp.flags.fin':{get:p=>p.tcpFlags?p.tcpFlags.FIN:false,type:'boolean'},
  'tcp.flags.ack':{get:p=>p.tcpFlags?p.tcpFlags.ACK:false,type:'boolean'},
  'protocol':{get:p=>p.protocol,type:'string'},'frame.len':{get:p=>p.originalLength||p.capturedLength,type:'number'},
  'dns.qname':{get:p=>p.dnsQueryName,type:'string'},'http.method':{get:p=>p.httpMethod,type:'string'},
  'http.status':{get:p=>p.httpStatusCode,type:'number'},'eth.src':{get:p=>p.srcMAC,type:'string'},
  'eth.dst':{get:p=>p.dstMAC,type:'string'},'ip.ttl':{get:p=>p.ttl,type:'number'},
};

export function parseFilterExpr(expr) {
  expr = expr.trim(); if (!expr) return null;
  try { return {fn:compileFilter(expr)}; } catch(e) { return {error:e.message}; }
}

export function compileFilter(expr) {
  const tokens=[]; let i=0;
  while(i<expr.length){
    if(expr[i]===' '||expr[i]==='\t'){i++;continue;}
    if(expr.slice(i,i+2)==='&&'){tokens.push({type:'AND'});i+=2;continue;}
    if(expr.slice(i,i+2)==='||'){tokens.push({type:'OR'});i+=2;continue;}
    if(expr.slice(i,i+2)==='=='){tokens.push({type:'OP',value:'=='});i+=2;continue;}
    if(expr.slice(i,i+2)==='!='){tokens.push({type:'OP',value:'!='});i+=2;continue;}
    if(expr.slice(i,i+2)==='>='){tokens.push({type:'OP',value:'>='});i+=2;continue;}
    if(expr.slice(i,i+2)==='<='){tokens.push({type:'OP',value:'<='});i+=2;continue;}
    if(expr[i]==='>'){tokens.push({type:'OP',value:'>'});i++;continue;}
    if(expr[i]==='<'){tokens.push({type:'OP',value:'<'});i++;continue;}
    if(expr[i]==='!'){tokens.push({type:'NOT'});i++;continue;}
    if(expr[i]==='('){tokens.push({type:'LPAREN'});i++;continue;}
    if(expr[i]===')'){tokens.push({type:'RPAREN'});i++;continue;}
    let w='';
    if(expr[i]==='"'){i++;while(i<expr.length&&expr[i]!=='"')w+=expr[i++];i++;tokens.push({type:'VALUE',value:w});continue;}
    while(i<expr.length&&!/[\s()!><=]/.test(expr[i])&&expr.slice(i,i+2)!=='&&'&&expr.slice(i,i+2)!=='||')w+=expr[i++];
    if(w==='contains'||w==='matches')tokens.push({type:'OP',value:w});
    else if(w==='and')tokens.push({type:'AND'}); else if(w==='or')tokens.push({type:'OR'}); else if(w==='not')tokens.push({type:'NOT'});
    else if(w==='true'||w==='false')tokens.push({type:'VALUE',value:w==='true'});
    else if(/^\d+$/.test(w))tokens.push({type:'VALUE',value:parseInt(w,10)});
    else if(/^\d+\.\d+\.\d+\.\d+$/.test(w))tokens.push({type:'VALUE',value:w});
    else if(/^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/.test(w))tokens.push({type:'VALUE',value:w});
    else if(/^\d+\.\d+/.test(w))tokens.push({type:'VALUE',value:parseFloat(w)});
    else tokens.push({type:'FIELD',value:w});
  }
  let pos=0;
  function peek(){return tokens[pos];}
  function consume(t){const tk=tokens[pos];if(!tk||(t&&tk.type!==t))throw new Error('Syntax error');pos++;return tk;}
  function pOr(){let l=pAnd();while(peek()&&peek().type==='OR'){consume();const r=pAnd();const ll=l;l=p=>ll(p)||r(p);}return l;}
  function pAnd(){let l=pUn();while(peek()&&peek().type==='AND'){consume();const r=pUn();const ll=l;l=p=>ll(p)&&r(p);}return l;}
  function pUn(){if(peek()&&peek().type==='NOT'){consume();const c=pUn();return p=>!c(p);}return pPri();}
  function pPri(){
    if(peek()&&peek().type==='LPAREN'){consume();const inner=pOr();consume('RPAREN');return inner;}
    const ft=consume('FIELD');const fd=FILTER_FIELDS[ft.value];if(!fd)throw new Error('Unknown: '+ft.value);
    const op=consume('OP').value;const vt=peek();let val;if(vt&&vt.type==='VALUE'){consume();val=vt.value;}else if(vt&&vt.type==='FIELD'){consume();val=vt.value;}else{throw new Error('Expected value');}
    return function(pkt){
      let fv=fd.get(pkt);if(fv===null||fv===undefined)return op==='!='?true:false;
      if(fd.type==='port'){const nv=typeof val==='number'?val:parseInt(val,10);if(op==='==')return fv[0]===nv||fv[1]===nv;if(op==='!=')return fv[0]!==nv&&fv[1]!==nv;return false;}
      if(fd.type==='boolean'){const bv=typeof val==='boolean'?val:val==='true';if(op==='==')return fv===bv;if(op==='!=')return fv!==bv;return false;}
      if(op==='contains')return String(fv).toLowerCase().includes(String(val).toLowerCase());
      if(op==='matches'){return safeRegexTest(val, fv);}
      if(fd.type==='number'){const nv=typeof val==='number'?val:parseFloat(val);if(op==='==')return fv===nv;if(op==='!=')return fv!==nv;if(op==='>')return fv>nv;if(op==='<')return fv<nv;if(op==='>=')return fv>=nv;if(op==='<=')return fv<=nv;}
      const sv=String(fv).toLowerCase(),tv=String(val).toLowerCase();if(op==='==')return sv===tv;if(op==='!=')return sv!==tv;return false;
    };
  }
  const fn=pOr();if(pos<tokens.length)throw new Error('Unexpected token');return fn;
}

// P9: Coloring rule cache (invalidated on profile/rule change)
let _coloringCache = new Map();
let _coloringCacheVersion = 0;

export function evaluateColoringRules(pkt){
  if(AppState.coloringProfile==='default')return null;
  const cacheKey=pkt.number+'_'+_coloringCacheVersion;
  if(_coloringCache.has(cacheKey))return _coloringCache.get(cacheKey);
  const rules=AppState.coloringProfile==='custom'?AppState.coloringRules:(COLORING_PRESETS[AppState.coloringProfile]||[]);
  let result=null;
  for(const rule of rules){
    if(!rule.enabled)continue;const fd=FILTER_FIELDS[rule.field];if(!fd)continue;
    const fv=fd.get(pkt);if(fv===null||fv===undefined)continue;
    const sv=String(fv).toLowerCase(),tv=String(rule.value).toLowerCase();
    let m=false;if(rule.operator==='=='||rule.operator==='equals')m=sv===tv;else if(rule.operator==='!=')m=sv!==tv;else if(rule.operator==='contains')m=sv.includes(tv);
    if(m){result=rule.color;break;}
  }
  _coloringCache.set(cacheKey,result);
  return result;
}
export function invalidateColoringCache(){_coloringCache=new Map();_coloringCacheVersion++;}

// ===== AppState =====
export const AppState = {
  packets:[], filteredPackets:[], fileInfo:null, fileName:'',
  hosts:new Map(), connections:new Map(), protocolStats:new Map(), dnsMap:new Map(),
  bookmarks:new Set(), selectedPacketIdx:-1, sortColumn:'number', sortAscending:true,
  filters:{selectedHost:null,protocolFilter:null,searchText:'',timeRange:null,anomalyOnly:false,bookmarkOnly:false},
  filterError:'', osFingerprints:new Map(), tunnelFlags:new Map(),
  diffPacketB:null, annotations:new Map(), coloringProfile:'default', coloringRules:[], graphLayer:'L3', graphHostLimit:50,
  iocList:[], iocMatches:[], darkWebFlags:new Map(), heatmapMode:false, alertRules:[], alertResults:[], subnetGroups:new Map(),
  streamIndex:new Map(),
  connStateCache:null,

  computeDerivedData() {
    this.hosts=new Map();this.connections=new Map();this.protocolStats=new Map();
    this.dnsMap=new Map();this.osFingerprints=new Map();this.tunnelFlags=new Map();
    this.darkWebFlags=new Map();this.subnetGroups=new Map();this.streamIndex=new Map();
    this.connStateCache=null;
    _coloringCache=new Map();_coloringCacheVersion++;
    const seqTracker=new Map(),sshBytes=new Map(),dnsSubCount=new Map();
    if(this.packets.length>0){const t0=this.packets[0].timestamp;this.packets.forEach(p=>{p.relativeTime=(p.timestamp-t0)/1000;});}
    for(const p of this.packets){
      this.protocolStats.set(p.protocol,(this.protocolStats.get(p.protocol)||0)+1);
      const sz=p.originalLength||p.capturedLength;
      if(p.srcIP){
        this.hosts.set(p.srcIP,(this.hosts.get(p.srcIP)||0)+sz);
        if(p.dstIP){
          this.hosts.set(p.dstIP,(this.hosts.get(p.dstIP)||0)+sz);
          const key=[p.srcIP,p.dstIP].sort().join(' <-> ');
          const c=this.connections.get(key)||{a:[p.srcIP,p.dstIP].sort()[0],b:[p.srcIP,p.dstIP].sort()[1],packets:0,bytes:0,protocols:new Set(),firstTs:p.timestamp,lastTs:p.timestamp};
          c.packets++;c.bytes+=sz;c.protocols.add(p.protocol);
          if(p.timestamp<c.firstTs)c.firstTs=p.timestamp;if(p.timestamp>c.lastTs)c.lastTs=p.timestamp;
          this.connections.set(key,c);
        }
      }
      if(p.dnsAnswers)for(const a of p.dnsAnswers)if((a.type==='A'||a.type==='AAAA')&&a.data)this.dnsMap.set(a.data,a.name);
      if(p.tcpFlags){
        if(p.tcpFlags.RST&&!p.anomalies.includes('TCP RST'))p.anomalies.push('TCP RST');
        const sk=`${p.srcIP}:${p.srcPort}-${p.dstIP}:${p.dstPort}`;
        if(p.tcpSeqNum!==null){if(seqTracker.has(sk)&&seqTracker.get(sk)===p.tcpSeqNum&&p.tcpPayloadLength>0&&!p.anomalies.includes('Retransmission'))p.anomalies.push('Retransmission');seqTracker.set(sk,p.tcpSeqNum);}
        if(p.srcIP&&p.dstIP&&p.srcPort!=null&&p.dstPort!=null){const stk=p.srcIP+':'+p.srcPort<p.dstIP+':'+p.dstPort?p.srcIP+':'+p.srcPort+'|'+p.dstIP+':'+p.dstPort:p.dstIP+':'+p.dstPort+'|'+p.srcIP+':'+p.srcPort;if(!this.streamIndex.has(stk))this.streamIndex.set(stk,[]);this.streamIndex.get(stk).push(p);}
      }
      if(sz>9000&&!p.anomalies.includes('Jumbo frame'))p.anomalies.push('Jumbo frame');
      if(p.tcpFlags&&p.tcpFlags.SYN&&!p.tcpFlags.ACK&&p.srcIP&&!this.osFingerprints.has(p.srcIP)){
        const fp={os:'Unknown',confidence:0,ttl:p.ttl,windowSize:p.layers.tcp?.windowSize,mss:p.tcpOptions?.mss};
        const ttl=p.ttl,ws=p.layers.tcp?.windowSize||0,mss=p.tcpOptions?.mss;
        if(ttl){
          if(ttl<=64&&ttl>32){fp.os=ws===65535?'macOS/FreeBSD':(ws===29200||ws===28960)?'Linux':'Linux/macOS';fp.confidence=ws===65535?80:ws===29200?85:60;}
          else if(ttl<=128&&ttl>64){fp.os=(ws===64240||ws===65535)?'Windows 10+':ws===8192?'Windows 7/8':'Windows';fp.confidence=(ws===64240||ws===65535)?80:ws===8192?70:55;}
          else if(ttl>200){fp.os='Solaris/Router';fp.confidence=50;}
          if(mss&&mss<1400&&fp.confidence>0){fp.os+=' (VPN)';fp.confidence=Math.max(fp.confidence-10,30);}
        }
        if(fp.confidence>0)this.osFingerprints.set(p.srcIP,fp);
      }
      if(p.srcPort||p.dstPort){
        const ports=[p.srcPort,p.dstPort],ips=[p.srcIP,p.dstIP];
        const addFlag=(ip,flag)=>{if(!ip)return;if(!this.tunnelFlags.has(ip))this.tunnelFlags.set(ip,new Set());this.tunnelFlags.get(ip).add(flag);};
        for(const port of ports){
          if(port===9001||port===9030)ips.forEach(ip=>addFlag(ip,'Tor'));
          if(port===51820&&p.protocol==='UDP')ips.forEach(ip=>addFlag(ip,'WireGuard'));
          if(port===1194)ips.forEach(ip=>addFlag(ip,'OpenVPN'));
        }
        if(ports.includes(22)&&p.tcpPayloadLength>0){const k=[p.srcIP,p.dstIP].sort().join('-');sshBytes.set(k,(sshBytes.get(k)||0)+p.tcpPayloadLength);}
        for(const port of ports){
          if(port&&DARKWEB_PORTS[port]){
            for(const ip of ips){
              if(!ip)continue;
              if(!this.darkWebFlags.has(ip))this.darkWebFlags.set(ip,new Map());
              this.darkWebFlags.get(ip).set(port,(this.darkWebFlags.get(ip).get(port)||0)+1);
            }
          }
        }
      }
      if(p.dnsQueryName){
        if(p.dnsQueryName.length>50&&p.srcIP){const addF=(ip,f)=>{if(!this.tunnelFlags.has(ip))this.tunnelFlags.set(ip,new Set());this.tunnelFlags.get(ip).add(f);};addF(p.srcIP,'DNS Tunnel');}
        const parts=p.dnsQueryName.split('.'),dom=parts.slice(-2).join('.');dnsSubCount.set(dom,(dnsSubCount.get(dom)||0)+1);
      }
    }
    for(const[k,b]of sshBytes)if(b>100000){const[a,bb]=k.split('-');for(const ip of[a,bb]){if(!this.tunnelFlags.has(ip))this.tunnelFlags.set(ip,new Set());this.tunnelFlags.get(ip).add('SSH Tunnel');}}
    for(const[ip]of this.hosts){
      if(!ip||ip.includes(':'))continue;
      const parts=ip.split('.');
      const subnet=parts.slice(0,3).join('.')+'.0/24';
      if(!this.subnetGroups.has(subnet))this.subnetGroups.set(subnet,[]);
      this.subnetGroups.get(subnet).push(ip);
    }
  },

  applyFilters() {
    const f=this.filters;
    let filterFn=null,textQuery='';
    if(f.searchText){
      const res=parseFilterExpr(f.searchText);
      if(res&&res.fn){this.filterError='';filterFn=res.fn;}
      else{this.filterError=res&&res.error?res.error:'';textQuery=f.searchText.toLowerCase();}
    } else this.filterError='';
    const result=[];
    for(let i=0;i<this.packets.length;i++){
      const p=this.packets[i];
      if(f.selectedHost&&p.srcIP!==f.selectedHost&&p.dstIP!==f.selectedHost)continue;
      if(f.protocolFilter&&p.protocol!==f.protocolFilter)continue;
      if(filterFn&&!filterFn(p))continue;
      if(textQuery&&!`${p.srcIP||''} ${p.dstIP||''} ${p.protocol} ${p.info} ${p.srcPort||''} ${p.dstPort||''} ${p.srcMAC||''} ${p.dstMAC||''}`.toLowerCase().includes(textQuery))continue;
      if(f.timeRange&&(p.timestamp<f.timeRange[0]||p.timestamp>f.timeRange[1]))continue;
      if(f.anomalyOnly&&p.anomalies.length===0)continue;
      if(f.bookmarkOnly&&!this.bookmarks.has(p.number))continue;
      result.push(p);
    }
    result.sort((a,b)=>{let va=a[this.sortColumn],vb=b[this.sortColumn];if(typeof va==='string'){va=va.toLowerCase();vb=(vb||'').toLowerCase();}if(va<vb)return this.sortAscending?-1:1;if(va>vb)return this.sortAscending?1:-1;return 0;});
    this.filteredPackets=result;
  },
};
