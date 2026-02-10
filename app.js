// app.js -- CyntricaVIZ with all 26 features
(function() {
  'use strict';
  const PROTOCOL_COLORS = { TCP:'#4fc3f7', UDP:'#81c784', DNS:'#ffb74d', HTTP:'#e57373', ICMP:'#ba68c8', ICMPv6:'#9575cd', ARP:'#fff176', IPv6:'#4dd0e1', Other:'#90a4ae' };
  const protoColor = p => PROTOCOL_COLORS[p] || PROTOCOL_COLORS.Other;
  const ROW_HEIGHT = 24, BUFFER = 10;
  function formatBytes(b) { if (b < 1024) return b + ' B'; if (b < 1048576) return (b/1024).toFixed(1) + ' KB'; return (b/1048576).toFixed(1) + ' MB'; }
  function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
  function escapeHTML(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }
  function hexToRGBA(hex, a) { const r=parseInt(hex.slice(1,3),16),g=parseInt(hex.slice(3,5),16),b=parseInt(hex.slice(5,7),16); return `rgba(${r},${g},${b},${a})`; }
  const $ = id => document.getElementById(id);

  // ===== Consolidated Constants =====
  const DARKWEB_PORTS = {
    9050:'Tor SOCKS',9051:'Tor Control',9150:'Tor Browser SOCKS',9001:'Tor Relay',9030:'Tor Directory',
    7656:'I2P SAM',7657:'I2P Router Console',7658:'I2P HTTP Proxy',4444:'I2P HTTP Proxy',4445:'I2P HTTPS Proxy',
    6668:'I2P IRC',2827:'I2P BOB',
    1080:'SOCKS Proxy',3128:'HTTP Proxy',8080:'HTTP Proxy Alt',8118:'Privoxy',
    9418:'Git (dark repo)',5222:'XMPP (Jabber)',
  };
  const HTTP_PORTS = new Set([80, 8080, 8000, 8888, 3000]);

  // P8: Hoisted regex constants for extraction (avoid recompilation per packet)
  const RE_BASIC_AUTH = /Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)/i;
  const RE_BEARER = /Authorization:\s*Bearer\s+(\S{8})/i;
  const RE_COOKIE = /Cookie:\s*([^\r\n]{0,120})/i;
  const RE_CONTENT_TYPE = /Content-Type:\s*([^\r\n;]+)/i;
  const RE_CONTENT_LENGTH = /Content-Length:\s*(\d+)/i;
  const RE_CONTENT_DISP = /Content-Disposition:.*filename="?([^"\r\n;]+)"?/i;
  const RE_FTP_USER = /^USER\s+(\S+)/mi;
  const RE_FTP_PASS = /^PASS\s+(\S+)/mi;
  const RE_SMTP_AUTH = /^AUTH\s+(LOGIN|PLAIN)\s*(.*)/mi;
  const RE_SMTP_MAIL = /^MAIL FROM:\s*<([^>]+)>/mi;
  const RE_PASSWORD_FIELD = /passw|passwd|pwd|secret|credential/i;
  const RE_SANITIZE_PASS = /(passw[^=&]*=)[^&\r\n]*/gi;
  const RE_SESSION_COOKIE = /session|token|auth|sid|jwt/i;
  const FILE_EXTS = new Set(['pdf','zip','gz','tar','exe','dmg','pkg','msi','iso','doc','docx','xls','xlsx','ppt','pptx','csv','json','xml','svg','png','jpg','jpeg','gif','webp','mp3','mp4','avi','mov','wav','apk','deb','rpm','jar','war','bin','dat','plist','ipa']);

  // S2: ReDoS-safe regex execution with nested quantifier rejection
  function safeRegexTest(pattern, str) {
    if (String(pattern).length > 200) return false;
    // Reject patterns with nested quantifiers that cause catastrophic backtracking
    if (/(\+|\*|\{)\s*\??(\+|\*|\{)/.test(pattern)) return false;
    if (/\([^)]*(\+|\*)\)[^)]*(\+|\*|\{)/.test(pattern)) return false;
    try { return new RegExp(pattern, 'i').test(String(str)); } catch { return false; }
  }

  // P9: Coloring rule cache (invalidated on profile/rule change)
  let _coloringCache = new Map();
  let _coloringCacheVersion = 0;

  // ===== Display Filter Parser (Feature 9) =====
  const FILTER_FIELDS = {
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
  function parseFilterExpr(expr) {
    expr = expr.trim(); if (!expr) return null;
    try { return {fn:compileFilter(expr)}; } catch(e) { return {error:e.message}; }
  }
  function compileFilter(expr) {
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

  // ===== AppState =====
  const AppState = {
    packets:[], filteredPackets:[], fileInfo:null, fileName:'',
    hosts:new Map(), connections:new Map(), protocolStats:new Map(), dnsMap:new Map(),
    bookmarks:new Set(), selectedPacketIdx:-1, sortColumn:'number', sortAscending:true,
    filters:{selectedHost:null,protocolFilter:null,searchText:'',timeRange:null,anomalyOnly:false,bookmarkOnly:false},
    filterError:'', osFingerprints:new Map(), tunnelFlags:new Map(),
    diffPacketB:null, annotations:new Map(), coloringProfile:'default', coloringRules:[], graphLayer:'L3', graphHostLimit:50,
    iocList:[], iocMatches:[], darkWebFlags:new Map(), heatmapMode:false, alertRules:[], alertResults:[], subnetGroups:new Map(),

    // P4: Cached connection state (computed once, reused by Conn State modal)
    connStateCache:null,

    computeDerivedData() {
      // P1: Single-pass computation for all derived data
      this.hosts=new Map();this.connections=new Map();this.protocolStats=new Map();
      this.dnsMap=new Map();this.osFingerprints=new Map();this.tunnelFlags=new Map();
      this.darkWebFlags=new Map();this.subnetGroups=new Map();
      this.connStateCache=null; // P4: invalidate cache
      _coloringCache=new Map();_coloringCacheVersion++; // P9: invalidate coloring cache
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
        }
        if(sz>9000&&!p.anomalies.includes('Jumbo frame'))p.anomalies.push('Jumbo frame');
        // OS fingerprint from SYN
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
        // Tunnel detection
        if(p.srcPort||p.dstPort){
          const ports=[p.srcPort,p.dstPort],ips=[p.srcIP,p.dstIP];
          const addFlag=(ip,flag)=>{if(!ip)return;if(!this.tunnelFlags.has(ip))this.tunnelFlags.set(ip,new Set());this.tunnelFlags.get(ip).add(flag);};
          for(const port of ports){
            if(port===9001||port===9030)ips.forEach(ip=>addFlag(ip,'Tor'));
            if(port===51820&&p.protocol==='UDP')ips.forEach(ip=>addFlag(ip,'WireGuard'));
            if(port===1194)ips.forEach(ip=>addFlag(ip,'OpenVPN'));
          }
          if(ports.includes(22)&&p.tcpPayloadLength>0){const k=[p.srcIP,p.dstIP].sort().join('-');sshBytes.set(k,(sshBytes.get(k)||0)+p.tcpPayloadLength);}
          // P1: Dark Web port detection merged into main loop
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
      // P1: Subnet grouping merged (needs hosts map, so after main loop)
      for(const[ip]of this.hosts){
        if(!ip||ip.includes(':'))continue;
        const parts=ip.split('.');
        const subnet=parts.slice(0,3).join('.')+'.0/24';
        if(!this.subnetGroups.has(subnet))this.subnetGroups.set(subnet,[]);
        this.subnetGroups.get(subnet).push(ip);
      }
    },

    applyFilters() {
      let pkts=this.packets; const f=this.filters;
      if(f.selectedHost)pkts=pkts.filter(p=>p.srcIP===f.selectedHost||p.dstIP===f.selectedHost);
      if(f.protocolFilter)pkts=pkts.filter(p=>p.protocol===f.protocolFilter);
      if(f.searchText){
        const res=parseFilterExpr(f.searchText);
        if(res&&res.fn){this.filterError='';pkts=pkts.filter(res.fn);}
        else{this.filterError=res&&res.error?res.error:'';const q=f.searchText.toLowerCase();pkts=pkts.filter(p=>`${p.srcIP||''} ${p.dstIP||''} ${p.protocol} ${p.info} ${p.srcPort||''} ${p.dstPort||''} ${p.srcMAC||''} ${p.dstMAC||''}`.toLowerCase().includes(q));}
      } else this.filterError='';
      if(f.timeRange)pkts=pkts.filter(p=>p.timestamp>=f.timeRange[0]&&p.timestamp<=f.timeRange[1]);
      if(f.anomalyOnly)pkts=pkts.filter(p=>p.anomalies.length>0);
      if(f.bookmarkOnly)pkts=pkts.filter(p=>this.bookmarks.has(p.number));
      pkts.sort((a,b)=>{let va=a[this.sortColumn],vb=b[this.sortColumn];if(typeof va==='string'){va=va.toLowerCase();vb=(vb||'').toLowerCase();}if(va<vb)return this.sortAscending?-1:1;if(va>vb)return this.sortAscending?1:-1;return 0;});
      this.filteredPackets=pkts;
    },
  };

  // ===== DOM Refs =====
  const els={
    uploadOverlay:$('upload-overlay'),dropZone:$('drop-zone'),fileInput:$('file-input'),
    fileInputCompare:$('file-input-compare'),loadingOverlay:$('loading-overlay'),loadingStatus:$('loading-status'),
    dashboard:$('dashboard'),fileInfo:$('file-info'),tooltip:$('tooltip'),
    hostCount:$('host-count'),timelineInfo:$('timeline-info'),
    tableSearch:$('table-search'),tableProtoFilter:$('table-protocol-filter'),
    tablePacketCount:$('table-packet-count'),tableBody:$('table-body'),
    tableAnomalyFilter:$('table-anomaly-filter'),tableBookmarkFilter:$('table-bookmark-filter'),
    filterError:$('filter-error'),filterAutocomplete:$('filter-autocomplete'),
    btnResetFilters:$('btn-reset-filters'),btnNewFile:$('btn-new-file'),
    btnConversations:$('btn-conversations'),btnCompare:$('btn-compare'),
    btnExportCSV:$('btn-export-csv'),btnExportJSON:$('btn-export-json'),btnTheme:$('btn-theme'),
    detailPane:$('packet-detail-pane'),detailPacketNum:$('detail-packet-num'),
    detailLayers:$('detail-layers'),hexDump:$('hex-dump'),
    btnFollowStream:$('btn-follow-stream'),btnCloseDetail:$('btn-close-detail'),btnDiff:$('btn-diff'),
    streamModal:$('stream-modal'),streamContent:$('stream-content'),streamInfo:$('stream-info'),btnCloseStream:$('btn-close-stream'),
    conversationsModal:$('conversations-modal'),btnCloseConversations:$('btn-close-conversations'),
    compareModal:$('compare-modal'),btnCloseCompare:$('btn-close-compare'),
    geoipModal:$('geoip-modal'),geoipCanvas:$('geoip-canvas'),geoipLegend:$('geoip-legend'),btnCloseGeoip:$('btn-close-geoip'),
    shortcutsHelp:$('shortcuts-help'),btnCloseShortcuts:$('btn-close-shortcuts'),
    btnStats:$('btn-stats'),statsModal:$('stats-modal'),statsContent:$('stats-content'),btnCloseStats:$('btn-close-stats'),
    btnExtractions:$('btn-extractions'),extractionModal:$('extraction-modal'),extractionContent:$('extraction-content'),btnCloseExtraction:$('btn-close-extraction'),
    btnLatency:$('btn-latency'),latencyModal:$('latency-modal'),latencyContent:$('latency-content'),btnCloseLatency:$('btn-close-latency'),
    btnFlow:$('btn-flow'),sequenceModal:$('sequence-modal'),btnCloseSequence:$('btn-close-sequence'),btnSeqRefresh:$('btn-seq-refresh'),
    seqHostA:$('seq-host-a'),seqHostB:$('seq-host-b'),
    btnIOGraph:$('btn-iograph'),iographModal:$('iograph-modal'),btnCloseIOGraph:$('btn-close-iograph'),
    ioMetric:$('io-metric'),ioInterval:$('io-interval'),
    diffModal:$('diff-modal'),btnCloseDiff:$('btn-close-diff'),diffInfo:$('diff-info'),diffFields:$('diff-fields'),
    btnNotes:$('btn-notes'),notesModal:$('notes-modal'),notesContent:$('notes-content'),btnCloseNotes:$('btn-close-notes'),
    btnColoring:$('btn-coloring'),coloringModal:$('coloring-modal'),btnCloseColoring:$('btn-close-coloring'),
    coloringProfile:$('coloring-profile'),coloringRulesList:$('coloring-rules-list'),btnAddRule:$('btn-add-rule'),
    notePopover:$('note-popover'),noteText:$('note-text'),noteSave:$('note-save'),noteDelete:$('note-delete'),noteCancel:$('note-cancel'),
    hostLimitSlider:$('host-limit-slider'),hostLimitValue:$('host-limit-value'),
    // IoC Matching
    btnIoC:$('btn-ioc'),iocModal:$('ioc-modal'),btnCloseIoC:$('btn-close-ioc'),
    iocInput:$('ioc-input'),btnIoCScan:$('btn-ioc-scan'),btnIoCClear:$('btn-ioc-clear'),
    iocResults:$('ioc-results'),iocMatchCount:$('ioc-match-count'),iocStatus:$('ioc-status'),
    // Alert Rules
    btnAlerts:$('btn-alerts'),alertsModal:$('alerts-modal'),btnCloseAlerts:$('btn-close-alerts'),
    btnAlertsRun:$('btn-alerts-run'),alertRulesList:$('alert-rules-list'),btnAddAlertRule:$('btn-add-alert-rule'),
    alertResults:$('alert-results'),
    // Connection State Machine
    btnConnState:$('btn-connstate'),connstateModal:$('connstate-modal'),btnCloseConnState:$('btn-close-connstate'),
    connstateFilter:$('connstate-filter'),connstateContent:$('connstate-content'),
    // Heatmap toggle
    btnHeatmapToggle:$('btn-heatmap-toggle'),
  };

  function showTooltip(html,x,y){els.tooltip.innerHTML=html;els.tooltip.classList.remove('hidden');els.tooltip.style.left=Math.min(x+10,window.innerWidth-330)+'px';els.tooltip.style.top=Math.min(y+10,window.innerHeight-100)+'px';}
  function hideTooltip(){els.tooltip.classList.add('hidden');}

  // S6: User-friendly error display (replaces alert())
  function showError(userMsg, err) {
    console.error(userMsg, err);
    // Use a non-blocking toast-style notification
    const toast = document.createElement('div');
    toast.className = 'error-toast';
    toast.textContent = userMsg;
    document.body.appendChild(toast);
    setTimeout(() => { toast.classList.add('fade-out'); setTimeout(() => toast.remove(), 400); }, 4000);
  }

  // ===== Upload =====
  const ALLOWED_EXTENSIONS=['.pcap','.pcapng','.cap'];
  function isValidPcapFile(file){
    const name=(file.name||file).toString().toLowerCase();
    return ALLOWED_EXTENSIONS.some(ext=>name.endsWith(ext));
  }
  // Detect if running inside Tauri
  const isTauri=!!(window.__TAURI__);
  async function openNativeFileDialog(){
    try{
      const dialog=window.__TAURI__.dialog;
      const invoke=window.__TAURI__.core.invoke;
      const result=await dialog.open({
        multiple:false,
        filters:[{name:'Packet Captures',extensions:['pcap','pcapng','cap']}]
      });
      if(!result)return; // user cancelled
      const filePath=result.path||result;
      const fileName=filePath.split('/').pop().split('\\').pop();
      // Read file bytes via custom Rust command
      const bytes=await invoke('read_file_bytes',{path:filePath});
      const arrayBuffer=new Uint8Array(bytes).buffer;
      loadFileFromBuffer(arrayBuffer,fileName);
    }catch(err){showError('Could not open file. Please try again.',err);}
  }
  function setupUpload(){
    els.dropZone.addEventListener('dragover',e=>{e.preventDefault();els.dropZone.classList.add('drag-over');});
    els.dropZone.addEventListener('dragleave',()=>els.dropZone.classList.remove('drag-over'));
    els.dropZone.addEventListener('drop',e=>{e.preventDefault();els.dropZone.classList.remove('drag-over');if(e.dataTransfer.files.length){const f=e.dataTransfer.files[0];if(!isValidPcapFile(f)){showError('Invalid file type. Please select a .pcap, .pcapng, or .cap file.');return;}loadFile(f);}});
    if(isTauri){
      // Intercept the label click to use native dialog instead of HTML file input
      const label=els.fileInput.closest('label')||els.fileInput.parentElement;
      label.addEventListener('click',e=>{e.preventDefault();openNativeFileDialog();});
    } else {
      els.fileInput.addEventListener('change',e=>{if(e.target.files.length){const f=e.target.files[0];if(!isValidPcapFile(f)){showError('Invalid file type. Please select a .pcap, .pcapng, or .cap file.');e.target.value='';return;}loadFile(f);}});
    }
  }
  function loadFileFromBuffer(arrayBuffer,fileName){
    AppState.fileName=fileName;
    els.uploadOverlay.classList.add('hidden');els.loadingOverlay.classList.remove('hidden');
    els.loadingStatus.textContent=`Parsing ${fileName}...`;
    try{
      const result=PcapParser.parse(arrayBuffer);
      AppState.packets=result.packets;AppState.fileInfo=result.fileInfo;
      AppState.computeDerivedData();loadAnnotations();
      els.loadingStatus.textContent=`Rendering ${AppState.packets.length} packets...`;
      setTimeout(()=>{
        els.loadingOverlay.classList.add('hidden');els.dashboard.classList.remove('hidden');
        els.fileInfo.textContent=`${fileName} | ${AppState.packets.length} packets | ${AppState.fileInfo.format}`;
        populateProtocolFilter();renderAll();
      },50);
    }catch(err){els.loadingOverlay.classList.add('hidden');els.uploadOverlay.classList.remove('hidden');showError('Failed to parse capture file. It may be corrupted.',err);}
  }
  function loadFile(file){
    AppState.fileName=file.name;
    els.uploadOverlay.classList.add('hidden');els.loadingOverlay.classList.remove('hidden');
    els.loadingStatus.textContent=`Parsing ${file.name}...`;
    const reader=new FileReader();
    reader.onload=function(e){
      try{
        const result=PcapParser.parse(e.target.result);
        AppState.packets=result.packets;AppState.fileInfo=result.fileInfo;
        AppState.computeDerivedData();loadAnnotations();
        els.loadingStatus.textContent=`Rendering ${AppState.packets.length} packets...`;
        setTimeout(()=>{
          els.loadingOverlay.classList.add('hidden');els.dashboard.classList.remove('hidden');
          els.fileInfo.textContent=`${file.name} | ${AppState.packets.length} packets | ${AppState.fileInfo.format}`;
          populateProtocolFilter();renderAll();
        },50);
      }catch(err){els.loadingOverlay.classList.add('hidden');els.uploadOverlay.classList.remove('hidden');showError('Failed to parse capture file. It may be corrupted.',err);}
    };
    reader.readAsArrayBuffer(file);
  }

  // ===== Render =====
  function renderAll(){renderNetworkGraph();renderTimeline();renderProtocolCharts();renderPacketTable();}
  function onFilterChange(){
    AppState.applyFilters();
    AppState.selectedPacketIdx=-1;AppState.diffPacketB=null;
    if(AppState.filterError){els.filterError.textContent=AppState.filterError;els.filterError.classList.remove('hidden');}
    else els.filterError.classList.add('hidden');
    renderPacketTable();updateNetworkHighlights();renderProtocolCharts();saveStateToURL();
  }

  // ===== Coloring (Feature 3) =====
  const COLORING_PRESETS={
    security:[{name:'RST',field:'tcp.flags.rst',operator:'==',value:'true',color:'#ef4444',enabled:true},{name:'SYN-only',field:'tcp.flags.syn',operator:'==',value:'true',color:'#f59e0b',enabled:true}],
    web:[{name:'HTTP',field:'protocol',operator:'==',value:'HTTP',color:'#22c55e',enabled:true},{name:'DNS',field:'protocol',operator:'==',value:'DNS',color:'#3b82f6',enabled:true}],
  };
  // P9: Cached coloring rule evaluation
  function evaluateColoringRules(pkt){
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
  function invalidateColoringCache(){_coloringCache=new Map();_coloringCacheVersion++;}

  // ===== Network Graph =====
  // P5: Cache simulation to avoid recreating on resize/theme change
  let _graphSim = null, _graphDataKey = '';
  function renderNetworkGraph(){
    const container=$('panel-network').querySelector('.panel-body');
    const svg=d3.select('#network-graph');svg.selectAll('*').remove();
    const W=container.clientWidth,H=container.clientHeight;if(!W||!H)return;
    svg.attr('viewBox',`0 0 ${W} ${H}`);
    const layer=AppState.graphLayer;
    // P5: Check if data changed; if not, just resize existing simulation
    const newDataKey=AppState.packets.length+'_'+layer+'_'+AppState.graphHostLimit;
    if(_graphSim&&_graphDataKey===newDataKey){
      _graphSim.force('center',d3.forceCenter(W/2,H/2));
      _graphSim.alpha(0.1).restart();
      return;
    }
    _graphDataKey=newDataKey;
    if(_graphSim){_graphSim.stop();_graphSim=null;}
    let nodeMap=new Map(),edgeMap=new Map();
    // Build nodes/edges based on layer
    for(const p of AppState.packets){
      let src,dst;
      if(layer==='L2'){src=p.srcMAC;dst=p.dstMAC;}
      else if(layer==='L4'){src=p.srcIP&&p.srcPort?`${p.srcIP}:${p.srcPort}`:p.srcIP;dst=p.dstIP&&p.dstPort?`${p.dstIP}:${p.dstPort}`:p.dstIP;}
      else{src=p.srcIP;dst=p.dstIP;}
      if(!src||!dst)continue;
      const sz=p.originalLength||p.capturedLength;
      nodeMap.set(src,(nodeMap.get(src)||0)+sz);nodeMap.set(dst,(nodeMap.get(dst)||0)+sz);
      const ek=[src,dst].sort().join('|');
      const ed=edgeMap.get(ek)||{source:src,target:dst,packets:0,bytes:0,protocol:p.protocol};
      ed.packets++;ed.bytes+=sz;edgeMap.set(ek,ed);
    }
    // Limit nodes by traffic (configurable via slider)
    const hostLimit=AppState.graphHostLimit;
    let nodeArr=[...nodeMap.entries()].sort((a,b)=>b[1]-a[1]);
    if(nodeArr.length>hostLimit)nodeArr=nodeArr.slice(0,hostLimit);
    const topNodes=new Set(nodeArr.map(n=>n[0]));
    const nodes=nodeArr.map(([id,bytes])=>({id,bytes}));
    const edges=[...edgeMap.values()].filter(e=>topNodes.has(e.source)&&topNodes.has(e.target));
    if(!nodes.length){els.hostCount.textContent='No hosts';return;}
    els.hostCount.textContent=`${nodes.length} ${layer==='L2'?'MACs':layer==='L4'?'endpoints':'hosts'}`;
    const maxBytes=Math.max(...nodes.map(n=>n.bytes));
    const rScale=d3.scaleSqrt().domain([0,maxBytes]).range([4,layer==='L4'?15:22]);
    const g=svg.append('g');
    const zoom=d3.zoom().scaleExtent([0.2,5]).on('zoom',e=>g.attr('transform',e.transform));
    svg.call(zoom);
    const sim=d3.forceSimulation(nodes).force('link',d3.forceLink(edges).id(d=>d.id).distance(80))
      .force('charge',d3.forceManyBody().strength(-150)).force('center',d3.forceCenter(W/2,H/2)).force('collision',d3.forceCollide().radius(d=>rScale(d.bytes)+5));
    _graphSim=sim; // P5: store simulation reference
    const linkSel=g.selectAll('.link').data(edges).join('line').attr('class','link').attr('stroke',d=>protoColor(d.protocol)).attr('stroke-width',d=>Math.max(1,Math.min(4,d.packets/10)));
    const nodeSel=g.selectAll('.node').data(nodes).join('g').attr('class','node')
      .call(d3.drag().on('start',(e,d)=>{if(!e.active)sim.alphaTarget(0.3).restart();d.fx=d.x;d.fy=d.y;})
        .on('drag',(e,d)=>{d.fx=e.x;d.fy=e.y;}).on('end',(e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}));
    nodeSel.append('circle').attr('r',d=>rScale(d.bytes)).attr('fill',d=>{
      if(layer==='L3'||layer==='L4'){
        const ip=d.id.split(':')[0];
        if(AppState.darkWebFlags.has(ip)&&AppState.darkWebFlags.get(ip).size>0)return '#a855f7';
        const tf=AppState.tunnelFlags.get(ip);if(tf&&tf.size>0)return '#ef4444';
        if(!isPrivateIP(ip))return '#f59e0b';
      }
      return protoColor('Other');
    });
    nodeSel.append('text').attr('class','node-label').attr('dy',d=>rScale(d.bytes)+12).text(d=>d.id.length>20?d.id.slice(0,18)+'..':d.id);
    if(layer==='L3'){
      nodeSel.append('text').attr('class','node-hostname').attr('dy',d=>rScale(d.bytes)+21).text(d=>AppState.dnsMap.get(d.id)||'');
      nodeSel.append('text').attr('class','node-os').attr('dy',d=>rScale(d.bytes)+29).text(d=>{const fp=AppState.osFingerprints.get(d.id);return fp?fp.os:'';});
    }
    nodeSel.on('click',(e,d)=>{
      const ip=layer==='L4'?d.id.split(':')[0]:d.id;
      if(AppState.filters.selectedHost===ip){AppState.filters.selectedHost=null;}else{AppState.filters.selectedHost=ip;}
      onFilterChange();renderTimeline();
    }).on('mouseover',(e,d)=>{
      const ip=d.id.split(':')[0];let html=`<div class="tip-label">Host</div><div class="tip-value">${escapeHTML(d.id)}</div><div class="tip-label">Traffic</div><div class="tip-value">${formatBytes(d.bytes)}</div>`;
      const hn=AppState.dnsMap.get(ip);if(hn)html+=`<div class="tip-label">Hostname</div><div class="tip-value">${escapeHTML(hn)}</div>`;
      const fp=AppState.osFingerprints.get(ip);if(fp)html+=`<div class="tip-label">OS</div><div class="tip-value">${escapeHTML(fp.os)} (${fp.confidence}%)</div>`;
      const tf=AppState.tunnelFlags.get(ip);if(tf&&tf.size>0)html+=`<div class="tip-label">Tunnels</div><div class="tip-value">${escapeHTML([...tf].join(', '))}</div>`;
      const dw=AppState.darkWebFlags.get(ip);if(dw&&dw.size>0)html+=`<div class="tip-label">Dark Web Ports</div><div class="tip-value">${[...dw.entries()].map(([port,cnt])=>`${DARKWEB_PORTS[port]||port} (${cnt})`).join(', ')}</div>`;
      showTooltip(html,e.pageX,e.pageY);
    }).on('mouseout',hideTooltip);
    // Subnet hulls for L3
    let hullSel=null;
    if(layer==='L3'&&nodes.length>4){
      const subnetNodes=new Map();
      for(const n of nodes){
        const sn=getSubnet(n.id);if(!sn)continue;
        if(!subnetNodes.has(sn))subnetNodes.set(sn,[]);
        subnetNodes.get(sn).push(n);
      }
      const hullData=[];let ci=0;
      for(const[sn,snNodes]of subnetNodes){
        if(snNodes.length>=2){hullData.push({subnet:sn,nodes:snNodes,color:SUBNET_COLORS[ci%SUBNET_COLORS.length],isPrivate:isPrivateIP(snNodes[0].id)});ci++;}
      }
      if(hullData.length){
        hullSel=g.selectAll('.subnet-hull').data(hullData).join('path').attr('class','subnet-hull')
          .attr('fill',d=>d.color).attr('stroke',d=>d.color);
        g.selectAll('.subnet-group-label').data(hullData).join('text').attr('class','subnet-group-label')
          .text(d=>`${d.subnet}${d.isPrivate?' (internal)':' (external)'}`);
      }
    }
    sim.on('tick',()=>{
      linkSel.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y).attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
      nodeSel.attr('transform',d=>`translate(${d.x},${d.y})`);
      // Update subnet hulls
      if(hullSel){
        hullSel.attr('d',d=>{
          const pts=d.nodes.map(n=>[n.x,n.y]);
          if(pts.length<3){const[x,y]=pts[0]||[0,0];return `M${x-30},${y-30}L${x+30},${y-30}L${x+30},${y+30}L${x-30},${y+30}Z`;}
          const hull=d3.polygonHull(pts);
          if(!hull)return '';
          // Expand hull slightly
          const cx=d3.mean(hull,p=>p[0]),cy=d3.mean(hull,p=>p[1]);
          const expanded=hull.map(([x,y])=>[x+(x-cx)*0.3,y+(y-cy)*0.3]);
          return 'M'+expanded.map(p=>p.join(',')).join('L')+'Z';
        });
        g.selectAll('.subnet-group-label').attr('x',d=>d3.mean(d.nodes,n=>n.x)).attr('y',d=>d3.mean(d.nodes,n=>n.y)-Math.max(...d.nodes.map(n=>rScale(n.bytes)))-15);
      }
    });
  }
  function updateNetworkHighlights(){
    const host=AppState.filters.selectedHost;
    d3.selectAll('#network-graph .node').classed('dimmed',d=>host&&d.id!==host&&!d.id.startsWith(host+':'));
    d3.selectAll('#network-graph .link').classed('dimmed',d=>host&&d.source.id!==host&&d.target.id!==host&&!d.source.id.startsWith(host+':')&&!d.target.id.startsWith(host+':'));
  }

  // ===== Timeline =====
  function renderTimeline(){
    if(AppState.heatmapMode){renderHeatmapTimeline();return;}
    const container=$('panel-timeline').querySelector('.panel-body');
    const canvas=$('timeline-canvas'),svgEl=$('timeline-svg'),brushSvg=d3.select('#timeline-brush');
    const W=container.clientWidth,H=container.clientHeight-50;if(W<=0||H<=0)return;
    canvas.width=W;canvas.height=H;canvas.style.width=W+'px';canvas.style.height=H+'px';
    svgEl.setAttribute('viewBox',`0 0 ${W} ${H}`);svgEl.setAttribute('width',W);svgEl.setAttribute('height',H);
    const pkts=AppState.packets;if(!pkts.length)return;
    const tMin=pkts[0].timestamp,tMax=pkts[pkts.length-1].timestamp;
    const dur=(tMax-tMin)/1000;
    els.timelineInfo.textContent=`${dur.toFixed(2)}s`;
    const margin={top:10,right:15,bottom:25,left:45};
    const xScale=d3.scaleLinear().domain([tMin,tMax]).range([margin.left,W-margin.right]);
    // Canvas: draw packets
    const ctx=canvas.getContext('2d');ctx.clearRect(0,0,W,H);
    const host=AppState.filters.selectedHost;
    for(const p of pkts){
      const x=xScale(p.timestamp);
      const y=margin.top+Math.random()*(H-margin.top-margin.bottom);
      const dim=host&&p.srcIP!==host&&p.dstIP!==host;
      ctx.globalAlpha=dim?0.08:0.6;ctx.fillStyle=protoColor(p.protocol);
      ctx.beginPath();ctx.arc(x,y,2,0,Math.PI*2);ctx.fill();
      if(p.anomalies.length>0){ctx.globalAlpha=dim?0.05:0.4;ctx.strokeStyle='#ef4444';ctx.lineWidth=1;ctx.beginPath();ctx.arc(x,y,5,0,Math.PI*2);ctx.stroke();}
    }
    ctx.globalAlpha=1;
    // SVG axes
    const svgD3=d3.select(svgEl);svgD3.selectAll('*').remove();
    const xAxis=d3.axisBottom(xScale).ticks(6).tickFormat(d=>`${((d-tMin)/1000).toFixed(1)}s`);
    svgD3.append('g').attr('class','timeline-axis').attr('transform',`translate(0,${H-margin.bottom})`).call(xAxis);
    // Brush
    brushSvg.selectAll('*').remove();brushSvg.attr('viewBox',`0 0 ${W} 50`).attr('width',W).attr('height',50);
    const brushXScale=d3.scaleLinear().domain([tMin,tMax]).range([margin.left,W-margin.right]);
    const brush=d3.brushX().extent([[margin.left,5],[W-margin.right,45]]).on('end',e=>{
      if(!e.selection){AppState.filters.timeRange=null;}else{AppState.filters.timeRange=[brushXScale.invert(e.selection[0]),brushXScale.invert(e.selection[1])];}
      onFilterChange();
    });
    brushSvg.append('g').call(brush);
    // Mini overview in brush area
    const bCtx=document.createElement('canvas');bCtx.width=W;bCtx.height=50;
    const bc=bCtx.getContext('2d');bc.globalAlpha=0.3;
    const numBins=Math.min(200,W);const binW=(tMax-tMin)/numBins||1;const bins=new Array(numBins).fill(0);
    for(const p of pkts){const idx=Math.min(Math.floor((p.timestamp-tMin)/binW),numBins-1);if(idx>=0)bins[idx]++;}
    const maxBin=Math.max(...bins,1);
    for(let i=0;i<numBins;i++){const bx=margin.left+(i/numBins)*(W-margin.left-margin.right);const bw=(W-margin.left-margin.right)/numBins;const bh=(bins[i]/maxBin)*35;bc.fillStyle='#6366f1';bc.fillRect(bx,45-bh,bw,bh);}
  }

  // ===== Protocol Charts =====
  function renderProtocolCharts(){renderPieChart();renderBarChart();}
  function renderPieChart(){
    const c=$('panel-protocols').querySelector('.chart-container');if(!c)return;
    const svg=d3.select('#protocol-pie');svg.selectAll('*').remove();
    const W=c.clientWidth,H=c.clientHeight;if(!W||!H)return;
    svg.attr('viewBox',`0 0 ${W} ${H}`);
    const data=[...AppState.protocolStats.entries()].map(([k,v])=>({protocol:k,count:v})).sort((a,b)=>b.count-a.count);
    if(!data.length)return;
    const radius=Math.min(W,H)/2-30;const g=svg.append('g').attr('transform',`translate(${W/2},${H/2})`);
    const pie=d3.pie().value(d=>d.count).sort(null);const arc=d3.arc().innerRadius(radius*0.4).outerRadius(radius);
    const slices=g.selectAll('path').data(pie(data)).join('path').attr('d',arc).attr('fill',d=>protoColor(d.data.protocol)).attr('stroke','rgba(0,0,0,0.3)').attr('stroke-width',1).style('cursor','pointer');
    slices.on('click',(e,d)=>{
      if(AppState.filters.protocolFilter===d.data.protocol)AppState.filters.protocolFilter=null;else AppState.filters.protocolFilter=d.data.protocol;
      onFilterChange();renderTimeline();
    }).on('mouseover',(e,d)=>{showTooltip(`<div class="tip-value">${escapeHTML(d.data.protocol)}: ${d.data.count} packets</div>`,e.pageX,e.pageY);}).on('mouseout',hideTooltip);
    // Labels
    const labelArc=d3.arc().innerRadius(radius*0.75).outerRadius(radius*0.75);
    g.selectAll('text').data(pie(data)).join('text').attr('transform',d=>`translate(${labelArc.centroid(d)})`).attr('text-anchor','middle').attr('font-size','10px').text(d=>d.data.count/d3.sum(data,dd=>dd.count)>0.05?d.data.protocol:'');
  }
  function renderBarChart(){
    const containers=$('panel-protocols').querySelectorAll('.chart-container');const c=containers[1];if(!c)return;
    const svg=d3.select('#protocol-bar');svg.selectAll('*').remove();
    const W=c.clientWidth,H=c.clientHeight;if(!W||!H)return;
    svg.attr('viewBox',`0 0 ${W} ${H}`);
    const data=[...AppState.protocolStats.entries()].map(([k,v])=>({protocol:k,count:v})).sort((a,b)=>b.count-a.count).slice(0,8);
    if(!data.length)return;
    const m={top:10,right:10,bottom:30,left:50};
    const x=d3.scaleBand().domain(data.map(d=>d.protocol)).range([m.left,W-m.right]).padding(0.3);
    const y=d3.scaleLinear().domain([0,d3.max(data,d=>d.count)]).nice().range([H-m.bottom,m.top]);
    svg.append('g').attr('class','axis').attr('transform',`translate(0,${H-m.bottom})`).call(d3.axisBottom(x).tickSize(0));
    svg.append('g').attr('class','axis').attr('transform',`translate(${m.left},0)`).call(d3.axisLeft(y).ticks(5).tickFormat(d3.format('.2s')));
    svg.selectAll('.bar').data(data).join('rect').attr('class','bar').attr('x',d=>x(d.protocol)).attr('y',d=>y(d.count)).attr('width',x.bandwidth()).attr('height',d=>H-m.bottom-y(d.count)).attr('fill',d=>protoColor(d.protocol)).attr('rx',3);
  }

  // ===== Packet Table =====
  let _tableClickDelegated=false;
  function renderPacketTable(){
    // P7: applyFilters() already called by onFilterChange() and renderAll() callers
    els.tablePacketCount.textContent=`${AppState.filteredPackets.length} packets`;
    _rowPool.length=0;_prevStart=-1;_prevEnd=-1;
    els.tableBody.innerHTML=`<div class="table-spacer" style="height:${AppState.filteredPackets.length*ROW_HEIGHT}px"></div>`;
    renderVisibleRows();
    els.tableBody.onscroll=debounce(renderVisibleRows,16);
    // Event delegation for row interactions (set up once)
    if(!_tableClickDelegated){
      _tableClickDelegated=true;
      els.tableBody.addEventListener('click',e=>{
        const row=e.target.closest('.table-row');if(!row)return;
        const idx=parseInt(row.dataset.idx,10);if(isNaN(idx))return;
        const p=AppState.filteredPackets[idx];if(!p)return;
        // Star click
        if(e.target.closest('.col-star')){e.stopPropagation();toggleBookmark(p.number);return;}
        // Note click
        if(e.target.closest('.col-note')){e.stopPropagation();showNotePopover(p.number,e);return;}
        // Row click
        if(e.shiftKey&&AppState.selectedPacketIdx>=0){
          AppState.diffPacketB=p;
          els.btnDiff.classList.remove('hidden');
          renderVisibleRows();
          return;
        }
        AppState.selectedPacketIdx=idx;AppState.diffPacketB=null;els.btnDiff.classList.add('hidden');
        showPacketDetail(p);renderVisibleRows();
      });
    }
  }
  // Row pool for recycling DOM nodes
  const _rowPool=[];
  let _prevStart=-1,_prevEnd=-1;
  function _acquireRow(){
    if(_rowPool.length>0)return _rowPool.pop();
    const row=document.createElement('div');
    row.className='table-row';
    // Pre-create child structure once
    row.innerHTML=`<div class="col col-star"></div>`+
      `<div class="col col-note"></div>`+
      `<div class="col col-no"></div>`+
      `<div class="col col-time"></div>`+
      `<div class="col col-src"></div>`+
      `<div class="col col-dst"></div>`+
      `<div class="col col-proto"><span class="proto-tag"></span></div>`+
      `<div class="col col-len"></div>`+
      `<div class="col col-info"></div>`;
    return row;
  }
  function _releaseRow(row){
    row.remove();
    _rowPool.push(row);
  }
  function _updateRow(row,i){
    const p=AppState.filteredPackets[i];if(!p)return;
    // Update classes
    row.className='table-row';
    if(i===AppState.selectedPacketIdx)row.classList.add('selected');
    if(AppState.diffPacketB&&p.number===AppState.diffPacketB.number)row.classList.add('diff-selected');
    if(p.anomalies.length>0)row.classList.add('anomaly');
    if(AppState.bookmarks.has(p.number))row.classList.add('bookmarked');
    const customColor=evaluateColoringRules(p);
    const bgColor=customColor?hexToRGBA(customColor,0.15):hexToRGBA(protoColor(p.protocol),0.06);
    row.style.top=(i*ROW_HEIGHT)+'px';row.style.background=bgColor;
    row.dataset.idx=i;
    // Update cell contents
    const cols=row.children;
    const hasNote=AppState.annotations.has(p.number);
    cols[0].textContent=AppState.bookmarks.has(p.number)?'\u2605':'\u2606';
    cols[1].className='col col-note'+(hasNote?' has-note':'');
    cols[1].dataset.pkt=p.number;
    cols[1].textContent=hasNote?'\u270E':'\u00B7';
    cols[2].textContent=p.number;
    cols[3].textContent=p.relativeTime!==undefined?p.relativeTime.toFixed(4):'';
    cols[4].textContent=p.srcIP||p.srcMAC||'';
    cols[5].textContent=p.dstIP||p.dstMAC||'';
    const tag=cols[6].firstChild;
    tag.textContent=p.protocol;tag.style.background=hexToRGBA(protoColor(p.protocol),0.25);tag.style.color=protoColor(p.protocol);
    cols[7].textContent=p.originalLength||p.capturedLength;
    let infoSuffix='';
    if(p.anomalies.length)infoSuffix+=' \u26A0';
    const dwPort=getDarkWebLabel(p.srcPort)||getDarkWebLabel(p.dstPort);
    if(dwPort)infoSuffix+=' \uD83D\uDD35';
    cols[8].textContent=(p.info||'')+infoSuffix;
  }
  function renderVisibleRows(){
    const sb=els.tableBody;const scrollTop=sb.scrollTop;
    const visibleH=sb.clientHeight;const start=Math.max(0,Math.floor(scrollTop/ROW_HEIGHT)-BUFFER);
    const end=Math.min(AppState.filteredPackets.length,Math.ceil((scrollTop+visibleH)/ROW_HEIGHT)+BUFFER);
    const spacer=sb.querySelector('.table-spacer');
    // Collect existing rows keyed by data index
    const existingRows=new Map();
    sb.querySelectorAll('.table-row').forEach(r=>{
      const idx=parseInt(r.dataset.idx,10);
      if(!isNaN(idx)&&idx>=start&&idx<end){
        existingRows.set(idx,r);
      } else {
        _releaseRow(r);
      }
    });
    const frag=document.createDocumentFragment();
    for(let i=start;i<end;i++){
      const p=AppState.filteredPackets[i];if(!p)continue;
      let row=existingRows.get(i);
      if(row){
        existingRows.delete(i);
        _updateRow(row,i);
      } else {
        row=_acquireRow();
        _updateRow(row,i);
        frag.appendChild(row);
      }
    }
    // Release any remaining rows not in new range
    existingRows.forEach(r=>_releaseRow(r));
    if(frag.childNodes.length){if(spacer)spacer.after(frag); else sb.appendChild(frag);}
    _prevStart=start;_prevEnd=end;
  }

  // ===== Packet Detail =====
  function showPacketDetail(pkt){
    els.detailPane.classList.remove('hidden');els.detailPacketNum.textContent=pkt.number;
    // Layer tree
    let layerHTML='';
    for(const[name,fields]of Object.entries(pkt.layers)){
      layerHTML+=`<div class="layer-group"><div class="layer-header">${escapeHTML(name.toUpperCase())}</div><div class="layer-fields">`;
      for(const[k,v]of Object.entries(fields)){
        if(typeof v==='object'&&v!==null&&!Array.isArray(v)){
          for(const[sk,sv]of Object.entries(v))layerHTML+=`<div class="layer-field"><span class="field-name">${escapeHTML(k)}.${escapeHTML(sk)}: </span><span class="field-value">${escapeHTML(String(sv))}</span></div>`;
        } else {
          layerHTML+=`<div class="layer-field"><span class="field-name">${escapeHTML(k)}: </span><span class="field-value">${escapeHTML(Array.isArray(v)?JSON.stringify(v):String(v))}</span></div>`;
        }
      }
      layerHTML+='</div></div>';
    }
    // OS info
    if(pkt.srcIP){
      const fp=AppState.osFingerprints.get(pkt.srcIP);
      if(fp)layerHTML+=`<div class="layer-group"><div class="layer-header">OS FINGERPRINT</div><div class="layer-fields"><div class="layer-field"><span class="field-name">OS: </span><span class="field-value">${escapeHTML(fp.os)} (${fp.confidence}%)</span></div><div class="layer-field"><span class="field-name">TTL: </span><span class="field-value">${fp.ttl}</span></div></div></div>`;
      const tf=AppState.tunnelFlags.get(pkt.srcIP);
      if(tf&&tf.size)layerHTML+=`<div class="layer-group"><div class="layer-header">TUNNEL FLAGS</div><div class="layer-fields"><div class="layer-field"><span class="field-value">${[...tf].join(', ')}</span></div></div></div>`;
      // Dark Web port flags
      const dwSrc=AppState.darkWebFlags.get(pkt.srcIP);
      const dwDst=AppState.darkWebFlags.get(pkt.dstIP);
      if(dwSrc||dwDst){
        layerHTML+=`<div class="layer-group"><div class="layer-header" style="color:#a855f7">DARK WEB / PROXY PORTS</div><div class="layer-fields">`;
        if(dwSrc){for(const[port,cnt]of dwSrc)layerHTML+=`<div class="layer-field"><span class="field-name">${pkt.srcIP}:</span><span class="field-value" style="color:#a855f7"> Port ${port} (${DARKWEB_PORTS[port]||'Unknown'}) - ${cnt} packets</span></div>`;}
        if(dwDst){for(const[port,cnt]of dwDst)layerHTML+=`<div class="layer-field"><span class="field-name">${pkt.dstIP}:</span><span class="field-value" style="color:#a855f7"> Port ${port} (${DARKWEB_PORTS[port]||'Unknown'}) - ${cnt} packets</span></div>`;}
        layerHTML+=`</div></div>`;
      }
      // IoC match indicator
      if(AppState.iocList.length>0){
        const iocSet=new Set(AppState.iocList);
        const hit=(pkt.srcIP&&iocSet.has(pkt.srcIP.toLowerCase()))||(pkt.dstIP&&iocSet.has(pkt.dstIP.toLowerCase()))||(pkt.dnsQueryName&&iocSet.has(pkt.dnsQueryName.toLowerCase()));
        if(hit)layerHTML+=`<div class="layer-group"><div class="layer-header" style="color:var(--danger)">THREAT INTELLIGENCE</div><div class="layer-fields"><div class="layer-field"><span class="field-value" style="color:var(--danger)">This packet matches a loaded IoC indicator!</span></div></div></div>`;
      }
    }
    els.detailLayers.innerHTML=layerHTML;
    // S3: Event delegation for layer header toggling (replaces inline onclick)
    els.detailLayers.querySelectorAll('.layer-header').forEach(h=>{
      h.addEventListener('click',()=>{h.classList.toggle('collapsed');const fields=h.nextElementSibling;if(fields)fields.classList.toggle('hidden');});
    });
    // Hex dump
    els.hexDump.innerHTML=generateHexDump(pkt.rawBytes);
    // Show diff button if second packet selected
    if(AppState.diffPacketB)els.btnDiff.classList.remove('hidden');
    scrollToSelectedRow();
  }
  function closeDetailPane(){els.detailPane.classList.add('hidden');}
  function generateHexDump(bytes){
    let html='';
    for(let i=0;i<bytes.length;i+=16){
      html+=`<span class="hex-offset">${i.toString(16).padStart(8,'0')}</span>  `;
      let ascii='';
      for(let j=0;j<16;j++){
        if(i+j<bytes.length){const b=bytes[i+j];html+=b.toString(16).padStart(2,'0')+' ';ascii+=b>=32&&b<=126?String.fromCharCode(b):'.';}
        else{html+='   ';ascii+=' ';}
        if(j===7)html+=' ';
      }
      html+=` <span class="hex-ascii">${escapeHTML(ascii)}</span>\n`;
    }
    return html;
  }
  function scrollToSelectedRow(){
    if(AppState.selectedPacketIdx<0)return;
    const top=AppState.selectedPacketIdx*ROW_HEIGHT;
    const sb=els.tableBody;
    if(top<sb.scrollTop||top>sb.scrollTop+sb.clientHeight-ROW_HEIGHT)sb.scrollTop=top-sb.clientHeight/2;
  }

  // ===== TCP Stream =====
  function followTCPStream(){
    const idx=AppState.selectedPacketIdx;if(idx<0)return;
    const pkt=AppState.filteredPackets[idx];if(!pkt||!pkt.tcpFlags)return;
    const matchKey=`${pkt.srcIP}:${pkt.srcPort}-${pkt.dstIP}:${pkt.dstPort}`;
    const revKey=`${pkt.dstIP}:${pkt.dstPort}-${pkt.srcIP}:${pkt.srcPort}`;
    const client=pkt.srcIP+':'+pkt.srcPort;
    const streamPkts=AppState.packets.filter(sp=>{const k=`${sp.srcIP}:${sp.srcPort}-${sp.dstIP}:${sp.dstPort}`;return k===matchKey||k===revKey;});
    let html='';let totalBytes=0;
    for(const sp of streamPkts){
      if(sp.tcpPayloadLength>0&&sp.rawBytes){
        const payload=sp.rawBytes.slice(sp.tcpPayloadOffset,sp.tcpPayloadOffset+sp.tcpPayloadLength);
        const isClient=(sp.srcIP+':'+sp.srcPort)===client;
        let text='';for(let i=0;i<payload.length;i++){const c=payload[i];text+=c>=32&&c<=126?String.fromCharCode(c):c===10?'\n':c===13?'':'.'}
        html+=`<span class="${isClient?'stream-client':'stream-server'}">${escapeHTML(text)}</span>`;
        totalBytes+=payload.length;
      }
    }
    els.streamContent.innerHTML=html||'No payload data';
    els.streamInfo.textContent=`${streamPkts.length} packets, ${formatBytes(totalBytes)}`;
    els.streamModal.classList.remove('hidden');
  }

  // ===== Conversations =====
  function showConversations(){
    const tbody=document.querySelector('#conversations-table tbody');
    const conns=[...AppState.connections.values()].sort((a,b)=>b.bytes-a.bytes);
    tbody.innerHTML=conns.map(c=>{
      const dur=(c.lastTs-c.firstTs)/1000;
      return `<tr><td>${escapeHTML(c.a)}</td><td>${escapeHTML(c.b)}</td><td>${c.packets}</td><td>${formatBytes(c.bytes)}</td><td>${dur.toFixed(2)}s</td><td>${[...c.protocols].join(', ')}</td></tr>`;
    }).join('');
    els.conversationsModal.classList.remove('hidden');
  }

  // ===== Bookmarks =====
  function toggleBookmark(num){if(AppState.bookmarks.has(num))AppState.bookmarks.delete(num);else AppState.bookmarks.add(num);renderVisibleRows();}

  // ===== Export =====
  function exportCSV(){
    const rows=[['#','Time','Source','Destination','Protocol','Length','Info','Anomalies','Notes']];
    for(const p of AppState.filteredPackets){
      rows.push([p.number,p.relativeTime?.toFixed(6)||'',p.srcIP||'',p.dstIP||'',p.protocol,p.originalLength||p.capturedLength,`"${p.info}"`,p.anomalies.join('; '),`"${AppState.annotations.get(p.number)||''}"`]);
    }
    downloadText(rows.map(r=>r.join(',')).join('\n'),'packets.csv','text/csv');
  }
  function exportJSON(){
    const data=AppState.filteredPackets.map(p=>({number:p.number,time:p.relativeTime,src:p.srcIP,dst:p.dstIP,protocol:p.protocol,length:p.originalLength||p.capturedLength,info:p.info,anomalies:p.anomalies,note:AppState.annotations.get(p.number)||null}));
    downloadText(JSON.stringify(data,null,2),'packets.json','application/json');
  }
  // S8: Properly revoke object URLs after download
  function downloadText(text,name,type){const a=document.createElement('a');const url=URL.createObjectURL(new Blob([text],{type}));a.href=url;a.download=name;a.click();URL.revokeObjectURL(url);}

  // ===== Screenshot =====
  function screenshotPanel(panel){
    const body=panel.querySelector('.panel-body');const svg=body.querySelector('svg');const canvas=body.querySelector('canvas');
    if(canvas){const a=document.createElement('a');a.href=canvas.toDataURL('image/png');a.download='panel.png';a.click();return;}
    if(svg){const clone=svg.cloneNode(true);const s=new XMLSerializer().serializeToString(clone);const blob=new Blob([s],{type:'image/svg+xml'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='panel.svg';a.click();URL.revokeObjectURL(url);}
  }

  // ===== Theme =====
  function toggleTheme(){document.body.dataset.theme=document.body.dataset.theme==='dark'?'light':'dark';renderAll();}

  // ===== Fullscreen =====
  function togglePanelFullscreen(panel){panel.classList.toggle('fullscreen');setTimeout(renderAll,350);}

  // ===== GeoIP Map =====
  function showGeoIPMap(){
    const canvas=els.geoipCanvas;const ctx=canvas.getContext('2d');const W=canvas.width,H=canvas.height;
    ctx.fillStyle='#1a1a2e';ctx.fillRect(0,0,W,H);
    // Simplified continents
    ctx.strokeStyle='#2d3748';ctx.lineWidth=1;ctx.fillStyle='#2d3748';
    const continents=[[160,80,240,140],[350,60,180,120],[350,200,120,100],[580,60,200,160],[640,200,100,80],[80,230,60,50]];
    for(const[x,y,w,h]of continents){ctx.fillRect(x,y,w,h);ctx.strokeRect(x,y,w,h);}
    // Plot IPs
    function ipToPos(ip){
      if(!ip||ip.includes(':'))return null;
      const parts=ip.split('.').map(Number);const first=parts[0];
      let x,y;
      if(first<=50){x=180+Math.random()*200;y=100+Math.random()*100;}
      else if(first<=100){x=380+Math.random()*120;y=80+Math.random()*80;}
      else if(first<=150){x=600+Math.random()*160;y=80+Math.random()*120;}
      else if(first<=200){x=380+Math.random()*100;y=220+Math.random()*60;}
      else{x=100+Math.random()*40;y=240+Math.random()*30;}
      return{x,y};
    }
    for(const[ip,bytes]of AppState.hosts){
      const pos=ipToPos(ip);if(!pos)continue;
      const r=Math.max(3,Math.min(12,Math.sqrt(bytes/10000)));
      ctx.globalAlpha=0.6;ctx.fillStyle=protoColor('Other');
      ctx.beginPath();ctx.arc(pos.x,pos.y,r,0,Math.PI*2);ctx.fill();
      if(r>5){ctx.globalAlpha=0.8;ctx.fillStyle='#e2e8f0';ctx.font='8px sans-serif';ctx.fillText(ip,pos.x+r+2,pos.y+3);}
    }
    ctx.globalAlpha=1;
    els.geoipModal.classList.remove('hidden');
  }

  // ===== Compare =====
  let compareData=null;
  function loadCompareFile(){
    if(isTauri){
      (async()=>{
        try{
          const dialog=window.__TAURI__.dialog;
          const invoke=window.__TAURI__.core.invoke;
          const result=await dialog.open({multiple:false,filters:[{name:'Packet Captures',extensions:['pcap','pcapng','cap']}]});
          if(!result)return;
          const filePath=result.path||result;
          const fileName=filePath.split('/').pop().split('\\').pop();
          const bytes=await invoke('read_file_bytes',{path:filePath});
          const arrayBuffer=new Uint8Array(bytes).buffer;
          const parsed=PcapParser.parse(arrayBuffer);
          compareData={packets:parsed.packets,fileInfo:parsed.fileInfo,name:fileName};showComparison();
        }catch(err){showError('Failed to parse comparison file.',err);}
      })();
      return;
    }
    const input=document.createElement('input');input.type='file';input.accept='.pcap,.pcapng,.cap';
    input.addEventListener('change',e=>{
      if(!e.target.files.length)return;
      if(!isValidPcapFile(e.target.files[0])){showError('Invalid file type. Please select a .pcap, .pcapng, or .cap file.');return;}
      const reader=new FileReader();
      reader.onload=function(ev){
        try{const result=PcapParser.parse(ev.target.result);compareData={packets:result.packets,fileInfo:result.fileInfo,name:e.target.files[0].name};showComparison();}
        catch(err){showError('Failed to parse comparison file.',err);}
      };
      reader.readAsArrayBuffer(e.target.files[0]);
    });
    input.click();
  }
  function showComparison(){
    if(!compareData)return;
    function captureStats(pkts,name){
      const stats={name,total:pkts.length,bytes:0,protocols:{}};
      for(const p of pkts){stats.bytes+=(p.originalLength||p.capturedLength);stats.protocols[p.protocol]=(stats.protocols[p.protocol]||0)+1;}
      return stats;
    }
    const a=captureStats(AppState.packets,AppState.fileName);const b=captureStats(compareData.packets,compareData.name);
    function renderSide(el,s){
      el.innerHTML=`<h3>${escapeHTML(s.name)}</h3>`+
        `<div class="compare-stat"><span class="label">Packets</span><span class="value">${s.total}</span></div>`+
        `<div class="compare-stat"><span class="label">Bytes</span><span class="value">${formatBytes(s.bytes)}</span></div>`+
        Object.entries(s.protocols).sort((a,b)=>b[1]-a[1]).map(([proto,count])=>{
          const pct=(count/s.total*100).toFixed(1);
          return `<div class="compare-stat"><span class="label">${proto}</span><span class="value">${count} (${pct}%)</span></div>`;
        }).join('');
    }
    renderSide($('compare-left'),a);renderSide($('compare-right'),b);
    els.compareModal.classList.remove('hidden');
  }

  // ===== URL State =====
  function saveStateToURL(){
    const f=AppState.filters;const p=new URLSearchParams();
    if(f.selectedHost)p.set('host',f.selectedHost);if(f.protocolFilter)p.set('proto',f.protocolFilter);
    if(f.searchText)p.set('q',f.searchText);
    const hash=p.toString();window.location.hash=hash||'';
  }
  function loadStateFromURL(){
    const p=new URLSearchParams(window.location.hash.slice(1));
    if(p.has('host'))AppState.filters.selectedHost=p.get('host');
    if(p.has('proto'))AppState.filters.protocolFilter=p.get('proto');
    if(p.has('q')){AppState.filters.searchText=p.get('q');els.tableSearch.value=p.get('q');}
  }

  // ===== Feature 2: Protocol Stats =====
  function showProtocolStats(){
    const pkts=AppState.packets;
    function renderTab(tab){
      let html='';
      if(tab==='general'){
        const totalBytes=pkts.reduce((s,p)=>s+(p.originalLength||p.capturedLength),0);
        const dur=pkts.length>1?(pkts[pkts.length-1].timestamp-pkts[0].timestamp)/1000:0;
        html=`<div class="stats-grid">
          <div class="stat-card"><div class="stat-label">Total Packets</div><div class="stat-value">${pkts.length}</div></div>
          <div class="stat-card"><div class="stat-label">Total Bytes</div><div class="stat-value">${formatBytes(totalBytes)}</div></div>
          <div class="stat-card"><div class="stat-label">Duration</div><div class="stat-value">${dur.toFixed(2)}s</div></div>
          <div class="stat-card"><div class="stat-label">Avg Packets/sec</div><div class="stat-value">${dur>0?(pkts.length/dur).toFixed(1):'N/A'}</div></div>
          <div class="stat-card"><div class="stat-label">Avg Bytes/sec</div><div class="stat-value">${dur>0?formatBytes(totalBytes/dur)+'/s':'N/A'}</div></div>
          <div class="stat-card"><div class="stat-label">Avg Packet Size</div><div class="stat-value">${pkts.length>0?Math.round(totalBytes/pkts.length):0} B</div></div>
          <div class="stat-card"><div class="stat-label">Unique Hosts</div><div class="stat-value">${AppState.hosts.size}</div></div>
          <div class="stat-card"><div class="stat-label">Connections</div><div class="stat-value">${AppState.connections.size}</div></div>
        </div>`;
      } else if(tab==='tcp'){
        const tcpPkts=pkts.filter(p=>p.protocol==='TCP'||p.protocol==='HTTP');
        const syns=tcpPkts.filter(p=>p.tcpFlags&&p.tcpFlags.SYN).length;
        const rsts=tcpPkts.filter(p=>p.tcpFlags&&p.tcpFlags.RST).length;
        const retrans=tcpPkts.filter(p=>p.anomalies.includes('Retransmission')).length;
        const payloads=tcpPkts.filter(p=>p.tcpPayloadLength>0);
        const avgPayload=payloads.length>0?Math.round(payloads.reduce((s,p)=>s+p.tcpPayloadLength,0)/payloads.length):0;
        html=`<div class="stats-grid">
          <div class="stat-card"><div class="stat-label">TCP Packets</div><div class="stat-value">${tcpPkts.length}</div></div>
          <div class="stat-card"><div class="stat-label">SYN Packets</div><div class="stat-value">${syns}</div></div>
          <div class="stat-card"><div class="stat-label">RST Packets</div><div class="stat-value">${rsts}</div><div class="stat-sub">${tcpPkts.length?(rsts/tcpPkts.length*100).toFixed(1)+'%':''}</div></div>
          <div class="stat-card"><div class="stat-label">Retransmissions</div><div class="stat-value">${retrans}</div><div class="stat-sub">${tcpPkts.length?(retrans/tcpPkts.length*100).toFixed(2)+'%':''}</div></div>
          <div class="stat-card"><div class="stat-label">Avg Payload</div><div class="stat-value">${avgPayload} B</div></div>
          <div class="stat-card"><div class="stat-label">Unique Connections</div><div class="stat-value">${[...AppState.connections.values()].filter(c=>c.protocols.has('TCP')||c.protocols.has('HTTP')).length}</div></div>
        </div>`;
      } else if(tab==='dns'){
        const dnsPkts=pkts.filter(p=>p.protocol==='DNS');
        const queries=dnsPkts.filter(p=>!p.dnsIsResponse);const responses=dnsPkts.filter(p=>p.dnsIsResponse);
        const nxdomain=dnsPkts.filter(p=>p.dnsRcode===3).length;
        const domains=new Map();for(const p of queries)if(p.dnsQueryName)domains.set(p.dnsQueryName,(domains.get(p.dnsQueryName)||0)+1);
        const topDomains=[...domains.entries()].sort((a,b)=>b[1]-a[1]).slice(0,10);
        html=`<div class="stats-grid">
          <div class="stat-card"><div class="stat-label">Total DNS</div><div class="stat-value">${dnsPkts.length}</div></div>
          <div class="stat-card"><div class="stat-label">Queries</div><div class="stat-value">${queries.length}</div></div>
          <div class="stat-card"><div class="stat-label">Responses</div><div class="stat-value">${responses.length}</div></div>
          <div class="stat-card"><div class="stat-label">NXDOMAIN</div><div class="stat-value">${nxdomain}</div></div>
          <div class="stat-card"><div class="stat-label">Unique Domains</div><div class="stat-value">${domains.size}</div></div>
        </div>`;
        if(topDomains.length)html+=`<h3 style="margin-top:12px;font-size:0.85rem">Top Queried Domains</h3><table class="stats-table"><thead><tr><th>Domain</th><th>Queries</th></tr></thead><tbody>${topDomains.map(([d,c])=>`<tr><td>${escapeHTML(d)}</td><td>${c}</td></tr>`).join('')}</tbody></table>`;
      } else if(tab==='http'){
        const httpPkts=pkts.filter(p=>p.protocol==='HTTP');
        const reqs=httpPkts.filter(p=>p.httpMethod);const resps=httpPkts.filter(p=>p.httpStatusCode);
        const methods={};for(const p of reqs)methods[p.httpMethod]=(methods[p.httpMethod]||0)+1;
        const statuses={};for(const p of resps){const cat=Math.floor(p.httpStatusCode/100)+'xx';statuses[cat]=(statuses[cat]||0)+1;}
        html=`<div class="stats-grid">
          <div class="stat-card"><div class="stat-label">HTTP Packets</div><div class="stat-value">${httpPkts.length}</div></div>
          <div class="stat-card"><div class="stat-label">Requests</div><div class="stat-value">${reqs.length}</div></div>
          <div class="stat-card"><div class="stat-label">Responses</div><div class="stat-value">${resps.length}</div></div>
        </div>`;
        const methodEntries=Object.entries(methods).sort((a,b)=>b[1]-a[1]);
        if(methodEntries.length)html+=`<h3 style="margin-top:12px;font-size:0.85rem">Methods</h3><table class="stats-table"><thead><tr><th>Method</th><th>Count</th></tr></thead><tbody>${methodEntries.map(([m,c])=>`<tr><td>${m}</td><td>${c}</td></tr>`).join('')}</tbody></table>`;
        const statusEntries=Object.entries(statuses).sort();
        if(statusEntries.length)html+=`<h3 style="margin-top:12px;font-size:0.85rem">Status Codes</h3><table class="stats-table"><thead><tr><th>Category</th><th>Count</th></tr></thead><tbody>${statusEntries.map(([s,c])=>`<tr><td>${s}</td><td>${c}</td></tr>`).join('')}</tbody></table>`;
      }
      els.statsContent.innerHTML=html;
    }
    renderTab('general');
    // Tab switching
    els.statsModal.querySelectorAll('.stats-tab').forEach(btn=>{
      btn.onclick=()=>{els.statsModal.querySelectorAll('.stats-tab').forEach(b=>b.classList.remove('active'));btn.classList.add('active');renderTab(btn.dataset.tab);};
    });
    els.statsModal.classList.remove('hidden');
  }

  // ===== Feature 1: Extraction =====
  function _extractPacket(p,text,reqUrlMap,results){
    // P8: Use hoisted regex constants instead of inline regex
    // HTTP Basic Auth
    const authMatch=text.match(RE_BASIC_AUTH);
    if(authMatch){try{const decoded=atob(authMatch[1]);const parts=decoded.split(':');results.push({type:'credential',protocol:'HTTP',src:p.srcIP,dst:p.dstIP,detail:`Basic Auth user="${parts[0]}"`,size:'',pkt:p.number});}catch{}}
    // HTTP Bearer/Token
    const bearerMatch=text.match(RE_BEARER);
    if(bearerMatch)results.push({type:'credential',protocol:'HTTP',src:p.srcIP,dst:p.dstIP,detail:`Bearer token: ${bearerMatch[1]}...`,size:'',pkt:p.number});
    // HTTP Cookie with session-like tokens
    const cookieMatch=text.match(RE_COOKIE);
    if(cookieMatch){const cv=cookieMatch[1];if(RE_SESSION_COOKIE.test(cv))results.push({type:'credential',protocol:'HTTP',src:p.srcIP,dst:p.dstIP,detail:`Session cookie: ${cv.length>70?cv.slice(0,68)+'..':cv}`,size:'',pkt:p.number});}
    // HTTP POST with password-like fields
    if(p.httpMethod==='POST'){const bodyStart=text.indexOf('\r\n\r\n');if(bodyStart>-1){const body=text.slice(bodyStart+4,bodyStart+500);if(RE_PASSWORD_FIELD.test(body)){const sanitized=body.replace(RE_SANITIZE_PASS,'$1****');results.push({type:'credential',protocol:'HTTP',src:p.srcIP,dst:p.dstIP,detail:`POST form data: ${sanitized.length>80?sanitized.slice(0,78)+'..':sanitized}`,size:'',pkt:p.number});}}}
    // HTTP file transfers (responses with Content-Type)
    const ctMatch=text.match(RE_CONTENT_TYPE);
    const clMatch=text.match(RE_CONTENT_LENGTH);
    const cdMatch=text.match(RE_CONTENT_DISP);
    if(ctMatch){
      const ct=ctMatch[1].trim().toLowerCase();
      const skipTypes=['text/html','text/css','text/javascript','application/javascript'];
      if(!skipTypes.includes(ct)){
        const revKey=`${p.dstIP}:${p.dstPort}-${p.srcIP}:${p.srcPort}`;
        const reqs=reqUrlMap.get(revKey);
        let urlInfo='';
        if(reqs&&reqs.length){const req=reqs.shift();urlInfo=req.url;}
        const filename=cdMatch?cdMatch[1]:urlInfo?(urlInfo.split('/').pop().split('?')[0]||urlInfo):'';
        const sizeStr=clMatch?formatBytes(parseInt(clMatch[1])):'';
        const detail=filename?`${filename} [${ct}]`:`[${ct}]`;
        results.push({type:'file',protocol:'HTTP',src:p.srcIP,dst:p.dstIP,detail,size:sizeStr,pkt:p.number});
      }
    }
    // HTTP request URLs (GET for files based on extension)
    if(p.httpMethod==='GET'&&p.httpUrl){
      const ext=(p.httpUrl.split('?')[0].split('.').pop()||'').toLowerCase();
      if(FILE_EXTS.has(ext)){results.push({type:'request',protocol:'HTTP',src:p.srcIP,dst:p.dstIP,detail:`${p.httpMethod} ${p.httpUrl.length>90?p.httpUrl.slice(0,88)+'..':p.httpUrl}`,size:'',pkt:p.number});}
    }
    // FTP credentials
    if(p.dstPort===21||p.srcPort===21){
      const userMatch=text.match(RE_FTP_USER);if(userMatch)results.push({type:'credential',protocol:'FTP',src:p.srcIP,dst:p.dstIP,detail:`User: ${userMatch[1]}`,size:'',pkt:p.number});
      const passMatch=text.match(RE_FTP_PASS);if(passMatch)results.push({type:'credential',protocol:'FTP',src:p.srcIP,dst:p.dstIP,detail:'Password: ****',size:'',pkt:p.number});
    }
    // SMTP credentials
    if(p.dstPort===25||p.dstPort===587||p.srcPort===25){
      const smtpAuth=text.match(RE_SMTP_AUTH);if(smtpAuth)results.push({type:'credential',protocol:'SMTP',src:p.srcIP,dst:p.dstIP,detail:`SMTP Auth (${smtpAuth[1]})`,size:'',pkt:p.number});
      const mailFrom=text.match(RE_SMTP_MAIL);if(mailFrom)results.push({type:'credential',protocol:'SMTP',src:p.srcIP,dst:p.dstIP,detail:`Mail from: ${mailFrom[1]}`,size:'',pkt:p.number});
    }
    // Telnet credentials
    if(p.dstPort===23||p.srcPort===23){
      if(text.includes('login:')||text.includes('Password:'))results.push({type:'credential',protocol:'Telnet',src:p.srcIP,dst:p.dstIP,detail:'Telnet login prompt detected',size:'',pkt:p.number});
    }
  }
  function _renderExtractionResults(results){
    let html;
    if(results.length===0)html='<p style="color:var(--text-muted)">No files or credentials detected in this capture.</p>';
    else{
      html=`<p style="color:var(--text-dim);font-size:0.8rem;margin-bottom:10px">${results.length} items found &mdash; ${results.filter(r=>r.type==='file').length} files, ${results.filter(r=>r.type==='request').length} file requests, ${results.filter(r=>r.type==='credential').length} credentials</p>`;
      html+=`<table class="extraction-table"><thead><tr><th>Type</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Details</th><th>Size</th><th>Pkt#</th></tr></thead><tbody>${results.map(r=>`<tr><td><span class="extraction-type ${r.type}">${r.type}</span></td><td>${r.protocol}</td><td>${escapeHTML(r.src||'')}</td><td>${escapeHTML(r.dst||'')}</td><td>${escapeHTML(r.detail)}</td><td>${escapeHTML(r.size)}</td><td>${r.pkt}</td></tr>`).join('')}</tbody></table>`;
    }
    // HTTP Object Export section
    const objects=reconstructHTTPObjects();
    if(objects.length>0){
      html+=`<h3 style="margin-top:16px;font-size:0.9rem">Reconstructed HTTP Objects (${objects.length})</h3>`;
      html+=`<table class="extraction-table"><thead><tr><th>Filename</th><th>Content-Type</th><th>Size</th><th>Status</th><th>URL</th><th>Action</th></tr></thead><tbody>`;
      objects.forEach((obj,i)=>{
        html+=`<tr><td>${escapeHTML(obj.filename)}</td><td>${escapeHTML(obj.contentType)}</td><td>${formatBytes(obj.size)}</td><td>${obj.status}</td><td>${escapeHTML((obj.url||'').slice(0,60))}</td><td><button class="btn-small http-obj-dl" data-idx="${i}">Download</button></td></tr>`;
      });
      html+='</tbody></table>';
    }
    els.extractionContent.innerHTML=html;
    // S1: Wire up download buttons via closure (no global exposure)
    if(objects.length>0){
      els.extractionContent.querySelectorAll('.http-obj-dl').forEach(btn=>{
        btn.addEventListener('click',()=>{
          const idx=parseInt(btn.dataset.idx,10);
          const obj=objects[idx];
          if(obj)downloadBlob(obj.bodyBytes,obj.filename||'download',obj.contentType);
        });
      });
    }
  }
  function showExtractions(){
    els.extractionModal.classList.remove('hidden');
    els.extractionContent.innerHTML='<p style="color:var(--text-muted)">Scanning packets\u2026</p>';
    const results=[];
    // Build reqUrlMap synchronously (lightweight, no regex)
    const reqUrlMap=new Map();
    for(const p of AppState.packets){
      if(p.httpMethod&&p.httpUrl){
        const key=`${p.srcIP}:${p.srcPort}-${p.dstIP}:${p.dstPort}`;
        if(!reqUrlMap.has(key))reqUrlMap.set(key,[]);
        reqUrlMap.get(key).push({url:p.httpUrl,method:p.httpMethod,pkt:p.number});
      }
    }
    // Process packets in async chunks to avoid UI freeze
    const CHUNK=500;
    const packets=AppState.packets;
    let idx=0;
    function processChunk(){
      const chunkEnd=Math.min(idx+CHUNK,packets.length);
      for(;idx<chunkEnd;idx++){
        const p=packets[idx];
        if(p.tcpPayloadLength>0&&p.rawBytes){
          const payload=p.rawBytes.slice(p.tcpPayloadOffset,Math.min(p.tcpPayloadOffset+p.tcpPayloadLength,p.tcpPayloadOffset+2000));
          let text='';try{text=new TextDecoder('ascii',{fatal:false}).decode(payload);}catch{}
          _extractPacket(p,text,reqUrlMap,results);
        }
      }
      if(idx<packets.length){
        els.extractionContent.innerHTML=`<p style="color:var(--text-muted)">Scanning packets\u2026 ${Math.round(idx/packets.length*100)}%</p>`;
        setTimeout(processChunk,0);
      } else {
        _renderExtractionResults(results);
      }
    }
    processChunk();
  }

  // ===== Feature 6: Latency =====
  function showLatency(){
    const results=[];
    // TCP RTT: SYN -> SYN-ACK
    const synMap=new Map();
    for(const p of AppState.packets){
      if(!p.tcpFlags)continue;
      const fwd=`${p.srcIP}:${p.srcPort}-${p.dstIP}:${p.dstPort}`;
      const rev=`${p.dstIP}:${p.dstPort}-${p.srcIP}:${p.srcPort}`;
      if(p.tcpFlags.SYN&&!p.tcpFlags.ACK)synMap.set(fwd,p.timestamp);
      if(p.tcpFlags.SYN&&p.tcpFlags.ACK&&synMap.has(rev)){
        const rtt=p.timestamp-synMap.get(rev);
        results.push({type:'TCP',endpoint:rev.replace('-',' \u2194 '),rtt});synMap.delete(rev);
      }
    }
    // DNS RTT
    const dnsQueryMap=new Map();
    for(const p of AppState.packets){
      if(p.protocol!=='DNS')continue;
      if(!p.dnsIsResponse&&p.dnsQueryName)dnsQueryMap.set(p.dnsQueryName,p.timestamp);
      if(p.dnsIsResponse&&p.dnsQueryName&&dnsQueryMap.has(p.dnsQueryName)){
        const rtt=p.timestamp-dnsQueryMap.get(p.dnsQueryName);
        results.push({type:'DNS',endpoint:p.dnsQueryName,rtt});dnsQueryMap.delete(p.dnsQueryName);
      }
    }
    results.sort((a,b)=>b.rtt-a.rtt);
    let html;
    if(!results.length)html='<p style="color:var(--text-muted)">No RTT measurements available.</p>';
    else html=`<table class="latency-table"><thead><tr><th>Type</th><th>Endpoint</th><th>RTT</th><th>Rating</th></tr></thead><tbody>${results.slice(0,100).map(r=>{
      const ms=r.rtt.toFixed(2);const cls=r.rtt<50?'rtt-fast':r.rtt<200?'rtt-normal':'rtt-slow';const label=r.rtt<50?'Fast':r.rtt<200?'Normal':'Slow';
      return `<tr><td>${r.type}</td><td>${escapeHTML(r.endpoint)}</td><td>${ms} ms</td><td><span class="${cls}">${label}</span></td></tr>`;
    }).join('')}</tbody></table>`;
    els.latencyContent.innerHTML=html;els.latencyModal.classList.remove('hidden');
  }

  // ===== Feature 4: Sequence Diagram =====
  function showSequenceDiagram(){
    // Populate host dropdowns
    const hosts=[...AppState.hosts.entries()].sort((a,b)=>b[1]-a[1]).map(([ip])=>ip);
    for(const sel of[els.seqHostA,els.seqHostB]){
      const val=sel.value;sel.innerHTML='<option value="">Auto</option>'+hosts.map(h=>`<option value="${h}">${h}</option>`).join('');
      sel.value=val;
    }
    renderSequenceSVG();
    els.sequenceModal.classList.remove('hidden');
  }
  function renderSequenceSVG(){
    const svg=d3.select('#sequence-svg');svg.selectAll('*').remove();
    let hostA=els.seqHostA.value,hostB=els.seqHostB.value;
    if(!hostA||!hostB){
      const top=[...AppState.hosts.entries()].sort((a,b)=>b[1]-a[1]);
      if(!hostA&&top[0])hostA=top[0][0];if(!hostB&&top[1])hostB=top[1][0];
    }
    if(!hostA||!hostB)return;
    const pkts=AppState.packets.filter(p=>(p.srcIP===hostA&&p.dstIP===hostB)||(p.srcIP===hostB&&p.dstIP===hostA)).slice(0,200);
    if(!pkts.length)return;
    const margin={top:40,left:100,right:100};const colW=300;const rowH=24;
    const W=margin.left+colW+margin.right;const H=margin.top+pkts.length*rowH+40;
    svg.attr('viewBox',`0 0 ${W} ${H}`).attr('width',W).attr('height',H);
    // Arrowhead marker
    svg.append('defs').append('marker').attr('id','seq-arrowhead').attr('viewBox','0 0 10 10').attr('refX',10).attr('refY',5).attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto').append('path').attr('d','M 0 0 L 10 5 L 0 10 z').attr('fill','currentColor');
    const xA=margin.left,xB=margin.left+colW;
    // Host labels
    svg.append('text').attr('class','seq-host-label').attr('x',xA).attr('y',25).text(hostA);
    svg.append('text').attr('class','seq-host-label').attr('x',xB).attr('y',25).text(hostB);
    // Lifelines
    svg.append('line').attr('class','seq-lifeline').attr('x1',xA).attr('y1',margin.top).attr('x2',xA).attr('y2',H-20);
    svg.append('line').attr('class','seq-lifeline').attr('x1',xB).attr('y1',margin.top).attr('x2',xB).attr('y2',H-20);
    // Arrows
    pkts.forEach((p,i)=>{
      const y=margin.top+i*rowH+12;
      const fromA=p.srcIP===hostA;
      const x1=fromA?xA:xB,x2=fromA?xB:xA;
      svg.append('line').attr('class','seq-arrow-line').attr('x1',x1+5*(fromA?1:-1)).attr('y1',y).attr('x2',x2-5*(fromA?1:-1)).attr('y2',y).attr('stroke',protoColor(p.protocol)).style('color',protoColor(p.protocol));
      svg.append('text').attr('class','seq-time-label').attr('x',margin.left-8).attr('y',y+3).text(p.relativeTime?.toFixed(3)+'s');
      const infoText=p.info.length>50?p.info.slice(0,48)+'..':p.info;
      svg.append('text').attr('class','seq-info-label').attr('x',(xA+xB)/2).attr('y',y-4).attr('text-anchor','middle').text(`[${p.protocol}] ${infoText}`);
    });
  }

  // ===== Feature 8: IO Graph =====
  function showIOGraph(){
    renderIOGraphSVG();
    els.iographModal.classList.remove('hidden');
    els.ioMetric.onchange=renderIOGraphSVG;
    els.ioInterval.onchange=renderIOGraphSVG;
  }
  function renderIOGraphSVG(){
    const svg=d3.select('#iograph-svg');svg.selectAll('*').remove();
    const pkts=AppState.packets;if(!pkts.length)return;
    const metric=els.ioMetric.value;const interval=parseInt(els.ioInterval.value);
    const tMin=pkts[0].timestamp,tMax=pkts[pkts.length-1].timestamp;
    const numBins=Math.max(1,Math.ceil((tMax-tMin)/interval));
    const protocols=[...AppState.protocolStats.keys()];
    // Buckets per protocol
    const buckets={};for(const proto of protocols)buckets[proto]=new Array(numBins).fill(0);
    for(const p of pkts){
      const idx=Math.min(Math.floor((p.timestamp-tMin)/interval),numBins-1);
      if(idx>=0)buckets[p.protocol][idx]+=(metric==='bytes'?(p.originalLength||p.capturedLength):1);
    }
    // Scale factor for rate
    const scaleFactor=1000/interval;
    const stackData=[];
    for(let i=0;i<numBins;i++){const d={time:tMin+i*interval};for(const proto of protocols)d[proto]=(buckets[proto][i]||0)*scaleFactor;stackData.push(d);}
    const W=900,H=350,m={top:20,right:20,bottom:40,left:60};
    svg.attr('viewBox',`0 0 ${W} ${H}`);
    const x=d3.scaleLinear().domain([tMin,tMax]).range([m.left,W-m.right]);
    const stack=d3.stack().keys(protocols);const series=stack(stackData);
    const yMax=d3.max(series,s=>d3.max(s,d=>d[1]))||1;
    const y=d3.scaleLinear().domain([0,yMax]).nice().range([H-m.bottom,m.top]);
    const area=d3.area().x(d=>x(d.data.time)).y0(d=>y(d[0])).y1(d=>y(d[1])).curve(d3.curveMonotoneX);
    svg.selectAll('.io-area').data(series).join('path').attr('d',area).attr('fill',d=>protoColor(d.key)).attr('opacity',0.7);
    svg.append('g').attr('class','io-axis').attr('transform',`translate(0,${H-m.bottom})`).call(d3.axisBottom(x).ticks(8).tickFormat(d=>`${((d-tMin)/1000).toFixed(1)}s`));
    svg.append('g').attr('class','io-axis').attr('transform',`translate(${m.left},0)`).call(d3.axisLeft(y).ticks(6).tickFormat(d3.format('.2s')));
    // Y label
    svg.append('text').attr('x',15).attr('y',H/2).attr('transform',`rotate(-90,15,${H/2})`).attr('text-anchor','middle').attr('font-size','10px').attr('fill','var(--text-muted)').text(metric==='bytes'?'Bytes/sec':'Packets/sec');
  }

  // ===== Feature 7: Packet Diff =====
  function showPacketDiff(){
    const pktA=AppState.filteredPackets[AppState.selectedPacketIdx];
    const pktB=AppState.diffPacketB;
    if(!pktA||!pktB)return;
    els.diffInfo.textContent=`Packet #${pktA.number} vs #${pktB.number}`;
    // Field diff
    const allKeys=new Set([...Object.keys(pktA.layers),...Object.keys(pktB.layers)]);
    let fieldsHTML='';
    for(const layer of allKeys){
      const la=pktA.layers[layer]||{};const lb=pktB.layers[layer]||{};
      const keys=new Set([...Object.keys(la),...Object.keys(lb)]);
      for(const k of keys){
        const va=JSON.stringify(la[k]??''),vb=JSON.stringify(lb[k]??'');
        const changed=va!==vb;
        fieldsHTML+=`<div class="diff-field-row"><div class="diff-field-name">${layer}.${k}</div><div class="diff-field-a${changed?' diff-field-changed':''}">${escapeHTML(va)}</div><div class="diff-field-b${changed?' diff-field-changed':''}">${escapeHTML(vb)}</div></div>`;
      }
    }
    els.diffFields.innerHTML=fieldsHTML;
    // Hex diff
    function diffHex(bytesA,bytesB,el){
      const maxLen=Math.max(bytesA.length,bytesB.length);let html='';
      for(let i=0;i<maxLen;i+=16){
        html+=`<span class="hex-offset">${i.toString(16).padStart(8,'0')}</span>  `;
        for(let j=0;j<16;j++){
          if(i+j<bytesA.length){
            const ba=bytesA[i+j];const bb=i+j<bytesB.length?bytesB[i+j]:-1;
            const cls=bb===-1?'diff-byte-only':ba!==bb?'diff-byte-changed':'diff-byte-same';
            html+=`<span class="${cls}">${ba.toString(16).padStart(2,'0')}</span> `;
          } else html+=`<span class="diff-byte-only">--</span> `;
          if(j===7)html+=' ';
        }
        html+='\n';
      }
      el.innerHTML=html;
    }
    $('diff-label-a').textContent=`Packet #${pktA.number}`;
    $('diff-label-b').textContent=`Packet #${pktB.number}`;
    diffHex(pktA.rawBytes,pktB.rawBytes,$('diff-hex-a'));
    diffHex(pktB.rawBytes,pktA.rawBytes,$('diff-hex-b'));
    els.diffModal.classList.remove('hidden');
  }

  // ===== Feature 10: Annotations =====
  let currentNotePacket=null;
  function showNotePopover(pktNum,e){
    currentNotePacket=pktNum;
    els.noteText.value=AppState.annotations.get(pktNum)||'';
    els.notePopover.classList.remove('hidden');
    const rect=e.target.getBoundingClientRect();
    els.notePopover.style.left=Math.min(rect.left,window.innerWidth-280)+'px';
    els.notePopover.style.top=(rect.bottom+4)+'px';
    els.noteText.focus();
  }
  function hideNotePopover(){els.notePopover.classList.add('hidden');currentNotePacket=null;}
  function saveAnnotation(){
    if(currentNotePacket===null)return;
    const text=els.noteText.value.trim();
    if(text)AppState.annotations.set(currentNotePacket,text);else AppState.annotations.delete(currentNotePacket);
    saveAnnotations();hideNotePopover();renderVisibleRows();
  }
  function deleteAnnotation(){if(currentNotePacket!==null){AppState.annotations.delete(currentNotePacket);saveAnnotations();hideNotePopover();renderVisibleRows();}}
  function showNotesModal(){
    const entries=[...AppState.annotations.entries()].sort((a,b)=>a[0]-b[0]);
    let html;
    if(!entries.length)html='<p style="color:var(--text-muted)">No annotations yet. Click the note icon on a packet row to add one.</p>';
    else html=`<table class="notes-table"><thead><tr><th>Pkt#</th><th>Note</th><th></th></tr></thead><tbody>${entries.map(([num,note])=>`<tr><td>${num}</td><td>${escapeHTML(note)}</td><td><button class="btn-small note-del-btn" data-pktnum="${num}">Del</button></td></tr>`).join('')}</tbody></table>`;
    els.notesContent.innerHTML=html;
    els.notesContent.querySelectorAll('.note-del-btn').forEach(btn=>{
      btn.addEventListener('click',()=>{AppState.annotations.delete(parseInt(btn.dataset.pktnum));saveAnnotations();showNotesModal();renderVisibleRows();});
    });
    els.notesModal.classList.remove('hidden');
  }
  // S5: Sanitize localStorage key and enforce size limit (1MB max for annotations)
  const MAX_ANNOTATIONS_SIZE = 1024 * 1024;
  function _storageKey(name){return 'wsv-notes-'+name.replace(/[^a-zA-Z0-9._-]/g,'_').slice(0,100);}
  function saveAnnotations(){try{const data=JSON.stringify([...AppState.annotations]);if(data.length>MAX_ANNOTATIONS_SIZE){console.warn('Annotations too large to save (',data.length,'bytes)');return;}localStorage.setItem(_storageKey(AppState.fileName),data);}catch{}}
  function loadAnnotations(){try{const d=localStorage.getItem(_storageKey(AppState.fileName));if(d){const parsed=JSON.parse(d);if(Array.isArray(parsed))AppState.annotations=new Map(parsed);}}catch{}}

  // ===== Feature: Dark Web Port Detection (#7) =====
  // C2: DARKWEB_PORTS consolidated at module top
  function getDarkWebLabel(port){return DARKWEB_PORTS[port]||null;}

  // ===== Feature: Threat Intelligence IoC Matching (#1) =====
  function showIoCModal(){
    els.iocModal.classList.remove('hidden');
    if(AppState.iocMatches.length>0)renderIoCResults();
  }
  // S10: Async chunked IoC scanning to avoid UI freeze on large captures
  function scanIoCs(){
    const raw=els.iocInput.value.trim();
    if(!raw){els.iocStatus.textContent='Paste IoC indicators first.';return;}
    const iocs=raw.split(/[\n,;]+/).map(s=>s.trim().toLowerCase()).filter(s=>s.length>0);
    AppState.iocList=iocs;
    const iocSet=new Set(iocs);
    const matches=[];
    const matchedIPs=new Set(),matchedDomains=new Set();
    const packets=AppState.packets;
    const CHUNK=1000;
    let idx=0;
    els.iocStatus.textContent='Scanning...';
    function processChunk(){
      const chunkEnd=Math.min(idx+CHUNK,packets.length);
      for(;idx<chunkEnd;idx++){
        const p=packets[idx];
        let matched=false,matchType='';
        if(p.srcIP&&iocSet.has(p.srcIP.toLowerCase())){matched=true;matchType='IP';matchedIPs.add(p.srcIP);}
        if(p.dstIP&&iocSet.has(p.dstIP.toLowerCase())){matched=true;matchType='IP';matchedIPs.add(p.dstIP);}
        if(p.dnsQueryName&&iocSet.has(p.dnsQueryName.toLowerCase())){matched=true;matchType='Domain';matchedDomains.add(p.dnsQueryName);}
        if(p.dnsAnswers){for(const a of p.dnsAnswers){if(a.name&&iocSet.has(a.name.toLowerCase())){matched=true;matchType='Domain';matchedDomains.add(a.name);}if(a.data&&iocSet.has(a.data.toLowerCase())){matched=true;matchType='IP';matchedIPs.add(a.data);}}}
        if(matched)matches.push({pkt:p,matchType});
      }
      if(idx<packets.length){
        els.iocStatus.textContent=`Scanning... ${Math.round(idx/packets.length*100)}%`;
        setTimeout(processChunk,0);
      } else {
        AppState.iocMatches=matches;
        els.iocMatchCount.textContent=`${matches.length} matches`;
        els.iocStatus.textContent=`Scanned ${packets.length} packets. ${matchedIPs.size} IPs, ${matchedDomains.size} domains matched.`;
        renderIoCResults();
      }
    }
    processChunk();
  }
  function renderIoCResults(){
    const matches=AppState.iocMatches;
    if(!matches.length){els.iocResults.innerHTML='<p style="color:var(--text-muted)">No matches found.</p>';return;}
    // Summary cards
    const byIP=new Map();
    for(const m of matches){
      const key=m.pkt.srcIP||m.pkt.dstIP;
      byIP.set(key,(byIP.get(key)||0)+1);
    }
    let html='<div class="ioc-summary">';
    html+=`<div class="stat-card"><div class="stat-label">Total Matches</div><div class="stat-value">${matches.length}</div></div>`;
    html+=`<div class="stat-card"><div class="stat-label">Unique IoCs Hit</div><div class="stat-value">${byIP.size}</div></div>`;
    // Dark web overlap
    let dwOverlap=0;
    for(const[ip]of byIP){if(AppState.darkWebFlags.has(ip))dwOverlap++;}
    if(dwOverlap>0)html+=`<div class="stat-card"><div class="stat-label">Also Dark Web Ports</div><div class="stat-value" style="color:var(--danger)">${dwOverlap}</div></div>`;
    html+='</div>';
    // Table of matches
    html+='<table class="extraction-table"><thead><tr><th>Pkt#</th><th>Type</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Info</th><th>Flags</th></tr></thead><tbody>';
    for(const m of matches.slice(0,200)){
      const p=m.pkt;
      let flags='<span class="ioc-badge threat">IoC</span>';
      const srcDW=AppState.darkWebFlags.get(p.srcIP);
      const dstDW=AppState.darkWebFlags.get(p.dstIP);
      if(srcDW||dstDW)flags+=' <span class="ioc-badge darkweb">Dark Web</span>';
      html+=`<tr><td>${p.number}</td><td>${m.matchType}</td><td>${escapeHTML(p.srcIP||'')}</td><td>${escapeHTML(p.dstIP||'')}</td><td>${escapeHTML(p.protocol)}</td><td>${escapeHTML((p.info||'').slice(0,80))}</td><td>${flags}</td></tr>`;
    }
    html+='</tbody></table>';
    if(matches.length>200)html+=`<p style="color:var(--text-muted);margin-top:8px">Showing first 200 of ${matches.length} matches.</p>`;
    els.iocResults.innerHTML=html;
  }

  // ===== Feature: Subnet/VLAN Grouping in Network Graph (#2) =====
  function getSubnet(ip){
    if(!ip||ip.includes(':'))return null;
    const parts=ip.split('.');
    return parts.slice(0,3).join('.')+'.0/24';
  }
  function isPrivateIP(ip){
    if(!ip||ip.includes(':'))return false;
    const p=ip.split('.').map(Number);
    return(p[0]===10)||(p[0]===172&&p[1]>=16&&p[1]<=31)||(p[0]===192&&p[1]===168)||(p[0]===127);
  }
  const SUBNET_COLORS=['#6366f1','#f59e0b','#22c55e','#ef4444','#8b5cf6','#ec4899','#14b8a6','#f97316','#06b6d4','#84cc16'];

  // ===== Feature: Packet Heatmap Timeline (#4) =====
  // P6: Cache heatmap grid data (only changes on new file load)
  let _heatmapGridCache=null, _heatmapCacheKey='';
  function renderHeatmapTimeline(){
    const container=$('panel-timeline').querySelector('.panel-body');
    const canvas=$('timeline-canvas');
    const W=container.clientWidth,H=container.clientHeight-50;if(W<=0||H<=0)return;
    canvas.width=W;canvas.height=H;canvas.style.width=W+'px';canvas.style.height=H+'px';
    const pkts=AppState.packets;if(!pkts.length)return;
    const tMin=pkts[0].timestamp,tMax=pkts[pkts.length-1].timestamp;
    const ctx=canvas.getContext('2d');ctx.clearRect(0,0,W,H);
    const margin={top:5,right:10,bottom:5,left:40};
    const plotW=W-margin.left-margin.right;
    const plotH=H-margin.top-margin.bottom;
    // Determine bins
    const numCols=Math.max(1,Math.min(200,Math.floor(plotW/4)));
    const protocols=[...AppState.protocolStats.keys()].sort((a,b)=>(AppState.protocolStats.get(b)||0)-(AppState.protocolStats.get(a)||0)).slice(0,12);
    const numRows=protocols.length;if(!numRows)return;
    const cellW=plotW/numCols;
    const cellH=plotH/numRows;
    const binDur=(tMax-tMin)/numCols||1;
    // P6: Use cached grid if data hasn't changed
    const cacheKey=pkts.length+'_'+numCols+'_'+numRows;
    let grid, maxVal;
    if(_heatmapCacheKey===cacheKey&&_heatmapGridCache){
      grid=_heatmapGridCache.grid;maxVal=_heatmapGridCache.maxVal;
    } else {
      // Build heatmap data
      grid=Array.from({length:numRows},()=>new Array(numCols).fill(0));
      maxVal=0;
      for(const p of pkts){
        const pi=protocols.indexOf(p.protocol);if(pi<0)continue;
        const ci=Math.min(Math.floor((p.timestamp-tMin)/binDur),numCols-1);if(ci<0)continue;
        grid[pi][ci]++;
        if(grid[pi][ci]>maxVal)maxVal=grid[pi][ci];
      }
      _heatmapGridCache={grid,maxVal};_heatmapCacheKey=cacheKey;
    }
    // Draw cells
    for(let r=0;r<numRows;r++){
      for(let c=0;c<numCols;c++){
        const val=grid[r][c];if(val===0)continue;
        const intensity=Math.min(1,val/maxVal);
        const x=margin.left+c*cellW;
        const y=margin.top+r*cellH;
        const color=protoColor(protocols[r]);
        ctx.globalAlpha=0.15+intensity*0.85;
        ctx.fillStyle=color;
        ctx.fillRect(x,y,cellW-0.5,cellH-0.5);
      }
    }
    ctx.globalAlpha=1;
    // Row labels
    ctx.fillStyle=getComputedStyle(document.body).getPropertyValue('--text-muted')||'#64748b';
    ctx.font='9px -apple-system, sans-serif';
    ctx.textAlign='right';
    for(let r=0;r<numRows;r++){
      ctx.fillText(protocols[r],margin.left-4,margin.top+r*cellH+cellH/2+3);
    }
    // Axis label
    const svgEl=$('timeline-svg');
    const svgD3=d3.select(svgEl);svgD3.selectAll('*').remove();
    svgEl.setAttribute('viewBox',`0 0 ${W} ${H}`);svgEl.setAttribute('width',W);svgEl.setAttribute('height',H);
    const xScale=d3.scaleLinear().domain([tMin,tMax]).range([margin.left,W-margin.right]);
    const xAxis=d3.axisBottom(xScale).ticks(6).tickFormat(d=>`${((d-tMin)/1000).toFixed(1)}s`);
    svgD3.append('g').attr('class','timeline-axis').attr('transform',`translate(0,${H-margin.bottom})`).call(xAxis);
    // Brush still in brush SVG
    const brushSvg=d3.select('#timeline-brush');
    brushSvg.selectAll('*').remove();brushSvg.attr('viewBox',`0 0 ${W} 50`).attr('width',W).attr('height',50);
    const brushXScale=d3.scaleLinear().domain([tMin,tMax]).range([margin.left,W-margin.right]);
    const brush=d3.brushX().extent([[margin.left,5],[W-margin.right,45]]).on('end',e=>{
      if(!e.selection){AppState.filters.timeRange=null;}else{AppState.filters.timeRange=[brushXScale.invert(e.selection[0]),brushXScale.invert(e.selection[1])];}
      onFilterChange();
    });
    brushSvg.append('g').call(brush);
  }

  // ===== Feature: Connection State Machine View (#5) =====
  function showConnStateModal(){
    renderConnState();
    els.connstateModal.classList.remove('hidden');
  }
  // P4: Compute connection state once, cache in AppState
  function _buildConnStateCache(){
    if(AppState.connStateCache)return AppState.connStateCache;
    const connMap=new Map();
    for(const p of AppState.packets){
      if(!p.tcpFlags||!p.srcIP||!p.dstIP)continue;
      const fwd=`${p.srcIP}:${p.srcPort}-${p.dstIP}:${p.dstPort}`;
      const rev=`${p.dstIP}:${p.dstPort}-${p.srcIP}:${p.srcPort}`;
      let key=connMap.has(fwd)?fwd:connMap.has(rev)?rev:null;
      if(!key){
        if(p.tcpFlags.SYN&&!p.tcpFlags.ACK)key=fwd;
        else key=[p.srcIP+':'+p.srcPort,p.dstIP+':'+p.dstPort].sort().join('-');
      }
      if(!connMap.has(key))connMap.set(key,{client:p.srcIP+':'+p.srcPort,server:p.dstIP+':'+p.dstPort,events:[],packets:0,bytes:0,firstTs:p.timestamp,lastTs:p.timestamp});
      const conn=connMap.get(key);
      conn.packets++;conn.bytes+=(p.originalLength||p.capturedLength);
      if(p.timestamp<conn.firstTs)conn.firstTs=p.timestamp;
      if(p.timestamp>conn.lastTs)conn.lastTs=p.timestamp;
      const isClient=(p.srcIP+':'+p.srcPort)===conn.client;
      if(p.tcpFlags.SYN&&!p.tcpFlags.ACK)conn.events.push({type:'SYN',from:isClient?'client':'server',ts:p.timestamp,pkt:p.number});
      else if(p.tcpFlags.SYN&&p.tcpFlags.ACK)conn.events.push({type:'SYN-ACK',from:isClient?'client':'server',ts:p.timestamp,pkt:p.number});
      else if(p.tcpFlags.FIN)conn.events.push({type:'FIN',from:isClient?'client':'server',ts:p.timestamp,pkt:p.number});
      else if(p.tcpFlags.RST)conn.events.push({type:'RST',from:isClient?'client':'server',ts:p.timestamp,pkt:p.number});
      else if(p.tcpPayloadLength>0)conn.events.push({type:'DATA',from:isClient?'client':'server',ts:p.timestamp,pkt:p.number,size:p.tcpPayloadLength});
    }
    const connections=[];
    for(const[key,conn]of connMap){
      const types=new Set(conn.events.map(e=>e.type));
      let state='unknown';
      if(types.has('RST'))state='reset';
      else if(types.has('SYN')&&types.has('SYN-ACK')&&types.has('FIN'))state='complete';
      else if(types.has('SYN')&&types.has('SYN-ACK'))state='established';
      else if(types.has('SYN')&&!types.has('SYN-ACK'))state='halfopen';
      else if(types.has('DATA'))state='data-only';
      conn.state=state;conn.key=key;
      connections.push(conn);
    }
    connections.sort((a,b)=>b.packets-a.packets);
    AppState.connStateCache=connections;
    return connections;
  }
  function renderConnState(){
    const connections=_buildConnStateCache();
    // Filter
    const filter=els.connstateFilter.value;
    let filtered=connections;
    if(filter==='incomplete')filtered=connections.filter(c=>c.state==='halfopen'||c.state==='unknown');
    else if(filter==='reset')filtered=connections.filter(c=>c.state==='reset');
    else if(filter==='halfopen')filtered=connections.filter(c=>c.state==='halfopen');
    // Render
    if(!filtered.length){els.connstateContent.innerHTML='<p style="color:var(--text-muted)">No TCP connections match the filter.</p>';return;}
    // Summary
    const stateCounts={complete:0,established:0,halfopen:0,reset:0,'data-only':0,unknown:0};
    for(const c of connections)stateCounts[c.state]=(stateCounts[c.state]||0)+1;
    let html='<div class="alert-result-summary">';
    html+=`<div class="stat-card"><div class="stat-label">Total TCP Connections</div><div class="stat-value">${connections.length}</div></div>`;
    html+=`<div class="stat-card"><div class="stat-label">Complete</div><div class="stat-value" style="color:var(--success)">${stateCounts.complete}</div></div>`;
    html+=`<div class="stat-card"><div class="stat-label">Established</div><div class="stat-value" style="color:var(--accent)">${stateCounts.established}</div></div>`;
    html+=`<div class="stat-card"><div class="stat-label">Half-Open</div><div class="stat-value" style="color:#a855f7">${stateCounts.halfopen}</div></div>`;
    html+=`<div class="stat-card"><div class="stat-label">RST / Reset</div><div class="stat-value" style="color:var(--danger)">${stateCounts.reset}</div></div>`;
    html+='</div>';
    // Connection cards
    for(const conn of filtered.slice(0,100)){
      const badgeClass=conn.state==='complete'?'complete':conn.state==='reset'?'reset':conn.state==='halfopen'?'halfopen':'incomplete';
      const dur=((conn.lastTs-conn.firstTs)/1000).toFixed(2);
      html+=`<div class="connstate-card">`;
      html+=`<h4>${escapeHTML(conn.client)} &harr; ${escapeHTML(conn.server)} <span class="connstate-badge ${badgeClass}">${conn.state.toUpperCase()}</span></h4>`;
      html+=`<div class="conn-detail">${conn.packets} packets | ${formatBytes(conn.bytes)} | ${dur}s</div>`;
      // State flow
      html+='<div class="connstate-flow">';
      const shownEvents=[];const seenTypes=new Set();
      for(const ev of conn.events){
        if(ev.type==='DATA'){if(seenTypes.has('DATA'))continue;seenTypes.add('DATA');}
        else seenTypes.add(ev.type);
        shownEvents.push(ev);
        if(shownEvents.length>=12)break;
      }
      for(let i=0;i<shownEvents.length;i++){
        const ev=shownEvents[i];
        const cls=ev.type==='SYN'?'syn':ev.type==='SYN-ACK'?'synack':ev.type==='FIN'?'fin':ev.type==='RST'?'rst':'data';
        const label=ev.type==='DATA'?`DATA (${ev.from})`:`${ev.type} (${ev.from})`;
        html+=`<span class="connstate-step ${cls}">${label}</span>`;
        if(i<shownEvents.length-1)html+='<span class="connstate-step arrow">\u2192</span>';
      }
      html+='</div></div>';
    }
    if(filtered.length>100)html+=`<p style="color:var(--text-muted);margin-top:8px">Showing first 100 of ${filtered.length} connections.</p>`;
    els.connstateContent.innerHTML=html;
  }

  // ===== Feature: Alert Rules Engine (#6) =====
  const DEFAULT_ALERT_RULES=[
    {name:'High RST Rate',type:'rst_flood',threshold:50,window:10,severity:'high',enabled:true},
    {name:'DNS Non-Standard Port',type:'dns_nonstandard',threshold:0,window:0,severity:'medium',enabled:true},
    {name:'Dark Web Port Activity',type:'darkweb_ports',threshold:1,window:0,severity:'high',enabled:true},
    {name:'Large Data Transfer',type:'large_transfer',threshold:10485760,window:0,severity:'medium',enabled:true},
    {name:'Port Scan Detection',type:'port_scan',threshold:20,window:60,severity:'critical',enabled:true},
  ];
  function showAlertsModal(){
    if(!AppState.alertRules.length)AppState.alertRules=[...DEFAULT_ALERT_RULES.map(r=>({...r}))];
    renderAlertRules();
    els.alertsModal.classList.remove('hidden');
  }
  function renderAlertRules(){
    const rules=AppState.alertRules;
    const ruleTypes=[
      {value:'rst_flood',label:'RST Flood'},
      {value:'dns_nonstandard',label:'DNS Non-Standard Port'},
      {value:'darkweb_ports',label:'Dark Web Port Activity'},
      {value:'large_transfer',label:'Large Data Transfer (bytes)'},
      {value:'port_scan',label:'Port Scan (unique ports)'},
      {value:'syn_flood',label:'SYN Flood'},
      {value:'icmp_flood',label:'ICMP Flood'},
    ];
    const severities=['critical','high','medium','low'];
    els.alertRulesList.innerHTML=rules.map((r,i)=>`<div class="alert-rule-item">
      <input type="checkbox" ${r.enabled?'checked':''} data-idx="${i}" class="alert-rule-toggle">
      <input type="text" value="${escapeHTML(r.name)}" data-idx="${i}" class="alert-rule-name" style="width:140px" placeholder="Rule name">
      <select data-idx="${i}" class="alert-rule-type">${ruleTypes.map(t=>`<option value="${t.value}"${t.value===r.type?' selected':''}>${t.label}</option>`).join('')}</select>
      <label style="font-size:0.7rem;color:var(--text-muted)">Threshold:</label>
      <input type="number" value="${r.threshold}" data-idx="${i}" class="alert-rule-thresh">
      <label style="font-size:0.7rem;color:var(--text-muted)">Window(s):</label>
      <input type="number" value="${r.window}" data-idx="${i}" class="alert-rule-window" style="width:50px">
      <select data-idx="${i}" class="alert-rule-sev">${severities.map(s=>`<option value="${s}"${s===r.severity?' selected':''}>${s}</option>`).join('')}</select>
      <button class="rule-remove" data-idx="${i}">\u00D7</button>
    </div>`).join('');
    // Wire up rule edits
    els.alertRulesList.querySelectorAll('.alert-rule-toggle').forEach(cb=>{cb.onchange=()=>{rules[cb.dataset.idx].enabled=cb.checked;};});
    els.alertRulesList.querySelectorAll('.alert-rule-name').forEach(inp=>{inp.onchange=()=>{rules[inp.dataset.idx].name=inp.value;};});
    els.alertRulesList.querySelectorAll('.alert-rule-type').forEach(sel=>{sel.onchange=()=>{rules[sel.dataset.idx].type=sel.value;};});
    els.alertRulesList.querySelectorAll('.alert-rule-thresh').forEach(inp=>{inp.onchange=()=>{rules[inp.dataset.idx].threshold=parseInt(inp.value)||0;};});
    els.alertRulesList.querySelectorAll('.alert-rule-window').forEach(inp=>{inp.onchange=()=>{rules[inp.dataset.idx].window=parseInt(inp.value)||0;};});
    els.alertRulesList.querySelectorAll('.alert-rule-sev').forEach(sel=>{sel.onchange=()=>{rules[sel.dataset.idx].severity=sel.value;};});
    els.alertRulesList.querySelectorAll('.rule-remove').forEach(btn=>{btn.onclick=()=>{rules.splice(parseInt(btn.dataset.idx),1);renderAlertRules();};});
  }
  // P2: O(n) two-pointer sliding window for flood detection
  function _detectFlood(filteredPkts, windowMs, threshold) {
    if(!filteredPkts.length)return null;
    let left=0, maxCount=0, maxStartIdx=0;
    for(let right=0;right<filteredPkts.length;right++){
      while(filteredPkts[right].timestamp-filteredPkts[left].timestamp>windowMs)left++;
      const count=right-left+1;
      if(count>maxCount){maxCount=count;maxStartIdx=left;}
    }
    if(maxCount>=threshold)return{count:maxCount,startTs:filteredPkts[maxStartIdx].timestamp};
    return null;
  }
  function runAlertRules(){
    const results=[];
    const pkts=AppState.packets;
    if(!pkts.length){els.alertResults.innerHTML='<p style="color:var(--text-muted)">No packets loaded.</p>';return;}
    const tMin=pkts[0].timestamp;
    for(const rule of AppState.alertRules){
      if(!rule.enabled)continue;
      switch(rule.type){
        case 'rst_flood':{
          const rstPkts=pkts.filter(p=>p.tcpFlags&&p.tcpFlags.RST);
          const windowMs=rule.window*1000||10000;
          const hit=_detectFlood(rstPkts,windowMs,rule.threshold);
          if(hit)results.push({rule,severity:rule.severity,detail:`${hit.count} RST packets in ${rule.window}s window at ${((hit.startTs-tMin)/1000).toFixed(1)}s`,count:hit.count});
          break;
        }
        case 'syn_flood':{
          const synPkts=pkts.filter(p=>p.tcpFlags&&p.tcpFlags.SYN&&!p.tcpFlags.ACK);
          const windowMs=rule.window*1000||10000;
          const hit=_detectFlood(synPkts,windowMs,rule.threshold);
          if(hit)results.push({rule,severity:rule.severity,detail:`${hit.count} SYN packets in ${rule.window}s window at ${((hit.startTs-tMin)/1000).toFixed(1)}s`,count:hit.count});
          break;
        }
        case 'icmp_flood':{
          const icmpPkts=pkts.filter(p=>p.protocol==='ICMP'||p.protocol==='ICMPv6');
          const windowMs=rule.window*1000||10000;
          const hit=_detectFlood(icmpPkts,windowMs,rule.threshold);
          if(hit)results.push({rule,severity:rule.severity,detail:`${hit.count} ICMP packets in ${rule.window}s window at ${((hit.startTs-tMin)/1000).toFixed(1)}s`,count:hit.count});
          break;
        }
        case 'dns_nonstandard':{
          const nonStd=pkts.filter(p=>p.protocol==='DNS'&&p.dstPort&&p.dstPort!==53&&p.srcPort!==53);
          if(nonStd.length>0){
            const ports=new Set(nonStd.map(p=>p.dstPort));
            results.push({rule,severity:rule.severity,detail:`${nonStd.length} DNS packets on non-standard ports: ${[...ports].slice(0,5).join(', ')}`,count:nonStd.length});
          }
          break;
        }
        case 'darkweb_ports':{
          const dwEntries=[...AppState.darkWebFlags.entries()];
          if(dwEntries.length>=rule.threshold){
            const summary=dwEntries.slice(0,5).map(([ip,ports])=>{
              const labels=[...ports.entries()].map(([port,count])=>`${DARKWEB_PORTS[port]||port}(${count})`).join(', ');
              return `${ip}: ${labels}`;
            });
            results.push({rule,severity:rule.severity,detail:`${dwEntries.length} hosts with dark web port activity. ${summary.join('; ')}`,count:dwEntries.length});
          }
          break;
        }
        case 'large_transfer':{
          for(const[key,conn]of AppState.connections){
            if(conn.bytes>=rule.threshold){
              results.push({rule,severity:rule.severity,detail:`${conn.a} \u2194 ${conn.b}: ${formatBytes(conn.bytes)} transferred (${conn.packets} pkts)`,count:conn.bytes});
            }
          }
          break;
        }
        case 'port_scan':{
          // Detect hosts connecting to many unique ports on a single target
          const srcDstPorts=new Map();
          for(const p of pkts){
            if(!p.srcIP||!p.dstIP||!p.dstPort)continue;
            const key=`${p.srcIP}->${p.dstIP}`;
            if(!srcDstPorts.has(key))srcDstPorts.set(key,new Set());
            srcDstPorts.get(key).add(p.dstPort);
          }
          for(const[key,ports]of srcDstPorts){
            if(ports.size>=rule.threshold){
              results.push({rule,severity:rule.severity,detail:`${key}: ${ports.size} unique destination ports scanned`,count:ports.size});
            }
          }
          break;
        }
      }
    }
    AppState.alertResults=results;
    // Render results
    if(!results.length){els.alertResults.innerHTML='<p style="color:var(--text-muted);margin-top:12px">No alerts triggered. All clear!</p>';return;}
    results.sort((a,b)=>{const ord={critical:0,high:1,medium:2,low:3};return(ord[a.severity]||4)-(ord[b.severity]||4);});
    let html='<h3 style="margin:12px 0 8px;font-size:0.9rem">Triggered Alerts</h3>';
    html+='<div class="alert-result-summary">';
    const sevCounts={critical:0,high:0,medium:0,low:0};
    for(const r of results)sevCounts[r.severity]=(sevCounts[r.severity]||0)+1;
    for(const[sev,count]of Object.entries(sevCounts)){
      if(count>0)html+=`<div class="stat-card"><div class="stat-label">${sev.toUpperCase()}</div><div class="stat-value"><span class="alert-severity ${sev}">${count}</span></div></div>`;
    }
    html+='</div>';
    for(const r of results){
      html+=`<div class="alert-result-card"><h4><span class="alert-severity ${r.severity}">${r.severity.toUpperCase()}</span> ${escapeHTML(r.rule.name)}</h4><div class="alert-detail">${escapeHTML(r.detail)}</div></div>`;
    }
    els.alertResults.innerHTML=html;
  }

  // ===== Feature: Session Reconstruction & HTTP Object Export (#3) =====
  function reconstructHTTPObjects(){
    const objects=[];
    // Group packets into TCP streams
    const streams=new Map();
    for(const p of AppState.packets){
      if(!p.tcpFlags||!p.srcIP||!p.dstIP)continue;
      const fwd=`${p.srcIP}:${p.srcPort}-${p.dstIP}:${p.dstPort}`;
      const rev=`${p.dstIP}:${p.dstPort}-${p.srcIP}:${p.srcPort}`;
      let key=streams.has(fwd)?fwd:streams.has(rev)?rev:fwd;
      if(!streams.has(key))streams.set(key,[]);
      streams.get(key).push(p);
    }
    // For each stream, look for HTTP responses with bodies
    for(const[key,pkts]of streams){
      pkts.sort((a,b)=>a.timestamp-b.timestamp);
      // Concatenate payload bytes for response direction
      let responseBytes=[];
      let requestInfo=null;
      for(const p of pkts){
        if(p.httpMethod&&p.httpUrl)requestInfo={method:p.httpMethod,url:p.httpUrl,pkt:p.number};
        if(p.tcpPayloadLength>0&&p.rawBytes){
          const payload=p.rawBytes.slice(p.tcpPayloadOffset,p.tcpPayloadOffset+p.tcpPayloadLength);
          // P3: Check HTTP/ prefix via direct byte comparison (avoids String.fromCharCode spread)
          if(payload.length>=5&&payload[0]===72&&payload[1]===84&&payload[2]===84&&payload[3]===80&&payload[4]===47){
            // This is a response — try to extract body
            const fullPayload=payload;
            const headerEndIdx=findHeaderEnd(fullPayload);
            if(headerEndIdx>0){
              const headerStr=new TextDecoder('ascii',{fatal:false}).decode(fullPayload.slice(0,headerEndIdx));
              const ctMatch=headerStr.match(RE_CONTENT_TYPE);
              const clMatch=headerStr.match(RE_CONTENT_LENGTH);
              const cdMatch=headerStr.match(RE_CONTENT_DISP);
              const statusMatch=headerStr.match(/HTTP\/\d\.\d\s+(\d+)/);
              if(ctMatch){
                const ct=ctMatch[1].trim();
                const bodyStart=headerEndIdx;
                const bodyBytes=fullPayload.slice(bodyStart);
                const contentLength=clMatch?parseInt(clMatch[1]):bodyBytes.length;
                const filename=cdMatch?cdMatch[1]:(requestInfo?requestInfo.url.split('/').pop().split('?')[0]:'');
                const status=statusMatch?parseInt(statusMatch[1]):200;
                if(bodyBytes.length>0&&!['text/html','text/css','application/javascript','text/javascript'].includes(ct.toLowerCase())){
                  objects.push({
                    contentType:ct,filename:filename||'unknown',size:contentLength,
                    status,url:requestInfo?requestInfo.url:'',
                    bodyBytes:new Uint8Array(bodyBytes),streamKey:key,pkt:pkts[0].number,
                  });
                }
              }
            }
          }
        }
      }
    }
    return objects;
  }
  function findHeaderEnd(bytes){
    for(let i=0;i<bytes.length-3;i++){
      if(bytes[i]===0x0D&&bytes[i+1]===0x0A&&bytes[i+2]===0x0D&&bytes[i+3]===0x0A)return i+4;
    }
    return -1;
  }
  function downloadBlob(bytes,filename,contentType){
    const blob=new Blob([bytes],{type:contentType});
    const url=URL.createObjectURL(blob);
    const a=document.createElement('a');a.href=url;a.download=filename;a.click();
    URL.revokeObjectURL(url);
  }

  // ===== Feature 3: Coloring Rules UI =====
  function showColoringModal(){
    els.coloringProfile.value=AppState.coloringProfile;
    renderColoringRules();
    els.coloringModal.classList.remove('hidden');
  }
  function renderColoringRules(){
    const rules=AppState.coloringProfile==='custom'?AppState.coloringRules:(COLORING_PRESETS[AppState.coloringProfile]||[]);
    const isCustom=AppState.coloringProfile==='custom';
    if(AppState.coloringProfile==='default'){els.coloringRulesList.innerHTML='<p style="color:var(--text-muted)">Default protocol-based coloring. Select a profile or switch to Custom to define rules.</p>';return;}
    els.coloringRulesList.innerHTML=rules.map((r,i)=>`<div class="coloring-rule">
      <input type="checkbox" ${r.enabled?'checked':''} data-idx="${i}" class="rule-enabled">
      <input type="text" value="${escapeHTML(r.name)}" placeholder="Name" style="width:80px" ${isCustom?'':'disabled'}>
      <select data-idx="${i}" class="rule-field" ${isCustom?'':'disabled'}>${Object.keys(FILTER_FIELDS).map(f=>`<option value="${f}"${f===r.field?' selected':''}>${f}</option>`).join('')}</select>
      <select ${isCustom?'':'disabled'}><option value="==" ${r.operator==='=='?'selected':''}>==</option><option value="!=" ${r.operator==='!='?'selected':''}>!=</option><option value="contains" ${r.operator==='contains'?'selected':''}>contains</option></select>
      <input type="text" value="${escapeHTML(r.value)}" placeholder="value" style="width:80px" ${isCustom?'':'disabled'}>
      <input type="color" value="${r.color}" ${isCustom?'':'disabled'}>
      ${isCustom?`<button class="rule-remove" data-idx="${i}">\u00D7</button>`:''}
    </div>`).join('');
    // Enable checkboxes always work
    els.coloringRulesList.querySelectorAll('.rule-enabled').forEach(cb=>{cb.addEventListener('change',()=>{rules[cb.dataset.idx].enabled=cb.checked;invalidateColoringCache();renderVisibleRows();});});
  }

  // ===== Filter Autocomplete =====
  function setupFilterAutocomplete(){
    const fields=Object.keys(FILTER_FIELDS);
    // Event delegation: single click handler on container instead of per-item listeners
    els.filterAutocomplete.addEventListener('click',e=>{
      const item=e.target.closest('.filter-dropdown-item');
      if(!item)return;
      const val=els.tableSearch.value;
      const lastDot=val.lastIndexOf(' ');
      const prefix=val.slice(0,lastDot+1);
      els.tableSearch.value=prefix+item.dataset.field+' ';
      els.filterAutocomplete.classList.add('hidden');
      els.tableSearch.focus();
    });
    els.tableSearch.addEventListener('input',()=>{
      const val=els.tableSearch.value;
      const lastDot=val.lastIndexOf(' ');
      const current=val.slice(lastDot+1);
      if(current.length>0&&!current.includes('=')){
        const matches=fields.filter(f=>f.startsWith(current.toLowerCase()));
        if(matches.length>0&&matches.length<15){
          els.filterAutocomplete.innerHTML=matches.map(m=>`<div class="filter-dropdown-item" data-field="${m}">${m}<span class="field-type">${FILTER_FIELDS[m].type}</span></div>`).join('');
          els.filterAutocomplete.classList.remove('hidden');
          return;
        }
      }
      els.filterAutocomplete.classList.add('hidden');
    });
    els.tableSearch.addEventListener('blur',()=>{setTimeout(()=>els.filterAutocomplete.classList.add('hidden'),200);});
  }

  // ===== Keyboard =====
  function setupKeyboard(){
    document.addEventListener('keydown',e=>{
      if(e.target.tagName==='INPUT'||e.target.tagName==='TEXTAREA'||e.target.tagName==='SELECT'){
        if(e.key==='Escape'){e.target.blur();closeAllModals();}
        return;
      }
      switch(e.key){
        case '?':e.preventDefault();els.shortcutsHelp.classList.toggle('hidden');break;
        case 'Escape':
          e.preventDefault();
          // Exit fullscreen panels first
          const fsPanel=document.querySelector('.panel.fullscreen');
          if(fsPanel){togglePanelFullscreen(fsPanel);break;}
          closeAllModals();closeDetailPane();
          AppState.filters={selectedHost:null,protocolFilter:null,searchText:'',timeRange:null,anomalyOnly:false,bookmarkOnly:false};
          els.tableSearch.value='';els.tableProtoFilter.value='';
          els.tableAnomalyFilter.checked=false;els.tableBookmarkFilter.checked=false;
          document.querySelectorAll('.table-header-row .col').forEach(c=>c.classList.remove('sorted-asc','sorted-desc'));
          onFilterChange();renderTimeline();break;
        case 'ArrowDown':
          e.preventDefault();if(!AppState.filteredPackets.length)break;
          AppState.selectedPacketIdx=Math.min(AppState.selectedPacketIdx+1,AppState.filteredPackets.length-1);
          scrollToSelectedRow();if(AppState.filteredPackets[AppState.selectedPacketIdx])showPacketDetail(AppState.filteredPackets[AppState.selectedPacketIdx]);renderVisibleRows();break;
        case 'ArrowUp':
          e.preventDefault();if(!AppState.filteredPackets.length)break;
          AppState.selectedPacketIdx=Math.max(AppState.selectedPacketIdx-1,0);
          scrollToSelectedRow();if(AppState.filteredPackets[AppState.selectedPacketIdx])showPacketDetail(AppState.filteredPackets[AppState.selectedPacketIdx]);renderVisibleRows();break;
        case 'Enter':if(AppState.selectedPacketIdx>=0&&AppState.filteredPackets[AppState.selectedPacketIdx])showPacketDetail(AppState.filteredPackets[AppState.selectedPacketIdx]);break;
        case 'b':case 'B':if(AppState.selectedPacketIdx>=0)toggleBookmark(AppState.filteredPackets[AppState.selectedPacketIdx].number);break;
        case 'f':case 'F':
          if(e.ctrlKey||e.metaKey){e.preventDefault();els.tableSearch.focus();break;}
          const panels=document.querySelectorAll('.panel');panels.forEach(p=>{if(p.matches(':hover'))togglePanelFullscreen(p);});break;
        case 's':case 'S':followTCPStream();break;
        case 'g':case 'G':showGeoIPMap();break;
        case 'c':case 'C':showConversations();break;
        case 't':case 'T':toggleTheme();break;
        case 'd':case 'D':showProtocolStats();break;
        case 'x':case 'X':showExtractions();break;
        case 'w':case 'W':showSequenceDiagram();break;
        case 'i':case 'I':showIOGraph();break;
        case 'l':case 'L':showLatency();break;
        case 'n':case 'N':showNotesModal();break;
        case 'a':case 'A':showAlertsModal();break;
        case 'm':case 'M':showConnStateModal();break;
        case 'h':case 'H':AppState.heatmapMode=!AppState.heatmapMode;els.btnHeatmapToggle.classList.toggle('active',AppState.heatmapMode);renderTimeline();break;
        case '1':case '2':case '3':case '4':
          const panelIds=['panel-network','panel-timeline','panel-protocols','panel-table'];
          const p=$(panelIds[parseInt(e.key)-1]);if(p)togglePanelFullscreen(p);break;
      }
    });
  }
  function closeAllModals(){
    [els.streamModal,els.conversationsModal,els.compareModal,els.geoipModal,els.shortcutsHelp,
     els.statsModal,els.extractionModal,els.latencyModal,els.sequenceModal,els.iographModal,
     els.diffModal,els.notesModal,els.coloringModal,els.iocModal,els.alertsModal,els.connstateModal].forEach(m=>{if(m)m.classList.add('hidden');});
    hideNotePopover();
  }

  // ===== Table Controls =====
  function populateProtocolFilter(){
    const protos=[...AppState.protocolStats.keys()].sort();
    els.tableProtoFilter.innerHTML='<option value="">All Protocols</option>'+protos.map(p=>`<option value="${p}">${p}</option>`).join('');
  }
  function setupTableControls(){
    els.tableSearch.addEventListener('input',debounce(()=>{AppState.filters.searchText=els.tableSearch.value;onFilterChange();},300));
    els.tableProtoFilter.addEventListener('change',()=>{AppState.filters.protocolFilter=els.tableProtoFilter.value||null;onFilterChange();renderTimeline();});
    els.tableAnomalyFilter.addEventListener('change',()=>{AppState.filters.anomalyOnly=els.tableAnomalyFilter.checked;onFilterChange();});
    els.tableBookmarkFilter.addEventListener('change',()=>{AppState.filters.bookmarkOnly=els.tableBookmarkFilter.checked;onFilterChange();});
    // Column sort
    document.querySelectorAll('.table-header-row .col[data-sort]').forEach(col=>{
      col.addEventListener('click',()=>{
        const field=col.dataset.sort;
        if(AppState.sortColumn===field)AppState.sortAscending=!AppState.sortAscending;
        else{AppState.sortColumn=field;AppState.sortAscending=true;}
        document.querySelectorAll('.table-header-row .col').forEach(c=>c.classList.remove('sorted-asc','sorted-desc'));
        col.classList.add(AppState.sortAscending?'sorted-asc':'sorted-desc');
        onFilterChange();
      });
    });
  }

  // ===== Buttons =====
  function setupButtons(){
    els.btnResetFilters.addEventListener('click',()=>{AppState.filters={selectedHost:null,protocolFilter:null,searchText:'',timeRange:null,anomalyOnly:false,bookmarkOnly:false};els.tableSearch.value='';els.tableProtoFilter.value='';els.tableAnomalyFilter.checked=false;els.tableBookmarkFilter.checked=false;onFilterChange();renderTimeline();});
    els.btnNewFile.addEventListener('click',()=>{els.dashboard.classList.add('hidden');els.uploadOverlay.classList.remove('hidden');AppState.packets=[];AppState.filteredPackets=[];});
    els.btnConversations.addEventListener('click',showConversations);
    els.btnCompare.addEventListener('click',loadCompareFile);
    els.btnExportCSV.addEventListener('click',exportCSV);
    els.btnExportJSON.addEventListener('click',exportJSON);
    els.btnTheme.addEventListener('click',toggleTheme);
    els.btnFollowStream.addEventListener('click',followTCPStream);
    els.btnCloseDetail.addEventListener('click',closeDetailPane);
    els.btnDiff.addEventListener('click',showPacketDiff);
    // Close buttons
    els.btnCloseStream.addEventListener('click',()=>els.streamModal.classList.add('hidden'));
    els.btnCloseConversations.addEventListener('click',()=>els.conversationsModal.classList.add('hidden'));
    els.btnCloseCompare.addEventListener('click',()=>els.compareModal.classList.add('hidden'));
    els.btnCloseGeoip.addEventListener('click',()=>els.geoipModal.classList.add('hidden'));
    els.btnCloseShortcuts.addEventListener('click',()=>els.shortcutsHelp.classList.add('hidden'));
    els.btnCloseStats.addEventListener('click',()=>els.statsModal.classList.add('hidden'));
    els.btnCloseExtraction.addEventListener('click',()=>els.extractionModal.classList.add('hidden'));
    els.btnCloseLatency.addEventListener('click',()=>els.latencyModal.classList.add('hidden'));
    els.btnCloseSequence.addEventListener('click',()=>els.sequenceModal.classList.add('hidden'));
    els.btnCloseIOGraph.addEventListener('click',()=>els.iographModal.classList.add('hidden'));
    els.btnCloseDiff.addEventListener('click',()=>els.diffModal.classList.add('hidden'));
    els.btnCloseNotes.addEventListener('click',()=>els.notesModal.classList.add('hidden'));
    els.btnCloseColoring.addEventListener('click',()=>els.coloringModal.classList.add('hidden'));
    // New feature buttons
    els.btnStats.addEventListener('click',showProtocolStats);
    els.btnExtractions.addEventListener('click',showExtractions);
    els.btnFlow.addEventListener('click',showSequenceDiagram);
    els.btnIOGraph.addEventListener('click',showIOGraph);
    els.btnLatency.addEventListener('click',showLatency);
    els.btnNotes.addEventListener('click',showNotesModal);
    els.btnColoring.addEventListener('click',showColoringModal);
    // New feature buttons
    els.btnIoC.addEventListener('click',showIoCModal);
    els.btnCloseIoC.addEventListener('click',()=>els.iocModal.classList.add('hidden'));
    els.btnIoCScan.addEventListener('click',scanIoCs);
    els.btnIoCClear.addEventListener('click',()=>{els.iocInput.value='';AppState.iocList=[];AppState.iocMatches=[];els.iocResults.innerHTML='';els.iocMatchCount.textContent='';els.iocStatus.textContent='';});
    els.btnAlerts.addEventListener('click',showAlertsModal);
    els.btnCloseAlerts.addEventListener('click',()=>els.alertsModal.classList.add('hidden'));
    els.btnAlertsRun.addEventListener('click',runAlertRules);
    els.btnAddAlertRule.addEventListener('click',()=>{AppState.alertRules.push({name:'New Rule',type:'rst_flood',threshold:10,window:10,severity:'medium',enabled:true});renderAlertRules();});
    els.btnConnState.addEventListener('click',showConnStateModal);
    els.btnCloseConnState.addEventListener('click',()=>els.connstateModal.classList.add('hidden'));
    els.connstateFilter.addEventListener('change',renderConnState);
    els.btnHeatmapToggle.addEventListener('click',()=>{AppState.heatmapMode=!AppState.heatmapMode;els.btnHeatmapToggle.classList.toggle('active',AppState.heatmapMode);renderTimeline();});
    els.btnSeqRefresh.addEventListener('click',renderSequenceSVG);
    // Layer toggle
    document.querySelectorAll('.layer-btn').forEach(btn=>{
      btn.addEventListener('click',()=>{
        document.querySelectorAll('.layer-btn').forEach(b=>b.classList.remove('active'));
        btn.classList.add('active');AppState.graphLayer=btn.dataset.layer;renderNetworkGraph();
      });
    });
    // Host limit slider
    els.hostLimitSlider.addEventListener('input',()=>{
      els.hostLimitValue.textContent=els.hostLimitSlider.value;
    });
    els.hostLimitSlider.addEventListener('change',()=>{
      AppState.graphHostLimit=parseInt(els.hostLimitSlider.value,10);
      renderNetworkGraph();
    });
    // Screenshot & expand buttons
    document.querySelectorAll('.btn-expand').forEach(btn=>{btn.addEventListener('click',()=>togglePanelFullscreen(btn.closest('.panel')));});
    document.querySelectorAll('.btn-screenshot').forEach(btn=>{btn.addEventListener('click',()=>screenshotPanel(btn.closest('.panel')));});
    // Coloring profile
    els.coloringProfile.addEventListener('change',()=>{AppState.coloringProfile=els.coloringProfile.value;invalidateColoringCache();renderColoringRules();renderVisibleRows();});
    els.btnAddRule.addEventListener('click',()=>{AppState.coloringRules.push({name:'New Rule',field:'protocol',operator:'==',value:'TCP',color:'#4fc3f7',enabled:true});renderColoringRules();});
    // Note popover
    els.noteSave.addEventListener('click',saveAnnotation);
    els.noteDelete.addEventListener('click',deleteAnnotation);
    els.noteCancel.addEventListener('click',hideNotePopover);
    // Backdrop close for modals
    document.querySelectorAll('.modal').forEach(m=>{m.addEventListener('click',e=>{if(e.target===m)m.classList.add('hidden');});});
  }

  // ===== Resize =====
  function setupResize(){window.addEventListener('resize',debounce(renderAll,250));}

  // ===== Init =====
  function init(){setupUpload();setupTableControls();setupButtons();setupKeyboard();setupFilterAutocomplete();setupResize();loadStateFromURL();}
  init();
})();
