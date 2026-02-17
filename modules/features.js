// modules/features.js — All feature implementations (modals, analysis, tools)
'use strict';

import { AppState, $, escapeHTML, formatBytes, protoColor, hexToRGBA, DARKWEB_PORTS, FILTER_FIELDS, COLORING_PRESETS, DEFAULT_ALERT_RULES, RE_BASIC_AUTH, RE_BEARER, RE_COOKIE, RE_CONTENT_TYPE, RE_CONTENT_LENGTH, RE_CONTENT_DISP, RE_FTP_USER, RE_FTP_PASS, RE_SMTP_AUTH, RE_SMTP_MAIL, RE_PASSWORD_FIELD, RE_SANITIZE_PASS, RE_SESSION_COOKIE, FILE_EXTS, getDarkWebLabel, invalidateColoringCache } from './state.js';
import { els, showError, hideNotePopover } from './dom.js';
import { renderAll, renderVisibleRows, renderTimeline, onFilterChange, scrollToSelectedRow } from './rendering.js';

// ===== Packet Detail =====
export function showPacketDetail(pkt){
  els.detailPane.classList.remove('hidden');els.detailPacketNum.textContent=pkt.number;
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
  if(pkt.srcIP){
    const fp=AppState.osFingerprints.get(pkt.srcIP);
    if(fp)layerHTML+=`<div class="layer-group"><div class="layer-header">OS FINGERPRINT</div><div class="layer-fields"><div class="layer-field"><span class="field-name">OS: </span><span class="field-value">${escapeHTML(fp.os)} (${fp.confidence}%)</span></div><div class="layer-field"><span class="field-name">TTL: </span><span class="field-value">${fp.ttl}</span></div></div></div>`;
    const tf=AppState.tunnelFlags.get(pkt.srcIP);
    if(tf&&tf.size)layerHTML+=`<div class="layer-group"><div class="layer-header">TUNNEL FLAGS</div><div class="layer-fields"><div class="layer-field"><span class="field-value">${escapeHTML([...tf].join(', '))}</span></div></div></div>`;
    const dwSrc=AppState.darkWebFlags.get(pkt.srcIP);
    const dwDst=AppState.darkWebFlags.get(pkt.dstIP);
    if(dwSrc||dwDst){
      layerHTML+=`<div class="layer-group"><div class="layer-header" style="color:#a855f7">DARK WEB / PROXY PORTS</div><div class="layer-fields">`;
      if(dwSrc){for(const[port,cnt]of dwSrc)layerHTML+=`<div class="layer-field"><span class="field-name">${pkt.srcIP}:</span><span class="field-value" style="color:#a855f7"> Port ${port} (${DARKWEB_PORTS[port]||'Unknown'}) - ${cnt} packets</span></div>`;}
      if(dwDst){for(const[port,cnt]of dwDst)layerHTML+=`<div class="layer-field"><span class="field-name">${pkt.dstIP}:</span><span class="field-value" style="color:#a855f7"> Port ${port} (${DARKWEB_PORTS[port]||'Unknown'}) - ${cnt} packets</span></div>`;}
      layerHTML+=`</div></div>`;
    }
    if(AppState.iocList.length>0){
      const iocSet=new Set(AppState.iocList);
      const hit=(pkt.srcIP&&iocSet.has(pkt.srcIP.toLowerCase()))||(pkt.dstIP&&iocSet.has(pkt.dstIP.toLowerCase()))||(pkt.dnsQueryName&&iocSet.has(pkt.dnsQueryName.toLowerCase()));
      if(hit)layerHTML+=`<div class="layer-group"><div class="layer-header" style="color:var(--danger)">THREAT INTELLIGENCE</div><div class="layer-fields"><div class="layer-field"><span class="field-value" style="color:var(--danger)">This packet matches a loaded IoC indicator!</span></div></div></div>`;
    }
  }
  els.detailLayers.innerHTML=layerHTML;
  els.detailLayers.querySelectorAll('.layer-header').forEach(h=>{
    h.addEventListener('click',()=>{h.classList.toggle('collapsed');const fields=h.nextElementSibling;if(fields)fields.classList.toggle('hidden');});
  });
  els.hexDump.innerHTML=generateHexDump(pkt.rawBytes);
  if(AppState.diffPacketB)els.btnDiff.classList.remove('hidden');
  scrollToSelectedRow();
}
export function closeDetailPane(){els.detailPane.classList.add('hidden');}
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

// ===== TCP Stream =====
export function followTCPStream(){
  const idx=AppState.selectedPacketIdx;if(idx<0)return;
  const pkt=AppState.filteredPackets[idx];if(!pkt||!pkt.tcpFlags)return;
  const client=pkt.srcIP+':'+pkt.srcPort;
  const stk=pkt.srcIP+':'+pkt.srcPort<pkt.dstIP+':'+pkt.dstPort?pkt.srcIP+':'+pkt.srcPort+'|'+pkt.dstIP+':'+pkt.dstPort:pkt.dstIP+':'+pkt.dstPort+'|'+pkt.srcIP+':'+pkt.srcPort;
  const streamPkts=AppState.streamIndex.get(stk)||[];
  let html='';let totalBytes=0;
  for(const sp of streamPkts){
    if(sp.tcpPayloadLength>0&&sp.rawBytes){
      const payload=sp.rawBytes.subarray(sp.tcpPayloadOffset,sp.tcpPayloadOffset+sp.tcpPayloadLength);
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
export function showConversations(){
  const tbody=document.querySelector('#conversations-table tbody');
  const conns=[...AppState.connections.values()].sort((a,b)=>b.bytes-a.bytes);
  tbody.innerHTML=conns.map(c=>{
    const dur=(c.lastTs-c.firstTs)/1000;
    return `<tr><td>${escapeHTML(c.a)}</td><td>${escapeHTML(c.b)}</td><td>${c.packets}</td><td>${formatBytes(c.bytes)}</td><td>${dur.toFixed(2)}s</td><td>${escapeHTML([...c.protocols].join(', '))}</td></tr>`;
  }).join('');
  els.conversationsModal.classList.remove('hidden');
}

// ===== Bookmarks =====
export function toggleBookmark(num){if(AppState.bookmarks.has(num))AppState.bookmarks.delete(num);else AppState.bookmarks.add(num);renderVisibleRows();}

// ===== Export =====
function csvEscape(val){let s=String(val??'');if(/^[=+\-@\t\r]/.test(s))s="'"+s;return '"'+s.replace(/"/g,'""')+'"';}
export function exportCSV(){
  const rows=[['#','Time','Source','Destination','Protocol','Length','Info','Anomalies','Notes'].map(csvEscape)];
  for(const p of AppState.filteredPackets){
    rows.push([p.number,p.relativeTime?.toFixed(6)||'',p.srcIP||'',p.dstIP||'',p.protocol,p.originalLength||p.capturedLength,p.info||'',p.anomalies.join('; '),AppState.annotations.get(p.number)||''].map(csvEscape));
  }
  downloadText(rows.map(r=>r.join(',')).join('\n'),'packets.csv','text/csv');
}
export function exportJSON(){
  const data=AppState.filteredPackets.map(p=>({number:p.number,time:p.relativeTime,src:p.srcIP,dst:p.dstIP,protocol:p.protocol,length:p.originalLength||p.capturedLength,info:p.info,anomalies:p.anomalies,note:AppState.annotations.get(p.number)||null}));
  downloadText(JSON.stringify(data,null,2),'packets.json','application/json');
}
function downloadText(text,name,type){const a=document.createElement('a');const url=URL.createObjectURL(new Blob([text],{type}));a.href=url;a.download=name;a.click();URL.revokeObjectURL(url);}
export function downloadBlob(bytes,filename,contentType){
  const blob=new Blob([bytes],{type:contentType});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');a.href=url;a.download=filename;a.click();
  URL.revokeObjectURL(url);
}

// ===== Screenshot =====
export function screenshotPanel(panel){
  const body=panel.querySelector('.panel-body');const svg=body.querySelector('svg');const canvas=body.querySelector('canvas');
  if(canvas){const a=document.createElement('a');a.href=canvas.toDataURL('image/png');a.download='panel.png';a.click();return;}
  if(svg){const clone=svg.cloneNode(true);const s=new XMLSerializer().serializeToString(clone);const blob=new Blob([s],{type:'image/svg+xml'});const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='panel.svg';a.click();URL.revokeObjectURL(url);}
}

// ===== Theme =====
export function toggleTheme(){document.body.dataset.theme=document.body.dataset.theme==='dark'?'light':'dark';renderAll();}

// ===== Fullscreen =====
export function togglePanelFullscreen(panel){panel.classList.toggle('fullscreen');setTimeout(renderAll,350);}

// ===== GeoIP Map =====
export function showGeoIPMap(){
  const canvas=els.geoipCanvas;const ctx=canvas.getContext('2d');const W=canvas.width,H=canvas.height;
  ctx.fillStyle='#1a1a2e';ctx.fillRect(0,0,W,H);
  ctx.strokeStyle='#2d3748';ctx.lineWidth=1;ctx.fillStyle='#2d3748';
  const continents=[[160,80,240,140],[350,60,180,120],[350,200,120,100],[580,60,200,160],[640,200,100,80],[80,230,60,50]];
  for(const[x,y,w,h]of continents){ctx.fillRect(x,y,w,h);ctx.strokeRect(x,y,w,h);}
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
export function loadCompareFile(){
  const isTauri=!!(window.__TAURI__);
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
function isValidPcapFile(file){
  const name=(file.name||file).toString().toLowerCase();
  return ['.pcap','.pcapng','.cap'].some(ext=>name.endsWith(ext));
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

// ===== Protocol Stats =====
export function showProtocolStats(){
  const pkts=AppState.packets;
  // E1: Pre-compute per-protocol arrays once on modal open
  const tcpPkts=pkts.filter(p=>p.protocol==='TCP'||p.protocol==='HTTP');
  const dnsPkts=pkts.filter(p=>p.protocol==='DNS');
  const httpPkts=pkts.filter(p=>p.protocol==='HTTP');
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
  els.statsModal.querySelectorAll('.stats-tab').forEach(btn=>{
    btn.onclick=()=>{els.statsModal.querySelectorAll('.stats-tab').forEach(b=>b.classList.remove('active'));btn.classList.add('active');renderTab(btn.dataset.tab);};
  });
  els.statsModal.classList.remove('hidden');
}

// ===== Extraction =====
function _extractPacket(p,text,reqUrlMap,results){
  const authMatch=text.match(RE_BASIC_AUTH);
  if(authMatch){try{const decoded=atob(authMatch[1]);const parts=decoded.split(':');results.push({type:'credential',protocol:'HTTP',src:p.srcIP,dst:p.dstIP,detail:`Basic Auth user="${parts[0]}"`,size:'',pkt:p.number});}catch{}}
  const bearerMatch=text.match(RE_BEARER);
  if(bearerMatch)results.push({type:'credential',protocol:'HTTP',src:p.srcIP,dst:p.dstIP,detail:`Bearer token: ${bearerMatch[1]}...`,size:'',pkt:p.number});
  const cookieMatch=text.match(RE_COOKIE);
  if(cookieMatch){const cv=cookieMatch[1];if(RE_SESSION_COOKIE.test(cv))results.push({type:'credential',protocol:'HTTP',src:p.srcIP,dst:p.dstIP,detail:`Session cookie: ${cv.length>70?cv.slice(0,68)+'..':cv}`,size:'',pkt:p.number});}
  if(p.httpMethod==='POST'){const bodyStart=text.indexOf('\r\n\r\n');if(bodyStart>-1){const body=text.slice(bodyStart+4,bodyStart+500);if(RE_PASSWORD_FIELD.test(body)){const sanitized=body.replace(RE_SANITIZE_PASS,'$1****');results.push({type:'credential',protocol:'HTTP',src:p.srcIP,dst:p.dstIP,detail:`POST form data: ${sanitized.length>80?sanitized.slice(0,78)+'..':sanitized}`,size:'',pkt:p.number});}}}
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
  if(p.httpMethod==='GET'&&p.httpUrl){
    const ext=(p.httpUrl.split('?')[0].split('.').pop()||'').toLowerCase();
    if(FILE_EXTS.has(ext)){results.push({type:'request',protocol:'HTTP',src:p.srcIP,dst:p.dstIP,detail:`${p.httpMethod} ${p.httpUrl.length>90?p.httpUrl.slice(0,88)+'..':p.httpUrl}`,size:'',pkt:p.number});}
  }
  if(p.dstPort===21||p.srcPort===21){
    const userMatch=text.match(RE_FTP_USER);if(userMatch)results.push({type:'credential',protocol:'FTP',src:p.srcIP,dst:p.dstIP,detail:`User: ${userMatch[1]}`,size:'',pkt:p.number});
    const passMatch=text.match(RE_FTP_PASS);if(passMatch)results.push({type:'credential',protocol:'FTP',src:p.srcIP,dst:p.dstIP,detail:'Password: ****',size:'',pkt:p.number});
  }
  if(p.dstPort===25||p.dstPort===587||p.srcPort===25){
    const smtpAuth=text.match(RE_SMTP_AUTH);if(smtpAuth)results.push({type:'credential',protocol:'SMTP',src:p.srcIP,dst:p.dstIP,detail:`SMTP Auth (${smtpAuth[1]})`,size:'',pkt:p.number});
    const mailFrom=text.match(RE_SMTP_MAIL);if(mailFrom)results.push({type:'credential',protocol:'SMTP',src:p.srcIP,dst:p.dstIP,detail:`Mail from: ${mailFrom[1]}`,size:'',pkt:p.number});
  }
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
export function showExtractions(){
  els.extractionModal.classList.remove('hidden');
  els.extractionContent.innerHTML='<p style="color:var(--text-muted)">Scanning packets\u2026</p>';
  const results=[];
  const reqUrlMap=new Map();
  for(const p of AppState.packets){
    if(p.httpMethod&&p.httpUrl){
      const key=`${p.srcIP}:${p.srcPort}-${p.dstIP}:${p.dstPort}`;
      if(!reqUrlMap.has(key))reqUrlMap.set(key,[]);
      reqUrlMap.get(key).push({url:p.httpUrl,method:p.httpMethod,pkt:p.number});
    }
  }
  const CHUNK=500;
  const packets=AppState.packets;
  let idx=0;
  function processChunk(){
    const chunkEnd=Math.min(idx+CHUNK,packets.length);
    for(;idx<chunkEnd;idx++){
      const p=packets[idx];
      if(p.tcpPayloadLength>0&&p.rawBytes){
        const payload=p.rawBytes.subarray(p.tcpPayloadOffset,Math.min(p.tcpPayloadOffset+p.tcpPayloadLength,p.tcpPayloadOffset+2000));
        let text='';try{text=new TextDecoder().decode(payload);}catch{}
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

// ===== Session Reconstruction & HTTP Object Export =====
function reconstructHTTPObjects(){
  const objects=[];
  // E2: Reuse AppState.streamIndex instead of rebuilding stream map
  for(const[key,streamPkts]of AppState.streamIndex){
    const pkts=[...streamPkts].sort((a,b)=>a.timestamp-b.timestamp);
    let requestInfo=null;
    for(const p of pkts){
      if(p.httpMethod&&p.httpUrl)requestInfo={method:p.httpMethod,url:p.httpUrl,pkt:p.number};
      if(p.tcpPayloadLength>0&&p.rawBytes){
        const payload=p.rawBytes.subarray(p.tcpPayloadOffset,p.tcpPayloadOffset+p.tcpPayloadLength);
        if(payload.length>=5&&payload[0]===72&&payload[1]===84&&payload[2]===84&&payload[3]===80&&payload[4]===47){
          const fullPayload=payload;
          const headerEndIdx=findHeaderEnd(fullPayload);
          if(headerEndIdx>0){
            const headerStr=new TextDecoder().decode(fullPayload.subarray(0,headerEndIdx));
            const ctMatch=headerStr.match(RE_CONTENT_TYPE);
            const clMatch=headerStr.match(RE_CONTENT_LENGTH);
            const cdMatch=headerStr.match(RE_CONTENT_DISP);
            const statusMatch=headerStr.match(/HTTP\/\d\.\d\s+(\d+)/);
            if(ctMatch){
              const ct=ctMatch[1].trim();
              const bodyStart=headerEndIdx;
              const bodyBytes=fullPayload.subarray(bodyStart);
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

// ===== Latency =====
export function showLatency(){
  const results=[];
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

// ===== Sequence Diagram =====
export function showSequenceDiagram(){
  const hosts=[...AppState.hosts.entries()].sort((a,b)=>b[1]-a[1]).map(([ip])=>ip);
  for(const sel of[els.seqHostA,els.seqHostB]){
    const val=sel.value;sel.innerHTML='<option value="">Auto</option>'+hosts.map(h=>`<option value="${h}">${h}</option>`).join('');
    sel.value=val;
  }
  renderSequenceSVG();
  els.sequenceModal.classList.remove('hidden');
}
export function renderSequenceSVG(){
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
  svg.append('defs').append('marker').attr('id','seq-arrowhead').attr('viewBox','0 0 10 10').attr('refX',10).attr('refY',5).attr('markerWidth',6).attr('markerHeight',6).attr('orient','auto').append('path').attr('d','M 0 0 L 10 5 L 0 10 z').attr('fill','currentColor');
  const xA=margin.left,xB=margin.left+colW;
  svg.append('text').attr('class','seq-host-label').attr('x',xA).attr('y',25).text(hostA);
  svg.append('text').attr('class','seq-host-label').attr('x',xB).attr('y',25).text(hostB);
  svg.append('line').attr('class','seq-lifeline').attr('x1',xA).attr('y1',margin.top).attr('x2',xA).attr('y2',H-20);
  svg.append('line').attr('class','seq-lifeline').attr('x1',xB).attr('y1',margin.top).attr('x2',xB).attr('y2',H-20);
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

// ===== IO Graph =====
export function showIOGraph(){
  renderIOGraphSVG();
  els.iographModal.classList.remove('hidden');
  els.ioMetric.onchange=renderIOGraphSVG;
  els.ioInterval.onchange=renderIOGraphSVG;
}
export function renderIOGraphSVG(){
  const svg=d3.select('#iograph-svg');svg.selectAll('*').remove();
  const pkts=AppState.packets;if(!pkts.length)return;
  const metric=els.ioMetric.value;const interval=parseInt(els.ioInterval.value);
  const tMin=pkts[0].timestamp,tMax=pkts[pkts.length-1].timestamp;
  const numBins=Math.max(1,Math.ceil((tMax-tMin)/interval));
  const protocols=[...AppState.protocolStats.keys()];
  const buckets={};for(const proto of protocols)buckets[proto]=new Array(numBins).fill(0);
  for(const p of pkts){
    const idx=Math.min(Math.floor((p.timestamp-tMin)/interval),numBins-1);
    if(idx>=0)buckets[p.protocol][idx]+=(metric==='bytes'?(p.originalLength||p.capturedLength):1);
  }
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
  svg.append('text').attr('x',15).attr('y',H/2).attr('transform',`rotate(-90,15,${H/2})`).attr('text-anchor','middle').attr('font-size','10px').attr('fill','var(--text-muted)').text(metric==='bytes'?'Bytes/sec':'Packets/sec');
}

// ===== Packet Diff =====
export function showPacketDiff(){
  const pktA=AppState.filteredPackets[AppState.selectedPacketIdx];
  const pktB=AppState.diffPacketB;
  if(!pktA||!pktB)return;
  els.diffInfo.textContent=`Packet #${pktA.number} vs #${pktB.number}`;
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

// ===== Annotations =====
let currentNotePacket=null;
export function showNotePopover(pktNum,e){
  currentNotePacket=pktNum;
  els.noteText.value=AppState.annotations.get(pktNum)||'';
  els.notePopover.classList.remove('hidden');
  const rect=e.target.getBoundingClientRect();
  els.notePopover.style.left=Math.min(rect.left,window.innerWidth-280)+'px';
  els.notePopover.style.top=(rect.bottom+4)+'px';
  els.noteText.focus();
}
export function saveAnnotation(){
  if(currentNotePacket===null)return;
  const text=els.noteText.value.trim();
  if(text)AppState.annotations.set(currentNotePacket,text);else AppState.annotations.delete(currentNotePacket);
  saveAnnotations();hideNotePopover();currentNotePacket=null;renderVisibleRows();
}
export function deleteAnnotation(){if(currentNotePacket!==null){AppState.annotations.delete(currentNotePacket);saveAnnotations();hideNotePopover();currentNotePacket=null;renderVisibleRows();}}
export function showNotesModal(){
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
const MAX_ANNOTATIONS_SIZE = 1024 * 1024;
function _storageKey(name){return 'wsv-notes-'+encodeURIComponent(name).slice(0,200);}
export function saveAnnotations(){try{const data=JSON.stringify([...AppState.annotations]);if(data.length>MAX_ANNOTATIONS_SIZE){console.warn('Annotations too large to save (',data.length,'bytes)');return;}localStorage.setItem(_storageKey(AppState.fileName),data);}catch{}}
export function loadAnnotations(){try{const d=localStorage.getItem(_storageKey(AppState.fileName));if(d){const parsed=JSON.parse(d);if(Array.isArray(parsed))AppState.annotations=new Map(parsed);}}catch{}}

// ===== IoC Matching =====
export function showIoCModal(){
  els.iocModal.classList.remove('hidden');
  if(AppState.iocMatches.length>0)renderIoCResults();
}
export function scanIoCs(){
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
  const byIP=new Map();
  for(const m of matches){
    const key=m.pkt.srcIP||m.pkt.dstIP;
    byIP.set(key,(byIP.get(key)||0)+1);
  }
  let html='<div class="ioc-summary">';
  html+=`<div class="stat-card"><div class="stat-label">Total Matches</div><div class="stat-value">${matches.length}</div></div>`;
  html+=`<div class="stat-card"><div class="stat-label">Unique IoCs Hit</div><div class="stat-value">${byIP.size}</div></div>`;
  let dwOverlap=0;
  for(const[ip]of byIP){if(AppState.darkWebFlags.has(ip))dwOverlap++;}
  if(dwOverlap>0)html+=`<div class="stat-card"><div class="stat-label">Also Dark Web Ports</div><div class="stat-value" style="color:var(--danger)">${dwOverlap}</div></div>`;
  html+='</div>';
  html+='<table class="extraction-table"><thead><tr><th>Pkt#</th><th>Type</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Info</th><th>Flags</th></tr></thead><tbody>';
  for(const m of matches.slice(0,200)){
    const p=m.pkt;
    const badges=[{cls:'threat',label:'IoC'}];
    const srcDW=AppState.darkWebFlags.get(p.srcIP);
    const dstDW=AppState.darkWebFlags.get(p.dstIP);
    if(srcDW||dstDW)badges.push({cls:'darkweb',label:'Dark Web'});
    const flags=badges.map(b=>`<span class="ioc-badge ${escapeHTML(b.cls)}">${escapeHTML(b.label)}</span>`).join(' ');
    html+=`<tr><td>${p.number}</td><td>${escapeHTML(m.matchType)}</td><td>${escapeHTML(p.srcIP||'')}</td><td>${escapeHTML(p.dstIP||'')}</td><td>${escapeHTML(p.protocol)}</td><td>${escapeHTML((p.info||'').slice(0,80))}</td><td>${flags}</td></tr>`;
  }
  html+='</tbody></table>';
  if(matches.length>200)html+=`<p style="color:var(--text-muted);margin-top:8px">Showing first 200 of ${matches.length} matches.</p>`;
  els.iocResults.innerHTML=html;
}

// ===== Connection State Machine =====
export function showConnStateModal(){
  renderConnState();
  els.connstateModal.classList.remove('hidden');
}
function _buildConnStateCache(){
  if(AppState.connStateCache)return AppState.connStateCache;
  // E3: Reuse AppState.streamIndex instead of re-scanning all packets
  const connections=[];
  for(const[stk,streamPkts]of AppState.streamIndex){
    // Determine client (first SYN sender, or first packet sender)
    let clientAddr=null;
    for(const p of streamPkts){if(p.tcpFlags&&p.tcpFlags.SYN&&!p.tcpFlags.ACK){clientAddr=p.srcIP+':'+p.srcPort;break;}}
    if(!clientAddr&&streamPkts.length>0)clientAddr=streamPkts[0].srcIP+':'+streamPkts[0].srcPort;
    const firstP=streamPkts[0];
    const serverAddr=clientAddr===(firstP.srcIP+':'+firstP.srcPort)?firstP.dstIP+':'+firstP.dstPort:firstP.srcIP+':'+firstP.srcPort;
    const conn={client:clientAddr,server:serverAddr,events:[],packets:0,bytes:0,firstTs:Infinity,lastTs:0};
    for(const p of streamPkts){
      conn.packets++;conn.bytes+=(p.originalLength||p.capturedLength);
      if(p.timestamp<conn.firstTs)conn.firstTs=p.timestamp;
      if(p.timestamp>conn.lastTs)conn.lastTs=p.timestamp;
      if(!p.tcpFlags)continue;
      const isClient=(p.srcIP+':'+p.srcPort)===conn.client;
      if(p.tcpFlags.SYN&&!p.tcpFlags.ACK)conn.events.push({type:'SYN',from:isClient?'client':'server',ts:p.timestamp,pkt:p.number});
      else if(p.tcpFlags.SYN&&p.tcpFlags.ACK)conn.events.push({type:'SYN-ACK',from:isClient?'client':'server',ts:p.timestamp,pkt:p.number});
      else if(p.tcpFlags.FIN)conn.events.push({type:'FIN',from:isClient?'client':'server',ts:p.timestamp,pkt:p.number});
      else if(p.tcpFlags.RST)conn.events.push({type:'RST',from:isClient?'client':'server',ts:p.timestamp,pkt:p.number});
      else if(p.tcpPayloadLength>0)conn.events.push({type:'DATA',from:isClient?'client':'server',ts:p.timestamp,pkt:p.number,size:p.tcpPayloadLength});
    }
    const types=new Set(conn.events.map(e=>e.type));
    let state='unknown';
    if(types.has('RST'))state='reset';
    else if(types.has('SYN')&&types.has('SYN-ACK')&&types.has('FIN'))state='complete';
    else if(types.has('SYN')&&types.has('SYN-ACK'))state='established';
    else if(types.has('SYN')&&!types.has('SYN-ACK'))state='halfopen';
    else if(types.has('DATA'))state='data-only';
    conn.state=state;conn.key=stk;
    connections.push(conn);
  }
  connections.sort((a,b)=>b.packets-a.packets);
  AppState.connStateCache=connections;
  return connections;
}
export function renderConnState(){
  const connections=_buildConnStateCache();
  const filter=els.connstateFilter.value;
  let filtered=connections;
  if(filter==='incomplete')filtered=connections.filter(c=>c.state==='halfopen'||c.state==='unknown');
  else if(filter==='reset')filtered=connections.filter(c=>c.state==='reset');
  else if(filter==='halfopen')filtered=connections.filter(c=>c.state==='halfopen');
  if(!filtered.length){els.connstateContent.innerHTML='<p style="color:var(--text-muted)">No TCP connections match the filter.</p>';return;}
  const stateCounts={complete:0,established:0,halfopen:0,reset:0,'data-only':0,unknown:0};
  for(const c of connections)stateCounts[c.state]=(stateCounts[c.state]||0)+1;
  let html='<div class="alert-result-summary">';
  html+=`<div class="stat-card"><div class="stat-label">Total TCP Connections</div><div class="stat-value">${connections.length}</div></div>`;
  html+=`<div class="stat-card"><div class="stat-label">Complete</div><div class="stat-value" style="color:var(--success)">${stateCounts.complete}</div></div>`;
  html+=`<div class="stat-card"><div class="stat-label">Established</div><div class="stat-value" style="color:var(--accent)">${stateCounts.established}</div></div>`;
  html+=`<div class="stat-card"><div class="stat-label">Half-Open</div><div class="stat-value" style="color:#a855f7">${stateCounts.halfopen}</div></div>`;
  html+=`<div class="stat-card"><div class="stat-label">RST / Reset</div><div class="stat-value" style="color:var(--danger)">${stateCounts.reset}</div></div>`;
  html+='</div>';
  for(const conn of filtered.slice(0,100)){
    const badgeClass=conn.state==='complete'?'complete':conn.state==='reset'?'reset':conn.state==='halfopen'?'halfopen':'incomplete';
    const dur=((conn.lastTs-conn.firstTs)/1000).toFixed(2);
    html+=`<div class="connstate-card">`;
    html+=`<h4>${escapeHTML(conn.client)} &harr; ${escapeHTML(conn.server)} <span class="connstate-badge ${badgeClass}">${conn.state.toUpperCase()}</span></h4>`;
    html+=`<div class="conn-detail">${conn.packets} packets | ${formatBytes(conn.bytes)} | ${dur}s</div>`;
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

// ===== Alert Rules Engine =====
export function showAlertsModal(){
  if(!AppState.alertRules.length)AppState.alertRules=[...DEFAULT_ALERT_RULES.map(r=>({...r}))];
  renderAlertRules();
  els.alertsModal.classList.remove('hidden');
}
export function renderAlertRules(){
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
  els.alertRulesList.querySelectorAll('.alert-rule-toggle').forEach(cb=>{cb.onchange=()=>{rules[cb.dataset.idx].enabled=cb.checked;};});
  els.alertRulesList.querySelectorAll('.alert-rule-name').forEach(inp=>{inp.onchange=()=>{rules[inp.dataset.idx].name=inp.value;};});
  els.alertRulesList.querySelectorAll('.alert-rule-type').forEach(sel=>{sel.onchange=()=>{rules[sel.dataset.idx].type=sel.value;};});
  els.alertRulesList.querySelectorAll('.alert-rule-thresh').forEach(inp=>{inp.onchange=()=>{rules[inp.dataset.idx].threshold=parseInt(inp.value)||0;};});
  els.alertRulesList.querySelectorAll('.alert-rule-window').forEach(inp=>{inp.onchange=()=>{rules[inp.dataset.idx].window=parseInt(inp.value)||0;};});
  els.alertRulesList.querySelectorAll('.alert-rule-sev').forEach(sel=>{sel.onchange=()=>{rules[sel.dataset.idx].severity=sel.value;};});
  els.alertRulesList.querySelectorAll('.rule-remove').forEach(btn=>{btn.onclick=()=>{rules.splice(parseInt(btn.dataset.idx),1);renderAlertRules();};});
}
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
export function runAlertRules(){
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

// ===== Coloring Rules UI =====
export function showColoringModal(){
  els.coloringProfile.value=AppState.coloringProfile;
  renderColoringRules();
  els.coloringModal.classList.remove('hidden');
}
export function renderColoringRules(){
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
  els.coloringRulesList.querySelectorAll('.rule-enabled').forEach(cb=>{cb.addEventListener('change',()=>{rules[cb.dataset.idx].enabled=cb.checked;invalidateColoringCache();renderVisibleRows();});});
}
