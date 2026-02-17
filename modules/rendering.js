// modules/rendering.js — Network graph, timeline, heatmap, charts, packet table, virtual-scroll
'use strict';

import { AppState, $, protoColor, formatBytes, escapeHTML, hexToRGBA, debounce, isPrivateIP, getSubnet, getDarkWebLabel, evaluateColoringRules, ROW_HEIGHT, BUFFER, DARKWEB_PORTS, SUBNET_COLORS, getTransportGroup, TRANSPORT_GROUP_COLORS } from './state.js';
import { els, showTooltip, hideTooltip } from './dom.js';

// ===== Render entry points =====
export function renderAll(){renderNetworkGraph();renderTimeline();renderProtocolCharts();renderPacketTable();}

export function onFilterChange(){
  AppState.applyFilters();
  AppState.selectedPacketIdx=-1;AppState.diffPacketB=null;
  if(AppState.filterError){els.filterError.textContent=AppState.filterError;els.filterError.classList.remove('hidden');}
  else els.filterError.classList.add('hidden');
  renderPacketTable();updateNetworkHighlights();renderProtocolCharts();saveStateToURL();
}

// URL state (used by onFilterChange)
function saveStateToURL(){
  const f=AppState.filters;const p=new URLSearchParams();
  if(f.selectedHost)p.set('host',f.selectedHost);if(f.protocolFilter)p.set('proto',f.protocolFilter);
  if(f.searchText)p.set('q',f.searchText);
  const hash=p.toString();window.location.hash=hash||'';
}
export function loadStateFromURL(){
  const p=new URLSearchParams(window.location.hash.slice(1));
  if(p.has('host'))AppState.filters.selectedHost=p.get('host');
  if(p.has('proto'))AppState.filters.protocolFilter=p.get('proto');
  if(p.has('q')){AppState.filters.searchText=p.get('q');els.tableSearch.value=p.get('q');}
}

// ===== Network Graph =====
let _graphSim = null, _graphDataKey = '';
export function renderNetworkGraph(){
  const container=$('panel-network').querySelector('.panel-body');
  const svg=d3.select('#network-graph');svg.selectAll('*').remove();
  const W=container.clientWidth,H=container.clientHeight;if(!W||!H)return;
  svg.attr('viewBox',`0 0 ${W} ${H}`);
  const layer=AppState.graphLayer;
  const newDataKey=AppState.packets.length+'_'+layer+'_'+AppState.graphHostLimit;
  if(_graphSim&&_graphDataKey===newDataKey){
    _graphSim.force('center',d3.forceCenter(W/2,H/2));
    _graphSim.alpha(0.1).restart();
    return;
  }
  _graphDataKey=newDataKey;
  if(_graphSim){_graphSim.stop();_graphSim=null;}
  let nodeMap=new Map(),edgeMap=new Map();
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
  _graphSim=sim;
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
    const dw=AppState.darkWebFlags.get(ip);if(dw&&dw.size>0)html+=`<div class="tip-label">Dark Web Ports</div><div class="tip-value">${[...dw.entries()].map(([port,cnt])=>`${escapeHTML(String(DARKWEB_PORTS[port]||port))} (${cnt})`).join(', ')}</div>`;
    showTooltip(html,e.pageX,e.pageY,{raw:true});
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
    if(hullSel){
      hullSel.attr('d',d=>{
        const pts=d.nodes.map(n=>[n.x,n.y]);
        if(pts.length<3){const[x,y]=pts[0]||[0,0];return `M${x-30},${y-30}L${x+30},${y-30}L${x+30},${y+30}L${x-30},${y+30}Z`;}
        const hull=d3.polygonHull(pts);
        if(!hull)return '';
        const cx=d3.mean(hull,p=>p[0]),cy=d3.mean(hull,p=>p[1]);
        const expanded=hull.map(([x,y])=>[x+(x-cx)*0.3,y+(y-cy)*0.3]);
        return 'M'+expanded.map(p=>p.join(',')).join('L')+'Z';
      });
      g.selectAll('.subnet-group-label').attr('x',d=>d3.mean(d.nodes,n=>n.x)).attr('y',d=>d3.mean(d.nodes,n=>n.y)-Math.max(...d.nodes.map(n=>rScale(n.bytes)))-15);
    }
  });
}
export function updateNetworkHighlights(){
  const host=AppState.filters.selectedHost;
  d3.selectAll('#network-graph .node').classed('dimmed',d=>host&&d.id!==host&&!d.id.startsWith(host+':'));
  d3.selectAll('#network-graph .link').classed('dimmed',d=>host&&d.source.id!==host&&d.target.id!==host&&!d.source.id.startsWith(host+':')&&!d.target.id.startsWith(host+':'));
}

// ===== Timeline =====
export function renderTimeline(){
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
  const svgD3=d3.select(svgEl);svgD3.selectAll('*').remove();
  const xAxis=d3.axisBottom(xScale).ticks(6).tickFormat(d=>`${((d-tMin)/1000).toFixed(1)}s`);
  svgD3.append('g').attr('class','timeline-axis').attr('transform',`translate(0,${H-margin.bottom})`).call(xAxis);
  brushSvg.selectAll('*').remove();brushSvg.attr('viewBox',`0 0 ${W} 50`).attr('width',W).attr('height',50);
  const brushXScale=d3.scaleLinear().domain([tMin,tMax]).range([margin.left,W-margin.right]);
  const brush=d3.brushX().extent([[margin.left,5],[W-margin.right,45]]).on('end',e=>{
    if(!e.selection){AppState.filters.timeRange=null;}else{AppState.filters.timeRange=[brushXScale.invert(e.selection[0]),brushXScale.invert(e.selection[1])];}
    onFilterChange();
  });
  brushSvg.append('g').call(brush);
  const bCtx=document.createElement('canvas');bCtx.width=W;bCtx.height=50;
  const bc=bCtx.getContext('2d');bc.globalAlpha=0.3;
  const numBins=Math.min(200,W);const binW=(tMax-tMin)/numBins||1;const bins=new Array(numBins).fill(0);
  for(const p of pkts){const idx=Math.min(Math.floor((p.timestamp-tMin)/binW),numBins-1);if(idx>=0)bins[idx]++;}
  const maxBin=Math.max(...bins,1);
  for(let i=0;i<numBins;i++){const bx=margin.left+(i/numBins)*(W-margin.left-margin.right);const bw=(W-margin.left-margin.right)/numBins;const bh=(bins[i]/maxBin)*35;bc.fillStyle='#6366f1';bc.fillRect(bx,45-bh,bw,bh);}
}

// ===== Heatmap Timeline =====
let _heatmapGridCache=null, _heatmapCacheKey='';
export function renderHeatmapTimeline(){
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
  const numCols=Math.max(1,Math.min(200,Math.floor(plotW/4)));
  const protocols=[...AppState.protocolStats.keys()].sort((a,b)=>(AppState.protocolStats.get(b)||0)-(AppState.protocolStats.get(a)||0)).slice(0,12);
  const numRows=protocols.length;if(!numRows)return;
  const cellW=plotW/numCols;
  const cellH=plotH/numRows;
  const binDur=(tMax-tMin)/numCols||1;
  const cacheKey=pkts.length+'_'+numCols+'_'+numRows;
  let grid, maxVal;
  if(_heatmapCacheKey===cacheKey&&_heatmapGridCache){
    grid=_heatmapGridCache.grid;maxVal=_heatmapGridCache.maxVal;
  } else {
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
  ctx.fillStyle=getComputedStyle(document.body).getPropertyValue('--text-muted')||'#64748b';
  ctx.font='9px -apple-system, sans-serif';
  ctx.textAlign='right';
  for(let r=0;r<numRows;r++){
    ctx.fillText(protocols[r],margin.left-4,margin.top+r*cellH+cellH/2+3);
  }
  const svgEl=$('timeline-svg');
  const svgD3=d3.select(svgEl);svgD3.selectAll('*').remove();
  svgEl.setAttribute('viewBox',`0 0 ${W} ${H}`);svgEl.setAttribute('width',W);svgEl.setAttribute('height',H);
  const xScale=d3.scaleLinear().domain([tMin,tMax]).range([margin.left,W-margin.right]);
  const xAxis=d3.axisBottom(xScale).ticks(6).tickFormat(d=>`${((d-tMin)/1000).toFixed(1)}s`);
  svgD3.append('g').attr('class','timeline-axis').attr('transform',`translate(0,${H-margin.bottom})`).call(xAxis);
  const brushSvg=d3.select('#timeline-brush');
  brushSvg.selectAll('*').remove();brushSvg.attr('viewBox',`0 0 ${W} 50`).attr('width',W).attr('height',50);
  const brushXScale=d3.scaleLinear().domain([tMin,tMax]).range([margin.left,W-margin.right]);
  const brush=d3.brushX().extent([[margin.left,5],[W-margin.right,45]]).on('end',e=>{
    if(!e.selection){AppState.filters.timeRange=null;}else{AppState.filters.timeRange=[brushXScale.invert(e.selection[0]),brushXScale.invert(e.selection[1])];}
    onFilterChange();
  });
  brushSvg.append('g').call(brush);
}

// ===== Protocol Charts (Two-Level Drill-Down) =====
function getChartData() {
  // Level 1: transport groups (TCP, UDP, ICMP, ARP, Other)
  if (AppState.chartDrilldown === null) {
    const groups = { TCP: 0, UDP: 0, ICMP: 0, ARP: 0, Other: 0 };
    for (const p of AppState.packets) {
      const g = getTransportGroup(p);
      groups[g] = (groups[g] || 0) + 1;
    }
    return Object.entries(groups).filter(([, v]) => v > 0).map(([k, v]) => ({ protocol: k, count: v })).sort((a, b) => b.count - a.count);
  }
  // Level 2: app protocols within the drilled-down transport group (from filtered packets)
  const stats = new Map();
  for (const p of AppState.filteredPackets) {
    stats.set(p.protocol, (stats.get(p.protocol) || 0) + 1);
  }
  return [...stats.entries()].map(([k, v]) => ({ protocol: k, count: v })).sort((a, b) => b.count - a.count);
}

function chartColor(name) {
  if (AppState.chartDrilldown === null) return TRANSPORT_GROUP_COLORS[name] || '#90a4ae';
  return protoColor(name);
}

function updateBreadcrumb() {
  const bc = $('chart-breadcrumb');
  if (!bc) return;
  if (AppState.chartDrilldown === null) {
    bc.classList.add('hidden');
  } else {
    bc.classList.remove('hidden');
    const current = bc.querySelector('.breadcrumb-current');
    if (current) current.textContent = AppState.chartDrilldown;
  }
}

export function renderProtocolCharts() { updateBreadcrumb(); renderPieChart(); renderBarChart(); }

function renderPieChart() {
  const c = $('panel-protocols').querySelector('.chart-container'); if (!c) return;
  const svg = d3.select('#protocol-pie'); svg.selectAll('*').remove();
  const W = c.clientWidth, H = c.clientHeight; if (!W || !H) return;
  svg.attr('viewBox', `0 0 ${W} ${H}`);
  const data = getChartData();
  if (!data.length) return;
  // Reserve margin for leader-line labels
  const labelMargin = 40;
  const radius = Math.max(30, Math.min(W, H) / 2 - labelMargin);
  const g = svg.append('g').attr('transform', `translate(${W / 2},${H / 2})`);
  const pie = d3.pie().value(d => d.count).sort(null);
  const arc = d3.arc().innerRadius(radius * 0.3).outerRadius(radius);
  const slices = g.selectAll('path').data(pie(data)).join('path')
    .attr('d', arc).attr('fill', d => chartColor(d.data.protocol))
    .attr('stroke', 'rgba(0,0,0,0.3)').attr('stroke-width', 1).style('cursor', 'pointer');
  slices.on('click', (e, d) => {
    if (AppState.chartDrilldown === null) {
      AppState.chartDrilldown = d.data.protocol;
      AppState.filters.transportGroup = d.data.protocol;
      onFilterChange(); renderTimeline(); renderProtocolCharts();
    } else {
      if (AppState.filters.protocolFilter === d.data.protocol) AppState.filters.protocolFilter = null;
      else AppState.filters.protocolFilter = d.data.protocol;
      onFilterChange(); renderTimeline();
    }
  }).on('mouseover', (e, d) => {
    const total = d3.sum(data, dd => dd.count);
    const pct = ((d.data.count / total) * 100).toFixed(1);
    showTooltip(`<div class="tip-value">${escapeHTML(d.data.protocol)}: ${d.data.count} packets (${pct}%)</div>`, e.pageX, e.pageY, { raw: true });
  }).on('mouseout', hideTooltip);

  // Labels: inside for large slices, leader lines for small slices
  const total = d3.sum(data, dd => dd.count);
  const pieData = pie(data);
  const innerLabelArc = d3.arc().innerRadius(radius * 0.65).outerRadius(radius * 0.65);
  const outerPt = d3.arc().innerRadius(radius * 1.03).outerRadius(radius * 1.03);
  const leaderMid = d3.arc().innerRadius(radius * 1.12).outerRadius(radius * 1.12);

  // Large slices: label inside
  g.selectAll('.label-inside').data(pieData).join('text')
    .attr('class', 'label-inside')
    .attr('transform', d => `translate(${innerLabelArc.centroid(d)})`)
    .attr('text-anchor', 'middle').attr('font-size', '10px')
    .attr('fill', 'var(--text-primary)')
    .text(d => d.data.count / total >= 0.03 ? d.data.protocol : '');

  // Small slices (<3%): leader line + external label
  const smallSlices = pieData.filter(d => d.data.count / total < 0.03 && d.data.count / total > 0);

  // Leader lines: 3-point polyline from slice edge → elbow → horizontal tail
  g.selectAll('.leader-line').data(smallSlices).join('polyline')
    .attr('class', 'leader-line')
    .attr('fill', 'none')
    .attr('stroke', 'var(--text-muted)')
    .attr('stroke-width', 1)
    .attr('opacity', 0.6)
    .attr('points', d => {
      const mid = (d.startAngle + d.endAngle) / 2;
      const isRight = mid < Math.PI;
      const p1 = outerPt.centroid(d);
      const p2 = leaderMid.centroid(d);
      // Horizontal tail clamped within viewBox
      const tailX = isRight ? Math.min(p2[0] + 14, W / 2 - 4) : Math.max(p2[0] - 14, -W / 2 + 4);
      const p3 = [tailX, p2[1]];
      return [p1, p2, p3].map(p => p.join(',')).join(' ');
    });

  // External labels clamped so text doesn't overflow
  g.selectAll('.label-outside').data(smallSlices).join('text')
    .attr('class', 'label-outside')
    .attr('font-size', '9px')
    .attr('fill', 'var(--text-secondary)')
    .attr('transform', d => {
      const mid = (d.startAngle + d.endAngle) / 2;
      const isRight = mid < Math.PI;
      const p = leaderMid.centroid(d);
      const tailX = isRight ? Math.min(p[0] + 14, W / 2 - 4) : Math.max(p[0] - 14, -W / 2 + 4);
      const labelX = tailX + (isRight ? 3 : -3);
      return `translate(${labelX},${p[1]})`;
    })
    .attr('text-anchor', d => {
      const mid = (d.startAngle + d.endAngle) / 2;
      return mid < Math.PI ? 'start' : 'end';
    })
    .attr('dominant-baseline', 'middle')
    .text(d => d.data.protocol);
}

function renderBarChart() {
  const containers = $('panel-protocols').querySelectorAll('.chart-container'); const c = containers[1]; if (!c) return;
  const svg = d3.select('#protocol-bar'); svg.selectAll('*').remove();
  const W = c.clientWidth, H = c.clientHeight; if (!W || !H) return;
  svg.attr('viewBox', `0 0 ${W} ${H}`);
  const data = getChartData().slice(0, 8);
  if (!data.length) return;
  const m = { top: 10, right: 10, bottom: 30, left: 50 };
  const x = d3.scaleBand().domain(data.map(d => d.protocol)).range([m.left, W - m.right]).padding(0.3);
  const y = d3.scaleLinear().domain([0, d3.max(data, d => d.count)]).nice().range([H - m.bottom, m.top]);
  svg.append('g').attr('class', 'axis').attr('transform', `translate(0,${H - m.bottom})`).call(d3.axisBottom(x).tickSize(0));
  svg.append('g').attr('class', 'axis').attr('transform', `translate(${m.left},0)`).call(d3.axisLeft(y).ticks(5).tickFormat(d3.format('.2s')));
  const bars = svg.selectAll('.bar').data(data).join('rect').attr('class', 'bar')
    .attr('x', d => x(d.protocol)).attr('y', d => y(d.count))
    .attr('width', x.bandwidth()).attr('height', d => H - m.bottom - y(d.count))
    .attr('fill', d => chartColor(d.protocol)).attr('rx', 3).style('cursor', 'pointer');
  bars.on('click', (e, d) => {
    if (AppState.chartDrilldown === null) {
      AppState.chartDrilldown = d.protocol;
      AppState.filters.transportGroup = d.protocol;
      onFilterChange(); renderTimeline(); renderProtocolCharts();
    } else {
      if (AppState.filters.protocolFilter === d.protocol) AppState.filters.protocolFilter = null;
      else AppState.filters.protocolFilter = d.protocol;
      onFilterChange(); renderTimeline();
    }
  }).on('mouseover', (e, d) => {
    showTooltip(`<div class="tip-value">${escapeHTML(d.protocol)}: ${d.count} packets</div>`, e.pageX, e.pageY, { raw: true });
  }).on('mouseout', hideTooltip);
}

// ===== Packet Table =====
let _tableClickDelegated=false;
export function renderPacketTable(){
  els.tablePacketCount.textContent=`${AppState.filteredPackets.length} packets`;
  _rowPool.length=0;_prevStart=-1;_prevEnd=-1;
  els.tableBody.innerHTML=`<div class="table-spacer" style="height:${AppState.filteredPackets.length*ROW_HEIGHT}px"></div>`;
  renderVisibleRows();
  els.tableBody.onscroll=debounce(renderVisibleRows,16);
  if(!_tableClickDelegated){
    _tableClickDelegated=true;
    // Lazy import features to avoid circular dependency
    let _showPacketDetail, _toggleBookmark, _showNotePopover;
    import('./features.js').then(mod => {
      _showPacketDetail = mod.showPacketDetail;
      _toggleBookmark = mod.toggleBookmark;
      _showNotePopover = mod.showNotePopover;
    });
    els.tableBody.addEventListener('click',e=>{
      const row=e.target.closest('.table-row');if(!row)return;
      const idx=parseInt(row.dataset.idx,10);if(isNaN(idx))return;
      const p=AppState.filteredPackets[idx];if(!p)return;
      if(e.target.closest('.col-star')){e.stopPropagation();if(_toggleBookmark)_toggleBookmark(p.number);return;}
      if(e.target.closest('.col-note')){e.stopPropagation();if(_showNotePopover)_showNotePopover(p.number,e);return;}
      if(e.shiftKey&&AppState.selectedPacketIdx>=0){
        AppState.diffPacketB=p;
        els.btnDiff.classList.remove('hidden');
        renderVisibleRows();
        return;
      }
      AppState.selectedPacketIdx=idx;AppState.diffPacketB=null;els.btnDiff.classList.add('hidden');
      if(_showPacketDetail)_showPacketDetail(p);renderVisibleRows();
    });
  }
}

const _rowPool=[];
let _prevStart=-1,_prevEnd=-1;
function _acquireRow(){
  if(_rowPool.length>0)return _rowPool.pop();
  const row=document.createElement('div');
  row.className='table-row';
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
  row.className='table-row';
  if(i===AppState.selectedPacketIdx)row.classList.add('selected');
  if(AppState.diffPacketB&&p.number===AppState.diffPacketB.number)row.classList.add('diff-selected');
  if(p.anomalies.length>0)row.classList.add('anomaly');
  if(AppState.bookmarks.has(p.number))row.classList.add('bookmarked');
  const customColor=evaluateColoringRules(p);
  const bgColor=customColor?hexToRGBA(customColor,0.15):hexToRGBA(protoColor(p.protocol),0.06);
  row.style.top=(i*ROW_HEIGHT)+'px';row.style.background=bgColor;
  row.dataset.idx=i;
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
export function renderVisibleRows(){
  const sb=els.tableBody;const scrollTop=sb.scrollTop;
  const visibleH=sb.clientHeight;const start=Math.max(0,Math.floor(scrollTop/ROW_HEIGHT)-BUFFER);
  const end=Math.min(AppState.filteredPackets.length,Math.ceil((scrollTop+visibleH)/ROW_HEIGHT)+BUFFER);
  const spacer=sb.querySelector('.table-spacer');
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
  existingRows.forEach(r=>_releaseRow(r));
  if(frag.childNodes.length){if(spacer)spacer.after(frag); else sb.appendChild(frag);}
  _prevStart=start;_prevEnd=end;
}

export function scrollToSelectedRow(){
  if(AppState.selectedPacketIdx<0)return;
  const top=AppState.selectedPacketIdx*ROW_HEIGHT;
  const sb=els.tableBody;
  if(top<sb.scrollTop||top>sb.scrollTop+sb.clientHeight-ROW_HEIGHT)sb.scrollTop=top-sb.clientHeight/2;
}
