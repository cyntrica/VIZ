// modules/setup.js — Upload, event binding, keyboard, initialization
'use strict';

import { AppState, FILTER_FIELDS, debounce, escapeHTML, invalidateColoringCache } from './state.js';
import { els, showError, closeAllModals, hideNotePopover } from './dom.js';
import { renderAll, renderTimeline, renderPacketTable, renderVisibleRows, renderNetworkGraph, onFilterChange, loadStateFromURL } from './rendering.js';
import { showPacketDetail, closeDetailPane, followTCPStream, showConversations, toggleBookmark, exportCSV, exportJSON, screenshotPanel, toggleTheme, togglePanelFullscreen, showGeoIPMap, loadCompareFile, showProtocolStats, showExtractions, showLatency, showSequenceDiagram, renderSequenceSVG, showIOGraph, renderIOGraphSVG, showPacketDiff, showNotesModal, showNotePopover, saveAnnotation, deleteAnnotation, loadAnnotations, showIoCModal, scanIoCs, showAlertsModal, renderAlertRules, runAlertRules, showConnStateModal, renderConnState, showColoringModal, renderColoringRules } from './features.js';

// ===== Upload =====
const ALLOWED_EXTENSIONS=['.pcap','.pcapng','.cap'];
function isValidPcapFile(file){
  const name=(file.name||file).toString().toLowerCase();
  return ALLOWED_EXTENSIONS.some(ext=>name.endsWith(ext));
}
const isTauri=!!(window.__TAURI__);

async function openNativeFileDialog(){
  try{
    const dialog=window.__TAURI__.dialog;
    const invoke=window.__TAURI__.core.invoke;
    const result=await dialog.open({
      multiple:false,
      filters:[{name:'Packet Captures',extensions:['pcap','pcapng','cap']}]
    });
    if(!result)return;
    const filePath=result.path||result;
    const fileName=filePath.split('/').pop().split('\\').pop();
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

// ===== Filter Autocomplete =====
function setupFilterAutocomplete(){
  const fields=Object.keys(FILTER_FIELDS);
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
        if(AppState.filteredPackets[AppState.selectedPacketIdx])showPacketDetail(AppState.filteredPackets[AppState.selectedPacketIdx]);renderVisibleRows();break;
      case 'ArrowUp':
        e.preventDefault();if(!AppState.filteredPackets.length)break;
        AppState.selectedPacketIdx=Math.max(AppState.selectedPacketIdx-1,0);
        if(AppState.filteredPackets[AppState.selectedPacketIdx])showPacketDetail(AppState.filteredPackets[AppState.selectedPacketIdx]);renderVisibleRows();break;
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
        const p=document.getElementById(panelIds[parseInt(e.key)-1]);if(p)togglePanelFullscreen(p);break;
    }
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
  els.btnStats.addEventListener('click',showProtocolStats);
  els.btnExtractions.addEventListener('click',showExtractions);
  els.btnFlow.addEventListener('click',showSequenceDiagram);
  els.btnIOGraph.addEventListener('click',showIOGraph);
  els.btnLatency.addEventListener('click',showLatency);
  els.btnNotes.addEventListener('click',showNotesModal);
  els.btnColoring.addEventListener('click',showColoringModal);
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
  document.querySelectorAll('.layer-btn').forEach(btn=>{
    btn.addEventListener('click',()=>{
      document.querySelectorAll('.layer-btn').forEach(b=>b.classList.remove('active'));
      btn.classList.add('active');AppState.graphLayer=btn.dataset.layer;
      renderNetworkGraph();
    });
  });
  els.hostLimitSlider.addEventListener('input',()=>{
    els.hostLimitValue.textContent=els.hostLimitSlider.value;
  });
  els.hostLimitSlider.addEventListener('change',()=>{
    AppState.graphHostLimit=parseInt(els.hostLimitSlider.value,10);
    renderNetworkGraph();
  });
  document.querySelectorAll('.btn-expand').forEach(btn=>{btn.addEventListener('click',()=>togglePanelFullscreen(btn.closest('.panel')));});
  document.querySelectorAll('.btn-screenshot').forEach(btn=>{btn.addEventListener('click',()=>screenshotPanel(btn.closest('.panel')));});
  els.coloringProfile.addEventListener('change',()=>{AppState.coloringProfile=els.coloringProfile.value;invalidateColoringCache();renderColoringRules();renderVisibleRows();});
  els.btnAddRule.addEventListener('click',()=>{AppState.coloringRules.push({name:'New Rule',field:'protocol',operator:'==',value:'TCP',color:'#4fc3f7',enabled:true});renderColoringRules();});
  els.noteSave.addEventListener('click',saveAnnotation);
  els.noteDelete.addEventListener('click',deleteAnnotation);
  els.noteCancel.addEventListener('click',hideNotePopover);
  document.querySelectorAll('.modal').forEach(m=>{m.addEventListener('click',e=>{if(e.target===m)m.classList.add('hidden');});});
}

// ===== Resize =====
function setupResize(){window.addEventListener('resize',debounce(renderAll,250));}

// ===== Init =====
export function init(){
  setupUpload();
  setupTableControls();
  setupButtons();
  setupKeyboard();
  setupFilterAutocomplete();
  setupResize();
  loadStateFromURL();
}
