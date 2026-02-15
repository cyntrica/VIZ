// modules/dom.js — DOM references, tooltip, error toast, modal close
'use strict';

import { $ } from './state.js';

export const els={
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
  btnIoC:$('btn-ioc'),iocModal:$('ioc-modal'),btnCloseIoC:$('btn-close-ioc'),
  iocInput:$('ioc-input'),btnIoCScan:$('btn-ioc-scan'),btnIoCClear:$('btn-ioc-clear'),
  iocResults:$('ioc-results'),iocMatchCount:$('ioc-match-count'),iocStatus:$('ioc-status'),
  btnAlerts:$('btn-alerts'),alertsModal:$('alerts-modal'),btnCloseAlerts:$('btn-close-alerts'),
  btnAlertsRun:$('btn-alerts-run'),alertRulesList:$('alert-rules-list'),btnAddAlertRule:$('btn-add-alert-rule'),
  alertResults:$('alert-results'),
  btnConnState:$('btn-connstate'),connstateModal:$('connstate-modal'),btnCloseConnState:$('btn-close-connstate'),
  connstateFilter:$('connstate-filter'),connstateContent:$('connstate-content'),
  btnHeatmapToggle:$('btn-heatmap-toggle'),
};

export function showTooltip(html,x,y){els.tooltip.innerHTML=html;els.tooltip.classList.remove('hidden');els.tooltip.style.left=Math.min(x+10,window.innerWidth-330)+'px';els.tooltip.style.top=Math.min(y+10,window.innerHeight-100)+'px';}
export function hideTooltip(){els.tooltip.classList.add('hidden');}

export function showError(userMsg, err) {
  console.error(userMsg, err);
  const toast = document.createElement('div');
  toast.className = 'error-toast';
  toast.textContent = userMsg;
  document.body.appendChild(toast);
  setTimeout(() => { toast.classList.add('fade-out'); setTimeout(() => toast.remove(), 400); }, 4000);
}

export function hideNotePopover(){els.notePopover.classList.add('hidden');}

export function closeAllModals(){
  [els.streamModal,els.conversationsModal,els.compareModal,els.geoipModal,els.shortcutsHelp,
   els.statsModal,els.extractionModal,els.latencyModal,els.sequenceModal,els.iographModal,
   els.diffModal,els.notesModal,els.coloringModal,els.iocModal,els.alertsModal,els.connstateModal].forEach(m=>{if(m)m.classList.add('hidden');});
  hideNotePopover();
}
