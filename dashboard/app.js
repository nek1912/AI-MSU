/* ==========================================================================
   Insider Threat Detection dashboard — application logic
   Plain ES5/ES6 JavaScript. No libraries, no build step, runs from file://.

   Honesty rules enforced throughout:
   - Verified notebook figures are constants labelled as such.
   - Recomputed values only appear after a real CSV import.
   - Zero denominators render as "Not available", never NaN/Infinity.
   - Flags are "flagged user-days", never "confirmed attacks".
   ========================================================================== */
'use strict';

/* -------------------------------------------------------------------------
   1. Verified constants (from saved notebook outputs)
   ------------------------------------------------------------------------- */

var VERIFIED = {
  scenarioIncidents: [30, 30, 10],                 // notebook 07 group-by
  scenarioDetected: [13, 8, 10],                   // notebook 07 (13/30, 8/30, 10/10)
  records: [                                       // notebook 01/04 valid rows
    { label: 'http', value: 28434423 },
    { label: 'email', value: 2629979 },
    { label: 'logon', value: 854859 },
    { label: 'file', value: 445581 },
    { label: 'device', value: 405380 }
  ],
  normalUserDays: 495990,                          // notebook 06
  flaggedUserDays: 5010,                           // notebook 06
  totalUserDays: 501000,
  coverage: { startMs: Date.UTC(2010, 0, 2), endMs: Date.UTC(2011, 4, 17), days: 501 },
  thresholds: [                                    // notebook 08
    { pct: 99, threshold: 0.0000, flagged: 5010, alertRate: 1, recall: 4.44 },
    { pct: 98, threshold: -0.0530, flagged: 10020, alertRate: 2, recall: 9.51 },
    { pct: 95, threshold: -0.1043, flagged: 25050, alertRate: 5, recall: 19.29 }
  ]
};

var MODEL_COLS = [
  'logon_event_count', 'logon_after_hours',
  'device_event_count', 'device_after_hours',
  'file_event_count', 'file_after_hours',
  'email_event_count', 'email_after_hours',
  'email_size', 'email_attachments',
  'http_event_count', 'http_after_hours'
];

var COUNT_COLS = ['logon_event_count', 'device_event_count', 'file_event_count', 'email_event_count', 'http_event_count'];

/* Ground truth: r4.2 rows of data/raw/answers/insiders.csv (70 incidents).
   Embedded exactly as recorded in the source file. */
var GROUND_TRUTH_CSV = [
'dataset,scenario,details,user,start,end',
'4.2,1,r4.2-1-AAM0658.csv,AAM0658,10/23/2010 01:34:19,10/29/2010 05:23:28',
'4.2,1,r4.2-1-AJR0932.csv,AJR0932,09/10/2010 19:12:01,09/18/2010 02:02:51',
'4.2,1,r4.2-1-BDV0168.csv,BDV0168,07/30/2010 19:56:44,08/10/2010 05:16:41',
'4.2,1,r4.2-1-BIH0745.csv,BIH0745,07/13/2010 20:15:23,07/13/2010 21:20:44',
'4.2,1,r4.2-1-BLS0678.csv,BLS0678,09/21/2010 01:16:22,09/30/2010 04:48:19',
'4.2,1,r4.2-1-BTL0226.csv,BTL0226,10/06/2010 22:25:52,10/14/2010 06:43:29',
'4.2,1,r4.2-1-CAH0936.csv,CAH0936,08/11/2010 04:00:08,08/12/2010 23:56:19',
'4.2,1,r4.2-1-DCH0843.csv,DCH0843,02/04/2011 07:08:00,02/04/2011 07:36:05',
'4.2,1,r4.2-1-EHB0824.csv,EHB0824,07/22/2010 21:48:43,07/29/2010 01:08:41',
'4.2,1,r4.2-1-EHD0584.csv,EHD0584,10/02/2010 03:46:16,10/08/2010 22:26:26',
'4.2,1,r4.2-1-FMG0527.csv,FMG0527,01/05/2011 21:53:29,01/12/2011 01:15:35',
'4.2,1,r4.2-1-FTM0406.csv,FTM0406,11/25/2010 06:35:11,12/02/2010 00:35:19',
'4.2,1,r4.2-1-GHL0460.csv,GHL0460,11/09/2010 06:28:40,11/09/2010 07:08:45',
'4.2,1,r4.2-1-HJB0742.csv,HJB0742,11/19/2010 05:53:16,11/25/2010 04:51:16',
'4.2,1,r4.2-1-JMB0308.csv,JMB0308,07/14/2010 00:56:15,07/21/2010 01:46:49',
'4.2,1,r4.2-1-JRG0207.csv,JRG0207,01/19/2011 20:25:05,01/26/2011 02:38:27',
'4.2,1,r4.2-1-KLH0596.csv,KLH0596,02/12/2011 07:11:50,02/12/2011 07:33:24',
'4.2,1,r4.2-1-KPC0073.csv,KPC0073,07/07/2010 20:05:29,07/15/2010 03:08:16',
'4.2,1,r4.2-1-LJR0523.csv,LJR0523,07/31/2010 07:43:15,08/11/2010 04:28:49',
'4.2,1,r4.2-1-LQC0479.csv,LQC0479,09/14/2010 19:46:17,09/22/2010 01:08:02',
'4.2,1,r4.2-1-MAR0955.csv,MAR0955,02/08/2011 05:55:53,02/11/2011 06:29:08',
'4.2,1,r4.2-1-MAS0025.csv,MAS0025,09/29/2010 01:39:20,09/30/2010 22:39:20',
'4.2,1,r4.2-1-MCF0600.csv,MCF0600,09/20/2010 23:52:19,09/23/2010 02:00:46',
'4.2,1,r4.2-1-MYD0978.csv,MYD0978,12/13/2010 20:30:07,12/18/2010 07:02:34',
'4.2,1,r4.2-1-PPF0435.csv,PPF0435,02/09/2011 03:00:27,02/09/2011 06:46:27',
'4.2,1,r4.2-1-RAB0589.csv,RAB0589,09/13/2010 23:18:53,09/23/2010 07:30:03',
'4.2,1,r4.2-1-RGG0064.csv,RGG0064,10/20/2010 20:12:23,10/27/2010 03:03:52',
'4.2,1,r4.2-1-RKD0604.csv,RKD0604,07/13/2010 20:04:53,07/20/2010 03:36:55',
'4.2,1,r4.2-1-TAP0551.csv,TAP0551,10/23/2010 02:55:51,10/29/2010 05:56:18',
'4.2,1,r4.2-1-WDD0366.csv,WDD0366,02/24/2011 19:49:41,03/03/2011 01:01:02',
'4.2,2,r4.2-2-AAF0535.csv,AAF0535,06/28/2010 08:51:08,08/20/2010 15:38:04',
'4.2,2,r4.2-2-ABC0174.csv,ABC0174,10/27/2010 14:11:03,12/24/2010 15:53:02',
'4.2,2,r4.2-2-AKR0057.csv,AKR0057,10/04/2010 08:48:26,11/29/2010 18:48:10',
'4.2,2,r4.2-2-CCL0068.csv,CCL0068,12/27/2010 09:20:16,02/21/2011 08:25:17',
'4.2,2,r4.2-2-CEJ0109.csv,CEJ0109,02/07/2011 11:16:58,04/01/2011 17:23:43',
'4.2,2,r4.2-2-CQW0652.csv,CQW0652,02/18/2011 09:22:22,04/14/2011 20:58:56',
'4.2,2,r4.2-2-DIB0285.csv,DIB0285,07/26/2010 16:23:45,09/13/2010 17:13:29',
'4.2,2,r4.2-2-DRR0162.csv,DRR0162,11/11/2010 07:01:17,01/04/2011 15:43:53',
'4.2,2,r4.2-2-EDB0714.csv,EDB0714,10/18/2010 10:58:12,12/14/2010 14:17:02',
'4.2,2,r4.2-2-EGD0132.csv,EGD0132,08/02/2010 10:01:20,09/28/2010 17:24:42',
'4.2,2,r4.2-2-FSC0601.csv,FSC0601,01/18/2011 08:42:08,03/17/2011 16:45:04',
'4.2,2,r4.2-2-HBO0413.csv,HBO0413,02/14/2011 08:15:24,04/08/2011 15:25:10',
'4.2,2,r4.2-2-HXL0968.csv,HXL0968,08/31/2010 07:51:41,10/28/2010 16:06:01',
'4.2,2,r4.2-2-IJM0776.csv,IJM0776,07/06/2010 08:33:06,09/01/2010 14:10:31',
'4.2,2,r4.2-2-IKR0401.csv,IKR0401,12/27/2010 08:57:14,02/17/2011 18:21:57',
'4.2,2,r4.2-2-IUB0565.csv,IUB0565,10/06/2010 09:20:43,11/30/2010 17:49:20',
'4.2,2,r4.2-2-JJM0203.csv,JJM0203,09/02/2010 07:40:34,10/19/2010 17:04:21',
'4.2,2,r4.2-2-KRL0501.csv,KRL0501,11/22/2010 09:38:30,01/19/2011 17:06:28',
'4.2,2,r4.2-2-LCC0819.csv,LCC0819,06/16/2010 11:39:58,08/10/2010 18:31:17',
'4.2,2,r4.2-2-MDH0580.csv,MDH0580,01/04/2011 09:13:35,03/03/2011 11:40:25',
'4.2,2,r4.2-2-MOS0047.csv,MOS0047,07/15/2010 07:23:37,09/10/2010 19:34:22',
'4.2,2,r4.2-2-NWT0098.csv,NWT0098,02/07/2011 16:40:17,04/05/2011 14:00:24',
'4.2,2,r4.2-2-PNL0301.csv,PNL0301,06/14/2010 09:25:31,08/03/2010 16:54:30',
'4.2,2,r4.2-2-PSF0133.csv,PSF0133,08/02/2010 10:46:58,09/29/2010 16:23:30',
'4.2,2,r4.2-2-RAR0725.csv,RAR0725,07/06/2010 08:07:33,08/19/2010 09:58:36',
'4.2,2,r4.2-2-RHL0992.csv,RHL0992,07/13/2010 09:46:08,09/09/2010 20:45:13',
'4.2,2,r4.2-2-RMW0542.csv,RMW0542,06/21/2010 09:04:43,08/18/2010 17:37:38',
'4.2,2,r4.2-2-TNM0961.csv,TNM0961,10/15/2010 07:04:48,12/09/2010 16:05:04',
'4.2,2,r4.2-2-VSS0154.csv,VSS0154,09/07/2010 09:49:28,10/29/2010 16:40:54',
'4.2,2,r4.2-2-XHW0498.csv,XHW0498,08/09/2010 12:48:49,10/06/2010 16:05:32',
'4.2,3,r4.2-3-BBS0039.csv,BBS0039,08/12/2010 10:24:05,08/13/2010 19:08:58',
'4.2,3,r4.2-3-BSS0369.csv,BSS0369,09/30/2010 13:31:56,10/01/2010 19:48:03',
'4.2,3,r4.2-3-CCA0046.csv,CCA0046,10/14/2010 08:23:18,10/15/2010 20:01:27',
'4.2,3,r4.2-3-CSC0217.csv,CSC0217,06/10/2010 07:54:10,06/11/2010 17:42:48',
'4.2,3,r4.2-3-GTD0219.csv,GTD0219,06/17/2010 09:06:37,06/18/2010 17:50:42',
'4.2,3,r4.2-3-JGT0221.csv,JGT0221,07/15/2010 09:43:23,07/16/2010 19:33:29',
'4.2,3,r4.2-3-JLM0364.csv,JLM0364,04/28/2011 09:50:07,04/29/2011 20:04:27',
'4.2,3,r4.2-3-JTM0223.csv,JTM0223,07/22/2010 07:27:46,07/23/2010 18:01:20',
'4.2,3,r4.2-3-MPM0220.csv,MPM0220,11/04/2010 08:59:55,11/05/2010 19:29:06',
'4.2,3,r4.2-3-MSO0222.csv,MSO0222,12/09/2010 08:36:36,12/10/2010 17:39:36'
].join('\n');

/* -------------------------------------------------------------------------
   2. Application state
   ------------------------------------------------------------------------- */

var state = {
  predictions: null,   // {n, dayMs, score, flag, inWin, name, flaggedCount}
  features: null,      // {n, cols:{...Float64Array}, colNames, dayIdx, dayList, weekday, totals}
  incidents: [],       // {user, scenario, details, startMs, endMs, source}
  gtSource: 'embedded',
  audit: null,         // {rows:[{file, missing, dup, original, remaining}]}
  scenarioMode: 'count',
  recordsScale: 'linear',
  scenperfMode: 'percent',
  afterhoursMode: 'count',
  registerFilter: 'all',
  missedScenario: 'all',
  missedStatus: 'all'
};

var MODEL_COLS_LOWER = MODEL_COLS.map(function (c) { return c.toLowerCase(); });

/* -------------------------------------------------------------------------
   3. Small utilities
   ------------------------------------------------------------------------- */

function $(sel, root) { return (root || document).querySelector(sel); }
function $all(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

function fmtInt(n) {
  if (n === null || n === undefined || !isFinite(n)) return 'Not available';
  return Number(n).toLocaleString('en-US');
}

/* Safe percentage: zero denominators return null, callers render "Not available". */
function pct(num, den, digits) {
  if (!isFinite(num) || !isFinite(den) || den <= 0) return null;
  return (num / den) * 100;
}

function fmtPct(num, den, digits) {
  var p = pct(num, den, digits);
  if (p === null) return 'Not available';
  var d = (digits === undefined) ? 2 : digits;
  return p.toFixed(d) + '%';
}

function fmtNum(n, digits) {
  if (n === null || n === undefined || !isFinite(n)) return 'Not available';
  return Number(n).toFixed(digits === undefined ? 2 : digits);
}

/* Parse "M/D/YYYY H:MM:SS" or "YYYY-MM-DD[ H:MM:SS]" into epoch ms. */
function parseDateTime(str) {
  if (!str) return NaN;
  var s = String(str).trim();
  var m = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:[ ,]+(\d{1,2}):(\d{2})(?::(\d{2}))?)?/);
  if (m) {
    return Date.UTC(+m[3], +m[1] - 1, +m[2], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
  }
  m = s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})(?:[T ]+(\d{1,2}):(\d{2})(?::(\d{2}))?)?/);
  if (m) {
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0));
  }
  return NaN;
}

function dayKey(ms) { return Math.floor(ms / 86400000); }

function fmtDay(ms) {
  if (!isFinite(ms)) return 'Not available';
  var d = new Date(ms);
  var mm = String(d.getUTCMonth() + 1);
  var dd = String(d.getUTCDate());
  return d.getUTCFullYear() + '-' + (mm.length < 2 ? '0' + mm : mm) + '-' + (dd.length < 2 ? '0' + dd : dd);
}

function isTruthyFlag(v) {
  var s = String(v).trim().toLowerCase();
  return s === 'true' || s === '1' || s === 'yes' || s === 't';
}

/* -------------------------------------------------------------------------
   4. CSV parsing (quotes, escaped quotes, newlines inside quotes)
   ------------------------------------------------------------------------- */

function parseCSV(text) {
  var rows = [];
  var row = [];
  var field = '';
  var inQuotes = false;
  var i = 0;
  var len = text.length;
  if (text.charCodeAt(0) === 0xFEFF) { i = 1; } // strip BOM

  while (i < len) {
    var c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
        inQuotes = false; i++; continue;
      }
      field += c; i++; continue;
    }
    if (c === '"') { inQuotes = true; i++; continue; }
    if (c === ',') { row.push(field); field = ''; i++; continue; }
    if (c === '\r') { i++; continue; }
    if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
    field += c; i++;
  }
  if (field.length > 0 || row.length > 0) { row.push(field); rows.push(row); }

  // drop trailing fully-empty lines
  while (rows.length && rows[rows.length - 1].length === 1 && rows[rows.length - 1][0].trim() === '') {
    rows.pop();
  }
  if (rows.length === 0) return { header: [], rows: [] };

  var header = rows[0].map(function (h) { return h.trim(); });
  var body = rows.slice(1).filter(function (r) {
    return !(r.length === 1 && r[0].trim() === '');
  });
  return { header: header, rows: body };
}

function columnIndex(header, name) {
  var target = name.toLowerCase();
  for (var i = 0; i < header.length; i++) {
    if (header[i].toLowerCase() === target) return i;
  }
  return -1;
}

function readFileAsText(file, cb) {
  var reader = new FileReader();
  reader.onload = function () { cb(null, String(reader.result)); };
  reader.onerror = function () { cb(new Error('The file could not be read.')); };
  reader.readAsText(file);
}

/* Line index for large quote-free CSVs: avoids materialising every row at once.
   Returns an array of character offsets, one per line. */
function indexLines(text) {
  var offsets = [];
  var i = text.charCodeAt(0) === 0xFEFF ? 1 : 0;
  var len = text.length;
  while (i < len) {
    offsets.push(i);
    var nl = text.indexOf('\n', i);
    if (nl < 0) break;
    i = nl + 1;
  }
  if (offsets.length) {
    var last = offsets[offsets.length - 1];
    if (text.slice(last).trim() === '') offsets.pop();
  }
  return offsets;
}

function lineAt(text, offsets, k) {
  var start = offsets[k];
  var end = (k + 1 < offsets.length) ? offsets[k + 1] : text.length;
  var s = text.slice(start, end);
  var lastChar = s.charCodeAt(s.length - 1);
  if (lastChar === 10) { s = s.slice(0, -1); lastChar = s.charCodeAt(s.length - 1); }
  if (lastChar === 13) { s = s.slice(0, -1); }
  return s;
}

function setStatus(id, message, kind) {
  var el = document.getElementById(id);
  if (!el) return;
  el.textContent = message;
  el.classList.remove('is-ok', 'is-error');
  if (kind) el.classList.add(kind);
}

/* -------------------------------------------------------------------------
   5. Navigation
   ------------------------------------------------------------------------- */

var SECTION_NAMES = {
  overview: 'Overview',
  dataset: 'Dataset explorer',
  cleaning: 'Data cleaning',
  eda: 'Exploratory data analysis',
  features: 'Feature engineering',
  model: 'Model explorer',
  evaluation: 'Evaluation & confusion matrix',
  threshold: 'Threshold analysis',
  limitations: 'Limitations & future work',
  import: 'Data import'
};

function showSection(id, pushHash) {
  if (!SECTION_NAMES[id]) id = 'overview';
  $all('.panel-section').forEach(function (sec) {
    var on = sec.id === id;
    sec.hidden = !on;
    sec.classList.toggle('is-visible', on);
  });
  $all('.rail-link').forEach(function (link) {
    var on = link.getAttribute('data-section') === id;
    link.classList.toggle('is-active', on);
    if (on) { link.setAttribute('aria-current', 'page'); }
    else { link.removeAttribute('aria-current'); }
  });
  var nameEl = document.getElementById('topbar-section-name');
  if (nameEl) nameEl.textContent = SECTION_NAMES[id];
  if (pushHash && location.hash !== '#' + id) {
    history.replaceState(null, '', '#' + id);
  }
  redrawActiveCharts();
  window.scrollTo({ top: 0, behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
}

function prefersReducedMotion() {
  return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

function initNav() {
  $all('.rail-link').forEach(function (link) {
    link.addEventListener('click', function (e) {
      e.preventDefault();
      showSection(link.getAttribute('data-section'), true);
    });
  });
  window.addEventListener('hashchange', function () {
    showSection((location.hash || '#overview').slice(1), false);
  });
  var initial = (location.hash || '#overview').slice(1);
  showSection(initial, false);
}

/* -------------------------------------------------------------------------
   6. Chart engine — canvas, HiDPI, tooltips
   ------------------------------------------------------------------------- */

var tooltipEl = null;
var chartHits = {}; // canvasId -> [{x, y, w, h, label, value}]

var PALETTE = {
  ink: '#182831',
  teal: '#477B78',
  tealLight: 'rgba(71,123,120,0.35)',
  rust: '#C66B48',
  rustDark: '#A8542F',
  slate: '#69777D',
  rule: '#D8DEDA',
  ruleStrong: '#BFC8C3',
  paper: '#FBFBF8'
};

function setupCanvas(canvas, cssHeight) {
  if (!canvas) return null;
  var dpr = window.devicePixelRatio || 1;
  var cssW = canvas.parentElement ? canvas.parentElement.clientWidth - 24 : 600;
  if (cssW < 200) cssW = 200;
  var h = cssHeight || parseInt(canvas.getAttribute('height'), 10) || 220;
  canvas.style.width = '100%';
  canvas.style.height = h + 'px';
  canvas.width = Math.round(cssW * dpr);
  canvas.height = Math.round(h * dpr);
  var ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, cssW, h);
  chartHits[canvas.id] = [];
  return { ctx: ctx, w: cssW, h: h };
}

function registerHit(canvas, x, y, w, h, label, value) {
  if (!chartHits[canvas.id]) chartHits[canvas.id] = [];
  chartHits[canvas.id].push({ x: x, y: y, w: w, h: h, label: label, value: value });
}

function drawAxisText(ctx, text, x, y, align, size) {
  ctx.fillStyle = PALETTE.slate;
  ctx.font = (size || 10.5) + 'px ' + '"SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace';
  ctx.textAlign = align || 'left';
  ctx.textBaseline = 'middle';
  ctx.fillText(text, x, y);
}

/* Round a raw maximum up to a friendly gridline step (1 / 2 / 5 × 10^k). */
function niceAxis(max) {
  if (!isFinite(max) || max <= 0) return { max: 1, step: 0.25, count: 4 };
  var rawStep = max / 4;
  var exp = Math.floor(Math.log(rawStep) / Math.LN10);
  var base = Math.pow(10, exp);
  var f = rawStep / base;
  var mult = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  var step = mult * base;
  var top = Math.ceil(max / step) * step;
  var count = Math.round(top / step);
  return { max: top, step: step, count: count };
}

function drawEmpty(canvasId, message) {
  var canvas = document.getElementById(canvasId);
  if (!canvas) return;
  var s = setupCanvas(canvas);
  if (!s) return;
  var ctx = s.ctx;
  ctx.fillStyle = PALETTE.slate;
  ctx.font = '12px ' + '-apple-system, "Segoe UI", Roboto, Arial, sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(message, s.w / 2, s.h / 2);
}

/* Bar chart (single series). opts: labels, values, colors, valueFmt, unit, rotate */
function drawBarChart(canvasId, opts) {
  var canvas = document.getElementById(canvasId);
  if (!canvas) return;
  var s = setupCanvas(canvas, opts.height);
  if (!s) return;
  var ctx = s.ctx;
  var labels = opts.labels || [];
  var values = opts.values || [];
  var n = values.length;
  if (!n) { drawEmpty(canvasId, 'No data available'); return; }

  var padL = opts.padL || 62, padR = 14, padT = 16, padB = opts.rotate ? 54 : 34;
  var plotW = s.w - padL - padR;
  var plotH = s.h - padT - padB;

  var max = 0;
  for (var i = 0; i < n; i++) { if (isFinite(values[i]) && values[i] > max) max = values[i]; }
  var axis = niceAxis(max);
  max = axis.max;

  // gridlines
  ctx.strokeStyle = PALETTE.rule;
  ctx.lineWidth = 1;
  var steps = axis.count;
  for (var g = 0; g <= steps; g++) {
    var gy = Math.round(padT + plotH - (plotH * g / steps)) + 0.5;
    ctx.beginPath(); ctx.moveTo(padL, gy); ctx.lineTo(padL + plotW, gy); ctx.stroke();
    var v = max * g / steps;
    drawAxisText(ctx, opts.axisFmt ? opts.axisFmt(v) : fmtInt(Math.round(v)), padL - 8, gy, 'right', 10);
  }

  var slot = plotW / n;
  var barW = Math.min(opts.barMaxWidth || 64, slot * 0.62);
  for (var b = 0; b < n; b++) {
    var val = isFinite(values[b]) ? values[b] : 0;
    var bh = (val / max) * plotH;
    if (val > 0 && bh < 1.5) bh = 1.5;
    var x = padL + slot * b + (slot - barW) / 2;
    var y = padT + plotH - bh;
    ctx.fillStyle = (opts.colors && opts.colors[b]) || opts.color || PALETTE.teal;
    ctx.fillRect(x, y, barW, bh);

    // value on top
    ctx.fillStyle = PALETTE.ink;
    ctx.font = '600 11px ' + '"SFMono-Regular", Consolas, monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'bottom';
    ctx.fillText(opts.valueFmt ? opts.valueFmt(values[b]) : fmtInt(values[b]), x + barW / 2, y - 5);

    // label
    ctx.save();
    if (opts.rotate) {
      ctx.translate(padL + slot * b + slot / 2, padT + plotH + 10);
      ctx.rotate(-Math.PI / 4);
      drawAxisText(ctx, labels[b], 0, 0, 'left', 10.5);
    } else {
      drawAxisText(ctx, labels[b], padL + slot * b + slot / 2, padT + plotH + 16, 'center', 10.5);
    }
    ctx.restore();

    registerHit(canvas, padL + slot * b, padT, slot, plotH, labels[b],
      (opts.valueFmt ? opts.valueFmt(values[b]) : fmtInt(values[b])));
  }

  // baseline
  ctx.strokeStyle = PALETTE.ruleStrong;
  ctx.beginPath();
  ctx.moveTo(padL, padT + plotH + 0.5);
  ctx.lineTo(padL + plotW, padT + plotH + 0.5);
  ctx.stroke();
}

/* Grouped bar chart. series: [{name, values, color}], labels */
function drawGroupedBarChart(canvasId, opts) {
  var canvas = document.getElementById(canvasId);
  if (!canvas) return;
  var s = setupCanvas(canvas, opts.height);
  if (!s) return;
  var ctx = s.ctx;
  var labels = opts.labels || [];
  var series = opts.series || [];
  var n = labels.length;
  if (!n || !series.length) { drawEmpty(canvasId, 'No data available'); return; }

  var padL = opts.padL || 66, padR = 14, padT = 16, padB = opts.rotate ? 58 : 44;
  var plotW = s.w - padL - padR;
  var plotH = s.h - padT - padB;

  var max = 0;
  series.forEach(function (se) {
    se.values.forEach(function (v) { if (isFinite(v) && v > max) max = v; });
  });
  var axis = niceAxis(max);
  max = axis.max;

  ctx.strokeStyle = PALETTE.rule;
  for (var g = 0; g <= axis.count; g++) {
    var gy = Math.round(padT + plotH - (plotH * g / axis.count)) + 0.5;
    ctx.beginPath(); ctx.moveTo(padL, gy); ctx.lineTo(padL + plotW, gy); ctx.stroke();
    drawAxisText(ctx, opts.axisFmt ? opts.axisFmt(max * g / axis.count) : fmtInt(Math.round(max * g / axis.count)), padL - 8, gy, 'right', 10);
  }

  var slot = plotW / n;
  var groupW = slot * 0.7;
  var barW = groupW / series.length;

  for (var i = 0; i < n; i++) {
    for (var si = 0; si < series.length; si++) {
      var val = isFinite(series[si].values[i]) ? series[si].values[i] : 0;
      var bh = (val / max) * plotH;
      if (val > 0 && bh < 1.5) bh = 1.5;
      var x = padL + slot * i + (slot - groupW) / 2 + barW * si;
      var y = padT + plotH - bh;
      ctx.fillStyle = series[si].color || PALETTE.teal;
      ctx.fillRect(x, y, barW - 2, bh);
      registerHit(canvas, x, y, barW - 2, Math.max(bh, 10),
        labels[i] + ' · ' + series[si].name,
        opts.valueFmt ? opts.valueFmt(val) : fmtInt(val));
    }
    ctx.save();
    if (opts.rotate) {
      ctx.translate(padL + slot * i + slot / 2, padT + plotH + 10);
      ctx.rotate(-Math.PI / 4);
      drawAxisText(ctx, labels[i], 0, 0, 'left', 10.5);
    } else {
      drawAxisText(ctx, labels[i], padL + slot * i + slot / 2, padT + plotH + 16, 'center', 10.5);
    }
    ctx.restore();
  }

  // legend
  var lx = padL;
  series.forEach(function (se) {
    ctx.fillStyle = se.color || PALETTE.teal;
    ctx.fillRect(lx, 4, 9, 9);
    drawAxisText(ctx, se.name, lx + 13, 9, 'left', 10.5);
    lx += 13 + ctx.measureText(se.name).width + 18;
  });

  ctx.strokeStyle = PALETTE.ruleStrong;
  ctx.beginPath();
  ctx.moveTo(padL, padT + plotH + 0.5);
  ctx.lineTo(padL + plotW, padT + plotH + 0.5);
  ctx.stroke();
}

/* Histogram. opts: values (array), bins, unit label */
function drawHistogram(canvasId, values, opts) {
  opts = opts || {};
  var canvas = document.getElementById(canvasId);
  if (!canvas) return;
  var s = setupCanvas(canvas, opts.height);
  if (!s) return;
  var ctx = s.ctx;

  if (!values || values.length === 0) { drawEmpty(canvasId, 'No data available'); return; }

  var sorted = Array.prototype.slice.call(values).filter(isFinite).sort(function (a, b) { return a - b; });
  if (!sorted.length) { drawEmpty(canvasId, 'No numeric values found'); return; }

  var min = sorted[0];
  var max = sorted[sorted.length - 1];
  var capIdx = Math.min(sorted.length - 1, Math.floor(sorted.length * 0.995));
  var cap = sorted[capIdx];
  if (cap <= min) cap = max;
  var bins = opts.bins || 30;
  var counts = new Array(bins).fill(0);
  var overflow = 0;
  for (var i = 0; i < sorted.length; i++) {
    var v = sorted[i];
    if (v > cap) { overflow++; continue; }
    var bi = Math.floor(((v - min) / (cap - min || 1)) * bins);
    if (bi >= bins) bi = bins - 1;
    if (bi < 0) bi = 0;
    counts[bi]++;
  }

  drawBarChart(canvasId, {
    labels: counts.map(function (_, idx) {
      var lo = min + (cap - min) * idx / bins;
      return opts.tickFmt ? opts.tickFmt(lo) : String(Math.round(lo));
    }),
    values: counts,
    color: opts.color || PALETTE.teal,
    height: opts.height,
    padL: 54,
    rotate: true,
    valueFmt: function (v) { return fmtInt(v); },
    axisFmt: function (v) { return fmtInt(Math.round(v)); }
  });

  if (overflow > 0 && opts.noteId) {
    var note = document.getElementById(opts.noteId);
    if (note) {
      note.textContent = fmtPct(overflow, sorted.length, 1) +
        ' of values (' + fmtInt(overflow) + ' of ' + fmtInt(sorted.length) +
        ') exceed the ' + fmtInt(cap) + ' cut-off and are grouped beyond the last bin. Range shown: ' +
        fmtNum(min, 0) + ' to ' + fmtNum(cap, 0) + '.';
    }
  } else if (opts.noteId) {
    var note2 = document.getElementById(opts.noteId);
    if (note2) {
      note2.textContent = fmtInt(sorted.length) + ' user-day values. Range shown: ' +
        fmtNum(min, 0) + ' to ' + fmtNum(cap, 0) + '.';
    }
  }
}

/* Simple line chart. points: [{x, y}] with numeric x/y; xLabels: fn(value)->text */
function drawLineChart(canvasId, opts) {
  var canvas = document.getElementById(canvasId);
  if (!canvas) return;
  var s = setupCanvas(canvas, opts.height);
  if (!s) return;
  var ctx = s.ctx;
  var pts = opts.points || [];
  if (pts.length < 2) { drawEmpty(canvasId, 'Not enough data to draw a line'); return; }

  var padL = 58, padR = 16, padT = 16, padB = 36;
  var plotW = s.w - padL - padR;
  var plotH = s.h - padT - padB;

  var xs = pts.map(function (p) { return p.x; });
  var ys = pts.map(function (p) { return p.y; });
  var xMin = Math.min.apply(null, xs), xMax = Math.max.apply(null, xs);
  var yMin = Math.min(0, Math.min.apply(null, ys));
  var yMax = Math.max.apply(null, ys);
  if (yMax <= yMin) yMax = yMin + 1;

  function X(v) { return padL + ((v - xMin) / ((xMax - xMin) || 1)) * plotW; }
  function Y(v) { return padT + plotH - ((v - yMin) / ((yMax - yMin) || 1)) * plotH; }

  ctx.strokeStyle = PALETTE.rule;
  for (var g = 0; g <= 4; g++) {
    var gv = yMin + (yMax - yMin) * g / 4;
    var gy = Math.round(Y(gv)) + 0.5;
    ctx.beginPath(); ctx.moveTo(padL, gy); ctx.lineTo(padL + plotW, gy); ctx.stroke();
    drawAxisText(ctx, opts.yFmt ? opts.yFmt(gv) : fmtInt(Math.round(gv)), padL - 8, gy, 'right', 10);
  }

  // area
  ctx.beginPath();
  ctx.moveTo(X(pts[0].x), Y(pts[0].y));
  pts.forEach(function (p) { ctx.lineTo(X(p.x), Y(p.y)); });
  ctx.lineTo(X(pts[pts.length - 1].x), padT + plotH);
  ctx.lineTo(X(pts[0].x), padT + plotH);
  ctx.closePath();
  ctx.fillStyle = 'rgba(71,123,120,0.12)';
  ctx.fill();

  // line
  ctx.beginPath();
  pts.forEach(function (p, i) {
    if (i === 0) ctx.moveTo(X(p.x), Y(p.y)); else ctx.lineTo(X(p.x), Y(p.y));
  });
  ctx.strokeStyle = opts.color || PALETTE.teal;
  ctx.lineWidth = 1.6;
  ctx.stroke();
  ctx.lineWidth = 1;

  // points + x labels + hits
  var xLabelEvery = Math.max(1, Math.floor(pts.length / 6));
  pts.forEach(function (p, i) {
    var px = X(p.x), py = Y(p.y);
    if (opts.pointsVisible) {
      ctx.fillStyle = opts.pointColor || PALETTE.rust;
      ctx.beginPath(); ctx.arc(px, py, 3.5, 0, Math.PI * 2); ctx.fill();
      ctx.fillStyle = PALETTE.ink;
      ctx.font = '600 11px "SFMono-Regular", Consolas, monospace';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'bottom';
      ctx.fillText(opts.yFmt ? opts.yFmt(p.y) : fmtInt(p.y), px, py - 8);
    }
    if (i % xLabelEvery === 0 || i === pts.length - 1) {
      var align = 'center';
      if (i === 0) align = 'left';
      else if (i === pts.length - 1) align = 'right';
      drawAxisText(ctx, opts.xFmt ? opts.xFmt(p.x) : String(p.x), px, padT + plotH + 16, align, 10);
    }
    registerHit(canvas, px - 6, padT, 12, plotH, opts.labelFn ? opts.labelFn(p) : String(p.x),
      opts.yFmt ? opts.yFmt(p.y) : fmtInt(p.y));
  });

  if (opts.yLabel) {
    ctx.save();
    ctx.translate(12, padT + plotH / 2);
    ctx.rotate(-Math.PI / 2);
    drawAxisText(ctx, opts.yLabel, 0, 0, 'center', 10);
    ctx.restore();
  }

  ctx.strokeStyle = PALETTE.ruleStrong;
  ctx.beginPath();
  ctx.moveTo(padL, padT + plotH + 0.5);
  ctx.lineTo(padL + plotW, padT + plotH + 0.5);
  ctx.stroke();
}

/* Horizontal box plot. rows: [{label, p5, p25, p50, p75, p95}] on log1p scale */
function drawBoxPlot(canvasId, rows, opts) {
  opts = opts || {};
  var canvas = document.getElementById(canvasId);
  if (!canvas) return;
  var s = setupCanvas(canvas, Math.max(300, rows.length * 28 + 60));
  if (!s) return;
  var ctx = s.ctx;
  if (!rows.length) { drawEmpty(canvasId, 'No data available'); return; }

  function log1p(v) { return Math.log(1 + Math.max(0, v)); }

  var maxVal = 0;
  rows.forEach(function (r) { maxVal = Math.max(maxVal, r.p95 || 0, r.p50 || 0); });
  var maxLog = log1p(maxVal) || 1;

  var padL = 168, padR = 24, padT = 26, padB = 34;
  var plotW = s.w - padL - padR;
  var plotH = s.h - padT - padB;
  var rowH = plotH / rows.length;

  function X(v) { return padL + (log1p(v) / maxLog) * plotW; }

  // gridlines at round values
  var ticks = [0, 1, 3, 10, 30, 100, 300, 1000, 3000, 10000, 30000, 100000, 300000, 1000000];
  ticks = ticks.filter(function (t) { return log1p(t) <= maxLog; });
  ticks.forEach(function (t) {
    var x = Math.round(X(t)) + 0.5;
    ctx.strokeStyle = PALETTE.rule;
    ctx.beginPath(); ctx.moveTo(x, padT); ctx.lineTo(x, padT + plotH); ctx.stroke();
    drawAxisText(ctx, t >= 1000 ? (t / 1000) + 'k' : String(t), x, padT + plotH + 14, 'center', 10);
  });
  drawAxisText(ctx, 'log1p scale →', s.w - padR, padT + plotH + 14, 'right', 10);

  rows.forEach(function (r, i) {
    var cy = padT + rowH * i + rowH / 2;
    drawAxisText(ctx, r.label, padL - 12, cy, 'right', 10.5);

    // whisker
    ctx.strokeStyle = PALETTE.slate;
    ctx.beginPath();
    ctx.moveTo(X(r.p5), cy); ctx.lineTo(X(r.p95), cy);
    ctx.stroke();
    // box
    var bx1 = X(r.p25), bx2 = X(r.p75);
    ctx.fillStyle = 'rgba(71,123,120,0.22)';
    ctx.strokeStyle = PALETTE.teal;
    ctx.fillRect(bx1, cy - 7, Math.max(1, bx2 - bx1), 14);
    ctx.strokeRect(bx1 + 0.5, cy - 6.5, Math.max(1, bx2 - bx1), 14);
    // median
    ctx.strokeStyle = PALETTE.rust;
    ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(X(r.p50), cy - 7); ctx.lineTo(X(r.p50), cy + 7);
    ctx.stroke();
    ctx.lineWidth = 1;

    registerHit(canvas, padL, cy - 10, plotW, 20, r.label,
      'p5 ' + fmtNum(r.p5, 0) + ' · median ' + fmtNum(r.p50, 0) + ' · p95 ' + fmtNum(r.p95, 0));
  });
}

/* -------------------------------------------------------------------------
   7. Tooltip wiring
   ------------------------------------------------------------------------- */

function initTooltips() {
  tooltipEl = document.getElementById('chart-tooltip');
  $all('canvas').forEach(function (canvas) {
    canvas.addEventListener('mousemove', function (e) {
      var hits = chartHits[canvas.id] || [];
      if (!hits.length || !tooltipEl) { hideTooltip(); return; }
      var rect = canvas.getBoundingClientRect();
      var dpr = window.devicePixelRatio || 1;
      var mx = (e.clientX - rect.left);
      var my = (e.clientY - rect.top);
      var found = null;
      for (var i = 0; i < hits.length; i++) {
        var hIt = hits[i];
        if (mx >= hIt.x && mx <= hIt.x + hIt.w && my >= hIt.y && my <= hIt.y + hIt.h) {
          found = hIt;
        }
      }
      if (found) {
        tooltipEl.innerHTML = '<span class="tt-label"></span><span class="tt-value"></span>';
        tooltipEl.querySelector('.tt-label').textContent = found.label;
        tooltipEl.querySelector('.tt-value').textContent = found.value;
        tooltipEl.style.left = e.clientX + 'px';
        tooltipEl.style.top = e.clientY + 'px';
        tooltipEl.classList.add('is-visible');
        tooltipEl.setAttribute('aria-hidden', 'false');
      } else {
        hideTooltip();
      }
    });
    canvas.addEventListener('mouseleave', hideTooltip);
  });
}

function hideTooltip() {
  if (!tooltipEl) return;
  tooltipEl.classList.remove('is-visible');
  tooltipEl.setAttribute('aria-hidden', 'true');
}

/* -------------------------------------------------------------------------
   8. Static (verified) chart drawings
   ------------------------------------------------------------------------- */

function drawScenarioChart() {
  var mode = state.scenarioMode;
  var counts = VERIFIED.scenarioIncidents;
  var total = counts.reduce(function (a, b) { return a + b; }, 0);
  if (mode === 'percent') {
    drawBarChart('scenario-chart', {
      labels: ['Scenario 1', 'Scenario 2', 'Scenario 3'],
      values: counts.map(function (c) { return pct(c, total); }),
      valueFmt: function (v) { return fmtPct(v, 100, 2); },
      axisFmt: function (v) { return v.toFixed(0) + '%'; },
      color: PALETTE.teal
    });
  } else {
    drawBarChart('scenario-chart', {
      labels: ['Scenario 1', 'Scenario 2', 'Scenario 3'],
      values: counts,
      color: PALETTE.teal
    });
  }
}

function drawRecordsChart() {
  var recs = VERIFIED.records;
  var isLog = state.recordsScale === 'log';
  var note = document.getElementById('records-note');
  drawBarChart('records-chart', {
    labels: recs.map(function (r) { return r.label; }),
    values: recs.map(function (r) { return isLog ? Math.log1p(r.value) : r.value; }),
    color: PALETTE.teal,
    height: 240,
    rotate: false,
    valueFmt: function (v) { return isLog ? compactNumber(Math.expm1(v)) : compactNumber(v); },
    axisFmt: function (v) { return isLog ? fmtInt(Math.round(Math.expm1(v))) : compactNumber(v); }
  });
  if (note) {
    note.textContent = isLog
      ? 'Log1p axis: ' + recs.map(function (r) { return r.label + ' ' + fmtInt(r.value); }).join(' · ') +
        '. The transform changes only the axis scale, never the underlying counts.'
      : 'HTTP activity dominates the raw record volume by more than an order of magnitude (' +
        fmtInt(28434423) + ' valid rows versus ' + fmtInt(405380) + ' for device). The log1p option compresses the axis so smaller sources stay readable.';
  }
}

function compactNumber(v) {
  var n = Math.round(v);
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(0) + 'k';
  return fmtInt(n);
}

function drawCoverageChart() {
  var canvas = document.getElementById('coverage-chart');
  if (!canvas) return;
  var s = setupCanvas(canvas, 90);
  if (!s) return;
  var ctx = s.ctx;
  var start = VERIFIED.coverage.startMs;
  var end = VERIFIED.coverage.endMs;
  var padL = 14, padR = 14, y = 40;
  var w = s.w - padL - padR;

  // month ticks
  var d = new Date(start);
  d = Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1);
  ctx.strokeStyle = PALETTE.rule;
  while (d <= end) {
    var x = padL + ((d - start) / (end - start)) * w;
    ctx.beginPath();
    ctx.moveTo(Math.round(x) + 0.5, y - 12);
    ctx.lineTo(Math.round(x) + 0.5, y + 12);
    ctx.stroke();
    drawAxisText(ctx, ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][new Date(d).getUTCMonth()] +
      (new Date(d).getUTCMonth() === 0 ? ' ' + new Date(d).getUTCFullYear() : ''), x, y + 26, 'center', 10);
    d = Date.UTC(new Date(d).getUTCFullYear(), new Date(d).getUTCMonth() + 1, 1);
  }

  ctx.fillStyle = PALETTE.teal;
  ctx.fillRect(padL, y - 7, w, 14);
  registerHit(canvas, padL, y - 12, w, 24, 'Coverage',
    fmtInt(VERIFIED.coverage.days) + ' dates · ' + fmtDay(start) + ' → ' + fmtDay(end));

  drawAxisText(ctx, fmtDay(start), padL, y - 20, 'left', 10);
  drawAxisText(ctx, fmtDay(end), padL + w, y - 20, 'right', 10);
}

function drawFlagBarChart() {
  var normal = VERIFIED.normalUserDays;
  var flagged = VERIFIED.flaggedUserDays;
  var labelNote = 'Verified notebook 06 output';
  if (state.predictions) {
    normal = state.predictions.n - state.predictions.flaggedCount;
    flagged = state.predictions.flaggedCount;
    labelNote = 'Computed from imported predictions';
  }
  drawBarChart('flagbar-chart', {
    labels: ['Normal user-days', 'Flagged user-days'],
    values: [normal, flagged],
    colors: [PALETTE.teal, PALETTE.rust],
    height: 220
  });
}

function drawScenPerfChart() {
  var mode = state.scenperfMode;
  var counts = VERIFIED.scenarioDetected.slice();
  var totals = VERIFIED.scenarioIncidents.slice();
  var note = document.getElementById('scenperf-note');
  var sourceNote = 'Latest reported figures, verified from notebook 07';

  if (state.predictions && state.predictions.scenarioStats) {
    var st = state.predictions.scenarioStats;
    counts = [st[1] || 0, st[2] || 0, st[3] || 0];
    totals = [st.totals[1] || 0, st.totals[2] || 0, st.totals[3] || 0];
    sourceNote = 'Recomputed in this browser from the imported predictions and the loaded ground truth';
  }

  if (mode === 'percent') {
    drawBarChart('scenperf-chart', {
      labels: ['Scenario 1', 'Scenario 2', 'Scenario 3'],
      values: counts.map(function (c, i) { return totals[i] > 0 ? pct(c, totals[i]) : null; }),
      valueFmt: function (v) { return v === null ? 'Not available' : v.toFixed(1) + '%'; },
      axisFmt: function (v) { return v.toFixed(0) + '%'; },
      colors: [PALETTE.teal, PALETTE.teal, PALETTE.teal],
      height: 240
    });
  } else {
    drawGroupedBarChart('scenperf-chart', {
      labels: ['Scenario 1', 'Scenario 2', 'Scenario 3'],
      series: [
        { name: 'Detected', values: counts, color: PALETTE.teal },
        { name: 'Not detected', values: totals.map(function (t, i) { return t - counts[i]; }), color: PALETTE.rust }
      ],
      height: 240
    });
  }

  if (note) {
    if (mode === 'percent') {
      note.textContent = sourceNote + ': Scenario 1 detected ' + counts[0] + ' of ' + totals[0] +
        ' (' + fmtPct(counts[0], totals[0]) + '); Scenario 2 detected ' + counts[1] + ' of ' + totals[1] +
        ' (' + fmtPct(counts[1], totals[1]) + '); Scenario 3 detected ' + counts[2] + ' of ' + totals[2] +
        ' (' + fmtPct(counts[2], totals[2]) + '). Detection differs sharply by scenario, which is the most important qualification on the headline recall number.';
    } else {
      note.textContent = sourceNote + ': detected versus not detected counts per scenario. Detection differs sharply by scenario.';
    }
  }
}

function drawThresholdChart() {
  var pts = VERIFIED.thresholds.map(function (t) {
    return { x: t.alertRate, y: t.recall, t: t };
  });
  drawLineChart('threshold-chart', {
    points: pts,
    pointsVisible: true,
    height: 260,
    xFmt: function (v) { return v + '% alerts'; },
    yFmt: function (v) { return v.toFixed(1) + '%'; },
    labelFn: function (p) { return 'Alert rate ' + p.x + '%'; },
    yLabel: 'Incident-day recall'
  });
}

function drawCleaningChart() {
  var wrap = document.getElementById('cleaning-chart-wrap');
  var empty = document.getElementById('cleaning-chart-empty');
  if (!state.audit) {
    if (wrap) wrap.classList.add('is-hidden');
    if (empty) empty.classList.remove('is-hidden');
    return;
  }
  if (empty) empty.classList.add('is-hidden');
  if (wrap) wrap.classList.remove('is-hidden');
  var a = state.audit;
  drawGroupedBarChart('cleaning-chart', {
    labels: a.rows.map(function (r) { return r.file; }),
    series: [
      { name: 'Missing values', values: a.rows.map(function (r) { return r.missing; }), color: PALETTE.rust },
      { name: 'Duplicate rows', values: a.rows.map(function (r) { return r.dup; }), color: PALETTE.teal }
    ],
    height: 220,
    rotate: true,
    padL: 66
  });
}

/* -------------------------------------------------------------------------
   9. Ground-truth register + incident evaluation rendering
   ------------------------------------------------------------------------- */

function loadEmbeddedGroundTruth() {
  var parsed = parseCSV(GROUND_TRUTH_CSV);
  state.incidents = parsed.rows.map(function (r) {
    return {
      details: r[2],
      user: r[3],
      scenario: r[1],
      startMs: parseDateTime(r[4]),
      endMs: parseDateTime(r[5])
    };
  });
  state.gtSource = 'embedded';
}

function renderRegister() {
  var body = document.getElementById('register-body');
  if (!body) return;
  var rows = state.incidents.filter(function (inc) {
    return state.registerFilter === 'all' || inc.scenario === state.registerFilter;
  });
  body.innerHTML = '';
  rows.forEach(function (inc) {
    var tr = document.createElement('tr');
    var th = document.createElement('th');
    th.setAttribute('scope', 'row');
    th.className = 'mono';
    th.textContent = inc.user;
    var tdS = document.createElement('td');
    tdS.className = 'mono';
    tdS.textContent = inc.scenario;
    var tdA = document.createElement('td');
    tdA.className = 'mono';
    tdA.textContent = fmtDay(inc.startMs);
    var tdB = document.createElement('td');
    tdB.className = 'mono';
    tdB.textContent = fmtDay(inc.endMs);
    tr.appendChild(th); tr.appendChild(tdS); tr.appendChild(tdA); tr.appendChild(tdB);
    body.appendChild(tr);
  });
  var count = document.getElementById('register-count');
  if (count) count.textContent = rows.length + ' of ' + state.incidents.length + ' incidents' +
    (state.gtSource === 'embedded' ? ' · embedded r4.2 ground truth' : ' · imported ground truth');
}

/* -------------------------------------------------------------------------
   10. Prediction import + recomputation
   ------------------------------------------------------------------------- */

function handlePredictionsFile(file) {
  if (!file) return;
  setStatus('status-predictions', 'Reading ' + file.name + ' …');
  readFileAsText(file, function (err, text) {
    if (err) { setStatus('status-predictions', 'Error: ' + err.message, 'is-error'); return; }
    var t0 = Date.now();

    var offsets = indexLines(text);
    if (offsets.length < 2) {
      setStatus('status-predictions', 'Validation error — the file needs a header and at least one data row.', 'is-error');
      return;
    }
    var h = lineAt(text, offsets, 0).split(',');
    for (var hi = 0; hi < h.length; hi++) h[hi] = h[hi].trim();

    var iUser = columnIndex(h, 'user');
    var iDay = columnIndex(h, 'day');
    var iScore = columnIndex(h, 'anomaly_score');
    var iFlag = columnIndex(h, 'is_anomaly');
    var missingCols = [];
    if (iUser < 0) missingCols.push('user');
    if (iDay < 0) missingCols.push('day');
    if (iScore < 0) missingCols.push('anomaly_score');
    if (iFlag < 0) missingCols.push('is_anomaly');
    if (missingCols.length) {
      setStatus('status-predictions',
        'Validation error — missing required column(s): ' + missingCols.join(', ') +
        '. Found columns: ' + h.join(', ') + '.', 'is-error');
      return;
    }
    var need = Math.max(iUser, iDay, iScore, iFlag) + 1;

    var n = offsets.length - 1;
    var dayMs = new Float64Array(n);
    var score = new Float64Array(n);
    var flag = new Uint8Array(n);
    var users = new Array(n);
    var bad = 0;
    var flaggedCount = 0;
    var shortRows = 0;

    for (var i = 0; i < n; i++) {
      var cells = lineAt(text, offsets, i + 1).split(',');
      if (cells.length < need) { shortRows++; users[i] = ''; dayMs[i] = NaN; score[i] = 0; flag[i] = 0; continue; }
      users[i] = cells[iUser].trim();
      var d = parseDateTime(cells[iDay]);
      if (isFinite(d)) dayMs[i] = dayKey(d); else bad++;
      var sc = parseFloat(cells[iScore]);
      score[i] = isFinite(sc) ? sc : 0;
      var f = isTruthyFlag(cells[iFlag]);
      flag[i] = f ? 1 : 0;
      if (f) flaggedCount++;
    }

    var pred = {
      n: n, users: users, day: dayMs, score: score, flag: flag,
      flaggedCount: flaggedCount, name: file.name,
      badDates: bad, inWin: new Uint8Array(n)
    };
    state.predictions = pred;

    computeIncidentOverlap();
    computeScenarioStats();

    var secs = ((Date.now() - t0) / 1000).toFixed(1);
    setStatus('status-predictions',
      'Loaded ' + fmtInt(n) + ' rows from ' + file.name + ' in ' + secs + 's · ' +
      fmtInt(flaggedCount) + ' flagged user-days (' + fmtPct(flaggedCount, n, 2) + ')' +
      (bad > 0 ? ' · ' + fmtInt(bad) + ' rows had unreadable dates (excluded from window matching)' : '') +
      (shortRows > 0 ? ' · ' + fmtInt(shortRows) + ' malformed rows skipped' : ''),
      'is-ok');

    renderAfterPredictions();
  });
}

/* Mark each prediction row as inside/outside a labelled incident window. */
function computeIncidentOverlap() {
  var pred = state.predictions;
  var byUser = {};
  state.incidents.forEach(function (inc, idx) {
    if (!isFinite(inc.startMs) || !isFinite(inc.endMs)) return;
    var a = dayKey(inc.startMs);
    var b = dayKey(inc.endMs);
    if (!byUser[inc.user]) byUser[inc.user] = [];
    byUser[inc.user].push({ idx: idx, a: a, b: b });
  });

  pred.incidentDayCount = 0;
  pred.tp = 0; pred.fp = 0; pred.fn = 0; pred.tn = 0;

  var perIncident = state.incidents.map(function () {
    return { days: 0, flagged: 0 };
  });

  for (var i = 0; i < pred.n; i++) {
    var wins = byUser[pred.users[i]];
    var foundIdx = -1;
    if (wins) {
      for (var w = 0; w < wins.length; w++) {
        if (pred.day[i] >= wins[w].a && pred.day[i] <= wins[w].b) { foundIdx = wins[w].idx; break; }
      }
    }
    if (foundIdx >= 0) {
      pred.inWin[i] = 1;
      pred.incidentDayCount++;
      perIncident[foundIdx].days++;
      if (pred.flag[i]) { pred.tp++; perIncident[foundIdx].flagged++; }
      else { pred.fn++; }
    } else {
      pred.inWin[i] = 0;
      if (pred.flag[i]) pred.fp++; else pred.tn++;
    }
  }
  pred.perIncident = perIncident;
}

function computeScenarioStats() {
  var pred = state.predictions;
  if (!pred || !pred.perIncident) return;
  var stats = { 1: 0, 2: 0, 3: 0, totals: { 1: 0, 2: 0, 3: 0 } };
  state.incidents.forEach(function (inc, i) {
    var s = inc.scenario;
    if (stats.totals[s] === undefined) stats.totals[s] = 0;
    stats.totals[s]++;
    if (pred.perIncident[i] && pred.perIncident[i].flagged > 0) {
      if (stats[s] === undefined) stats[s] = 0;
      stats[s]++;
    }
  });
  pred.scenarioStats = stats;
}

function renderAfterPredictions() {
  var pred = state.predictions;

  // score distribution
  var scoreEmpty = document.getElementById('score-empty');
  var scoreWrap = document.getElementById('score-wrap');
  if (scoreEmpty) scoreEmpty.classList.add('is-hidden');
  if (scoreWrap) scoreWrap.classList.remove('is-hidden');
  drawHistogram('score-chart', pred.score, {
    bins: 34, height: 220, color: PALETTE.rust, noteId: 'score-note',
    tickFmt: function (v) { return v.toFixed(2); }
  });

  // flag bar recomputed
  drawFlagBarChart();

  // daily confusion matrix
  var emptyD = document.getElementById('daily-cm-empty');
  var wrapD = document.getElementById('daily-cm-wrap');
  if (emptyD) emptyD.classList.add('is-hidden');
  if (wrapD) wrapD.classList.remove('is-hidden');
  setText('daily-tn', fmtInt(pred.tn));
  setText('daily-fp', fmtInt(pred.fp));
  setText('daily-fn', fmtInt(pred.fn));
  setText('daily-tp', fmtInt(pred.tp));
  setText('daily-precision', fmtPct(pred.tp, pred.tp + pred.fp));
  setText('daily-recall', fmtPct(pred.tp, pred.tp + pred.fn));
  setText('daily-specificity', fmtPct(pred.tn, pred.tn + pred.fp));

  var precision = pct(pred.tp, pred.tp + pred.fp);
  var recall = pct(pred.tp, pred.tp + pred.fn);
  var f1 = (precision !== null && recall !== null && (precision + recall) > 0)
    ? (2 * precision * recall / (precision + recall)) : null;
  setText('daily-f1', f1 === null ? 'Not available' : f1.toFixed(2) + '%');
  setText('daily-accuracy', fmtPct(pred.tp + pred.tn, pred.n));

  // scenario performance recomputed
  drawScenPerfChart();

  // per-incident status table
  renderMissedTable();

  // threshold selector
  var emptyT = document.getElementById('threshold-interactive-empty');
  var wrapT = document.getElementById('threshold-interactive-wrap');
  if (emptyT) emptyT.classList.add('is-hidden');
  if (wrapT) wrapT.classList.remove('is-hidden');

  pred.sortedScores = Array.prototype.slice.call(pred.score).sort(function (a, b) { return a - b; });
  updateThresholdSelector();

  updateGlobalDataState();
}

function setText(id, text) {
  var el = document.getElementById(id);
  if (el) el.textContent = text;
}

function renderMissedTable() {
  var body = document.getElementById('missed-body');
  if (!body) return;
  var pred = state.predictions;
  var empty = document.getElementById('missed-empty');
  var wrap = document.getElementById('missed-wrap');
  if (!pred || !pred.perIncident) {
    if (empty) empty.classList.remove('is-hidden');
    if (wrap) wrap.classList.add('is-hidden');
    return;
  }
  if (empty) empty.classList.add('is-hidden');
  if (wrap) wrap.classList.remove('is-hidden');

  var rows = state.incidents.map(function (inc, i) {
    var p = pred.perIncident[i] || { days: 0, flagged: 0 };
    return {
      user: inc.user,
      scenario: inc.scenario,
      start: fmtDay(inc.startMs),
      end: fmtDay(inc.endMs),
      days: p.days,
      flagged: p.flagged,
      status: p.flagged > 0 ? 'detected' : 'missed'
    };
  }).filter(function (r) {
    if (state.missedScenario !== 'all' && r.scenario !== state.missedScenario) return false;
    if (state.missedStatus !== 'all' && r.status !== state.missedStatus) return false;
    return true;
  });

  body.innerHTML = '';
  rows.forEach(function (r) {
    var tr = document.createElement('tr');
    [['user', r.user], ['scenario', r.scenario], ['start', r.start], ['end', r.end],
     ['days', fmtInt(r.days)], ['flagged', fmtInt(r.flagged)]].forEach(function (pair) {
      var td = document.createElement('td');
      td.className = 'mono';
      td.textContent = pair[1];
      td.setAttribute('data-sort', String(pair[0] === 'days' || pair[0] === 'flagged' ? pair[1] : pair[1]));
      tr.appendChild(td);
    });
    var st = document.createElement('td');
    st.className = 'mono';
    st.textContent = r.status === 'detected' ? 'Detected' : 'Missed';
    st.style.color = r.status === 'detected' ? '#35605D' : '#A8542F';
    st.style.fontWeight = '600';
    tr.appendChild(st);
    body.appendChild(tr);
  });

  var count = document.getElementById('missed-count');
  if (count) {
    var detected = rows.filter(function (r) { return r.status === 'detected'; }).length;
    count.textContent = rows.length + ' shown · ' + detected + ' detected · ' +
      (rows.length - detected) + ' missed';
  }
}

function updateThresholdSelector() {
  var pred = state.predictions;
  if (!pred || !pred.sortedScores) return;
  var slider = document.getElementById('threshold-slider');
  if (!slider) return;
  var pctile = parseFloat(slider.value);
  var out = document.getElementById('threshold-slider-value');
  if (out) out.textContent = pctile.toFixed(1);

  var sorted = pred.sortedScores;
  var n = sorted.length;
  var idx = Math.min(n - 1, Math.floor((pctile / 100) * n));
  var threshold = sorted[idx];
  var flagged = n - idx; // scores >= threshold (ascending sort)

  // incident-day recall at this threshold
  var inWinTotal = 0, inWinFlagged = 0;
  for (var i = 0; i < n; i++) {
    if (pred.inWin[i]) {
      inWinTotal++;
      if (pred.score[i] >= threshold) inWinFlagged++;
    }
  }

  setText('ithresh-value', fmtNum(threshold, 4));
  setText('ithresh-flagged', fmtInt(flagged));
  setText('ithresh-rate', fmtPct(flagged, n, 2));
  setText('ithresh-recall', fmtPct(inWinFlagged, inWinTotal, 2));
}

/* -------------------------------------------------------------------------
   11. Feature import + EDA rendering
   ------------------------------------------------------------------------- */

function handleFeaturesFile(file) {
  if (!file) return;
  setStatus('status-features', 'Reading ' + file.name + ' — large files can take several seconds …');
  readFileAsText(file, function (err, text) {
    if (err) { setStatus('status-features', 'Error: ' + err.message, 'is-error'); return; }
    var t0 = Date.now();

    var offsets = indexLines(text);
    if (offsets.length < 2) {
      setStatus('status-features', 'Validation error — the file needs a header and at least one data row.', 'is-error');
      return;
    }
    var h = lineAt(text, offsets, 0).split(',');
    for (var hi = 0; hi < h.length; hi++) h[hi] = h[hi].trim();

    if (columnIndex(h, 'user') < 0 || columnIndex(h, 'day') < 0) {
      setStatus('status-features', 'Validation error — expected columns "user" and "day". Found: ' +
        h.join(', ') + '.', 'is-error');
      return;
    }
    var present = MODEL_COLS.filter(function (c) { return columnIndex(h, c) >= 0; });
    if (!present.length) {
      setStatus('status-features', 'Validation error — none of the 12 feature columns were found. Expected: ' +
        MODEL_COLS.join(', ') + '.', 'is-error');
      return;
    }

    var n = offsets.length - 1;
    var iDay = columnIndex(h, 'day');
    var idxOf = {};
    present.forEach(function (c) { idxOf[c] = columnIndex(h, c); });
    var need = Math.max(iDay, present.reduce(function (m, c) { return Math.max(m, idxOf[c]); }, 0)) + 1;

    var cols = {};
    present.forEach(function (c) { cols[c] = new Float64Array(n); });
    var dayIdx = new Int32Array(n);
    var weekday = new Int8Array(n);
    var dayMap = {};
    var dayList = [];
    var badDates = 0;
    var shortRows = 0;

    for (var i = 0; i < n; i++) {
      var cells = lineAt(text, offsets, i + 1).split(',');
      if (cells.length < need) { shortRows++; weekday[i] = -1; continue; }
      var d = parseDateTime(cells[iDay]);
      if (isFinite(d)) {
        var k = fmtDay(d);
        var idx = dayMap[k];
        if (idx === undefined) { idx = dayList.length; dayList.push(k); dayMap[k] = idx; }
        dayIdx[i] = idx;
        weekday[i] = new Date(d).getUTCDay();
      } else { badDates++; weekday[i] = -1; }

      for (var ci = 0; ci < present.length; ci++) {
        var name = present[ci];
        var v = parseFloat(cells[idxOf[name]]);
        cols[name][i] = isFinite(v) ? v : 0;
      }
    }

    // totals per row for time series & weekday charts
    var totals = new Float64Array(n);
    COUNT_COLS.forEach(function (c) {
      if (!cols[c]) return;
      var arr = cols[c];
      for (var i2 = 0; i2 < n; i2++) totals[i2] += arr[i2];
    });

    // sort dayList chronologically and remap
    var order = dayList.map(function (k, i2) { return i2; }).sort(function (a, b) {
      return dayList[a] < dayList[b] ? -1 : 1;
    });
    var sortedList = order.map(function (i2) { return dayList[i2]; });
    var remap = new Int32Array(dayList.length);
    order.forEach(function (oldIdx, newIdx) { remap[oldIdx] = newIdx; });
    for (var i3 = 0; i3 < n; i3++) dayIdx[i3] = remap[dayIdx[i3]];

    state.features = {
      n: n, cols: cols, colNames: present, dayIdx: dayIdx, weekday: weekday,
      dayList: sortedList, totals: totals, name: file.name, badDates: badDates
    };

    var secs = ((Date.now() - t0) / 1000).toFixed(1);
    setStatus('status-features',
      'Loaded ' + fmtInt(n) + ' user-day rows · ' + fmtInt(sortedList.length) + ' dates · ' +
      present.length + ' feature columns from ' + file.name + ' (' + secs + 's)' +
      (shortRows > 0 ? ' · ' + fmtInt(shortRows) + ' malformed rows skipped' : '') +
      (badDates > 0 ? ' · ' + fmtInt(badDates) + ' unreadable dates' : ''),
      'is-ok');

    renderEDA();
    updateGlobalDataState();
  });
}

function colStats(arr, n) {
  var sorted = Array.prototype.slice.call(arr.subarray ? arr.subarray(0, n) : arr).sort(function (a, b) { return a - b; });
  function q(p) {
    if (!sorted.length) return null;
    var idx = Math.floor(p * (sorted.length - 1));
    return sorted[idx];
  }
  var sum = 0;
  for (var i = 0; i < sorted.length; i++) sum += sorted[i];
  return {
    n: sorted.length,
    min: q(0), p5: q(0.05), p25: q(0.25), p50: q(0.5), p75: q(0.75), p95: q(0.95),
    max: q(1),
    mean: sorted.length ? sum / sorted.length : null
  };
}

function renderEDA() {
  var f = state.features;
  if (!f) return;
  var empty = document.getElementById('eda-empty');
  var content = document.getElementById('eda-content');
  if (empty) empty.classList.add('is-hidden');
  if (content) content.classList.remove('is-hidden');

  var histTargets = [
    ['hist-logon', 'logon_event_count'],
    ['hist-email', 'email_event_count'],
    ['hist-http', 'http_event_count'],
    ['hist-file', 'file_event_count']
  ];
  histTargets.forEach(function (t) {
    if (f.cols[t[1]]) {
      drawHistogram(t[0], f.cols[t[1]], {
        bins: 30, height: 220, color: PALETTE.teal, noteId: t[0] + '-note',
        tickFmt: function (v) { return String(Math.round(v)); }
      });
    } else {
      drawEmpty(t[0], 'Column ' + t[1] + ' not present in the imported file');
    }
  });

  // after-hours grouped chart
  var sources = ['logon', 'device', 'file', 'email', 'http'];
  var normalVals = [], afterVals = [];
  sources.forEach(function (src) {
    var total = f.cols[src + '_event_count'];
    var after = f.cols[src + '_after_hours'];
    if (!total) { normalVals.push(0); afterVals.push(0); return; }
    var s1 = 0, s2 = 0;
    for (var i = 0; i < f.n; i++) {
      var a = after ? after[i] : 0;
      if (a > total[i]) a = total[i];
      s2 += a;
      s1 += total[i] - a;
    }
    normalVals.push(s1);
    afterVals.push(s2);
  });

  var ahNote = document.getElementById('afterhours-note');
  if (state.afterhoursMode === 'percent') {
    drawGroupedBarChart('afterhours-chart', {
      labels: sources,
      series: [
        { name: 'Normal hours', values: normalVals.map(function (v, i) { return pct(v, v + afterVals[i]); }), color: PALETTE.teal },
        { name: 'After hours', values: afterVals.map(function (v, i) { return pct(v, v + normalVals[i]); }), color: PALETTE.rust }
      ],
      valueFmt: function (v) { return fmtPct(v, 100, 1); },
      axisFmt: function (v) { return v.toFixed(0) + '%'; },
      height: 240
    });
    if (ahNote) ahNote.textContent = 'Share of each source’s events falling outside 08:00–18:00, computed from the imported file.';
  } else {
    drawGroupedBarChart('afterhours-chart', {
      labels: sources,
      series: [
        { name: 'Normal hours', values: normalVals, color: PALETTE.teal },
        { name: 'After hours', values: afterVals, color: PALETTE.rust }
      ],
      axisFmt: function (v) { return compactNumber(v); },
      height: 240
    });
    if (ahNote) {
      ahNote.textContent = 'Totals across all ' + fmtInt(f.n) + ' user-days in the imported file. After-hours means hour < 8 or hour ≥ 18.';
    }
  }

  // weekday averages
  var wdSums = [0, 0, 0, 0, 0, 0, 0];
  var wdCounts = [0, 0, 0, 0, 0, 0, 0];
  for (var i2 = 0; i2 < f.n; i2++) {
    var wd = f.weekday[i2];
    if (wd < 0) continue;
    wdSums[wd] += f.totals[i2];
    wdCounts[wd]++;
  }
  var wdLabels = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  var wdAvgs = wdSums.map(function (s, i3) { return pct(s, wdCounts[i3]); });
  drawBarChart('weekday-chart', {
    labels: wdLabels,
    values: wdAvgs,
    valueFmt: function (v) { return v === null ? 'Not available' : fmtNum(v, 1); },
    axisFmt: function (v) { return fmtNum(v, 0); },
    color: PALETTE.teal,
    height: 240
  });
  var wdNote = document.getElementById('weekday-note');
  if (wdNote) {
    wdNote.textContent = 'Mean recorded events per user-day for each weekday in the imported file (' +
      fmtInt(f.n) + ' user-days). Lower weekend values reflect fewer recorded events, not verified inactivity.';
  }

  // time series: total events per date
  var perDay = new Float64Array(f.dayList.length);
  for (var i3b = 0; i3b < f.n; i3b++) {
    perDay[f.dayIdx[i3b]] += f.totals[i3b];
  }
  var pts = [];
  for (var d = 0; d < f.dayList.length; d++) {
    pts.push({ x: d, y: perDay[d], label: f.dayList[d] });
  }
  drawLineChart('timeseries-chart', {
    points: pts,
    height: 240,
    xFmt: function (v) { return f.dayList[Math.max(0, Math.min(f.dayList.length - 1, Math.round(v)))]; },
    yFmt: function (v) { return compactNumber(v); },
    labelFn: function (p) { return p.label; },
    yLabel: 'Events per day'
  });
  var tsNote = document.getElementById('timeseries-note');
  if (tsNote) {
    tsNote.textContent = 'Total recorded events across all users for each of ' +
      fmtInt(f.dayList.length) + ' dates (' + f.dayList[0] + ' to ' + f.dayList[f.dayList.length - 1] +
      '), computed from the imported file.';
  }

  // box plot + table
  var boxRows = f.colNames.map(function (c) {
    var st = colStats(f.cols[c], f.n);
    return { label: c, p5: st.p5, p25: st.p25, p50: st.p50, p75: st.p75, p95: st.p95, max: st.max };
  });
  drawBoxPlot('boxplot-chart', boxRows, {});

  var tableBody = document.getElementById('boxplot-table-body');
  if (tableBody) {
    tableBody.innerHTML = '';
    boxRows.forEach(function (r) {
      var tr = document.createElement('tr');
      var th = document.createElement('th');
      th.setAttribute('scope', 'row');
      th.className = 'mono';
      th.textContent = r.label;
      tr.appendChild(th);
      [r.p5, r.p25, r.p50, r.p75, r.p95, r.max].forEach(function (v) {
        var td = document.createElement('td');
        td.className = 'mono';
        td.textContent = fmtNum(v, 0);
        tr.appendChild(td);
      });
      tableBody.appendChild(tr);
    });
  }
}

/* -------------------------------------------------------------------------
   12. Ground-truth import
   ------------------------------------------------------------------------- */

function handleGroundTruthFile(file) {
  if (!file) return;
  setStatus('status-groundtruth', 'Reading ' + file.name + ' …');
  readFileAsText(file, function (err, text) {
    if (err) { setStatus('status-groundtruth', 'Error: ' + err.message, 'is-error'); return; }
    var parsed;
    try { parsed = parseCSV(text); }
    catch (e) { setStatus('status-groundtruth', 'Error: the file could not be parsed as CSV.', 'is-error'); return; }

    var h = parsed.header;
    var iUser = columnIndex(h, 'user');
    var iStart = columnIndex(h, 'start');
    var iEnd = columnIndex(h, 'end');
    var missing = [];
    if (iUser < 0) missing.push('user');
    if (iStart < 0) missing.push('start');
    if (iEnd < 0) missing.push('end');
    if (missing.length) {
      setStatus('status-groundtruth', 'Validation error — missing column(s): ' + missing.join(', ') +
        '. Found: ' + (h.join(', ') || '(none)') + '.', 'is-error');
      return;
    }
    var iDataset = columnIndex(h, 'dataset');
    var iScenario = columnIndex(h, 'scenario');

    var kept = [], skipped = 0;
    parsed.rows.forEach(function (r) {
      if (iDataset >= 0) {
        var ds = String(r[iDataset]).trim();
        if (ds.indexOf('4.2') < 0) { skipped++; return; }
      }
      var sm = parseDateTime(r[iStart]);
      var em = parseDateTime(r[iEnd]);
      if (!isFinite(sm) || !isFinite(em)) { skipped++; return; }
      kept.push({
        user: String(r[iUser]).trim(),
        scenario: iScenario >= 0 ? String(r[iScenario]).trim() : '—',
        startMs: sm, endMs: em
      });
    });

    if (!kept.length) {
      setStatus('status-groundtruth', 'Validation error — no usable incident rows found (need user, start, end; only dataset 4.2 rows are used when a dataset column exists).', 'is-error');
      return;
    }

    state.incidents = kept;
    state.gtSource = 'imported';
    setStatus('status-groundtruth',
      'Loaded ' + kept.length + ' incidents from ' + file.name +
      (skipped ? ' · ' + skipped + ' rows skipped (other datasets or unreadable dates)' : ''), 'is-ok');
    renderRegister();
    if (state.predictions) {
      computeIncidentOverlap();
      computeScenarioStats();
      renderAfterPredictions();
    }
    updateGlobalDataState();
  });
}

/* -------------------------------------------------------------------------
   13. Audit import
   ------------------------------------------------------------------------- */

function handleAuditFile(file) {
  if (!file) return;
  setStatus('status-audit', 'Reading ' + file.name + ' …');
  readFileAsText(file, function (err, text) {
    if (err) { setStatus('status-audit', 'Error: ' + err.message, 'is-error'); return; }
    var parsed;
    try { parsed = parseCSV(text); }
    catch (e) { setStatus('status-audit', 'Error: the file could not be parsed as CSV.', 'is-error'); return; }

    var h = parsed.header;
    var iFile = columnIndex(h, 'file');
    if (iFile < 0) {
      setStatus('status-audit', 'Validation error — a "file" column is required. Found: ' +
        (h.join(', ') || '(none)') + '.', 'is-error');
      return;
    }
    var iMissing = columnIndex(h, 'missing_values');
    var iDup = columnIndex(h, 'duplicate_rows');
    var iOrig = columnIndex(h, 'original_rows');
    var iRem = columnIndex(h, 'remaining_rows');
    if (iMissing < 0 && iDup < 0) {
      setStatus('status-audit', 'Validation error — need at least a "missing_values" or "duplicate_rows" column to draw the cleaning chart. Found: ' +
        h.join(', ') + '.', 'is-error');
      return;
    }

    function num(row, idx) {
      if (idx < 0) return 0;
      var v = parseFloat(row[idx]);
      return isFinite(v) ? v : 0;
    }

    var rows = parsed.rows.map(function (r) {
      var full = String(r[iFile]);
      var short = full.split(/[\\\/]/).pop();
      return {
        file: short,
        missing: num(r, iMissing),
        dup: num(r, iDup),
        original: iOrig >= 0 ? num(r, iOrig) : null,
        remaining: iRem >= 0 ? num(r, iRem) : null
      };
    });

    if (!rows.length) {
      setStatus('status-audit', 'Validation error — no data rows found.', 'is-error');
      return;
    }

    state.audit = { rows: rows, name: file.name };
    setStatus('status-audit', 'Loaded ' + rows.length + ' rows from ' + file.name, 'is-ok');
    drawCleaningChart();
    updateGlobalDataState();
  });
}

/* -------------------------------------------------------------------------
   14. Global status, reset, toggles, sorting, filters
   ------------------------------------------------------------------------- */

function updateGlobalDataState() {
  var parts = [];
  if (state.predictions) parts.push('predictions');
  if (state.features) parts.push('features');
  if (state.audit) parts.push('audit');
  parts.push(state.gtSource === 'embedded' ? 'embedded ground truth' : 'imported ground truth');

  var rail = document.getElementById('rail-data-state');
  if (rail) {
    rail.textContent = (state.predictions || state.features || state.audit)
      ? 'Loaded: ' + parts.join(' · ')
      : 'No files imported · notebook figures shown';
  }

  var badge = document.getElementById('source-badge');
  if (badge) {
    if (state.predictions || state.features || state.audit) {
      badge.textContent = 'Source: notebook outputs + imported files';
      badge.classList.add('is-imported');
    } else {
      badge.textContent = 'Source: saved notebook outputs';
      badge.classList.remove('is-imported');
    }
  }
}

function resetImportedData() {
  var hasAny = !!(state.predictions || state.features || state.audit || state.gtSource === 'imported');
  if (hasAny) {
    var ok = window.confirm('Clear every imported file from memory and return to the reported-figure state?');
    if (!ok) return;
  }
  state.predictions = null;
  state.features = null;
  state.audit = null;
  loadEmbeddedGroundTruth();
  renderRegister();

  ['import-predictions', 'import-features', 'import-groundtruth', 'import-audit'].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) el.value = '';
  });

  setStatus('status-predictions', 'No file loaded. Suggested source: data/processed/isolation_forest_baseline.csv');
  setStatus('status-features', 'No file loaded. Suggested source: data/processed/complete_daily_features.csv');
  setStatus('status-groundtruth', 'Embedded r4.2 register loaded (70 incidents from the project\'s answers file).');
  setStatus('status-audit', 'No file loaded. Provide a CSV with file, missing_values, duplicate_rows columns.');

  // back to empty states
  toggleHidden('score-empty', 'score-wrap', false);
  toggleHidden('daily-cm-empty', 'daily-cm-wrap', false);
  toggleHidden('threshold-interactive-empty', 'threshold-interactive-wrap', false);
  toggleHidden('missed-empty', 'missed-wrap', false);
  var edaEmpty = document.getElementById('eda-empty');
  var edaContent = document.getElementById('eda-content');
  if (edaEmpty) edaEmpty.classList.remove('is-hidden');
  if (edaContent) edaContent.classList.add('is-hidden');

  ['daily-tn', 'daily-fp', 'daily-fn', 'daily-tp', 'daily-precision', 'daily-recall',
   'daily-specificity', 'daily-f1', 'daily-accuracy'].forEach(function (id) { setText(id, '—'); });
  setText('missed-count', 'Not available');

  drawCleaningChart();
  drawScorePlaceholder();
  drawFlagBarChart();
  drawScenPerfChart();
  updateGlobalDataState();
}

function toggleHidden(emptyId, wrapId, showWrap) {
  var e = document.getElementById(emptyId);
  var w = document.getElementById(wrapId);
  if (e) e.classList.toggle('is-hidden', showWrap);
  if (w) w.classList.toggle('is-hidden', !showWrap);
}

function drawScorePlaceholder() {
  var wrap = document.getElementById('score-wrap');
  if (wrap) wrap.classList.add('is-hidden');
  var empty = document.getElementById('score-empty');
  if (empty) empty.classList.remove('is-hidden');
}

function initToggles() {
  $all('.toggle-btn').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var target = btn.getAttribute('data-target');
      var mode = btn.getAttribute('data-mode');
      $all('.toggle-btn[data-target="' + target + '"]').forEach(function (b) {
        b.classList.toggle('is-on', b === btn);
      });
      if (target === 'scenario') { state.scenarioMode = mode; drawScenarioChart(); }
      else if (target === 'records') { state.recordsScale = mode; drawRecordsChart(); }
      else if (target === 'scenperf') { state.scenperfMode = mode; drawScenPerfChart(); }
      else if (target === 'afterhours') { state.afterhoursMode = mode; renderEDA(); }
    });
  });
}

function initFilters() {
  var reg = document.getElementById('dataset-scenario-filter');
  if (reg) {
    reg.addEventListener('change', function () {
      state.registerFilter = reg.value;
      renderRegister();
    });
  }
  var mScen = document.getElementById('missed-scenario-filter');
  if (mScen) {
    mScen.addEventListener('change', function () { state.missedScenario = mScen.value; renderMissedTable(); });
  }
  var mStatus = document.getElementById('missed-status-filter');
  if (mStatus) {
    mStatus.addEventListener('change', function () { state.missedStatus = mStatus.value; renderMissedTable(); });
  }
  var slider = document.getElementById('threshold-slider');
  if (slider) {
    slider.addEventListener('input', updateThresholdSelector);
  }
}

function compareCells(a, b) {
  var na = parseFloat(String(a).replace(/[,\s%]/g, '').replace('−', '-'));
  var nb = parseFloat(String(b).replace(/[,\s%]/g, '').replace('−', '-'));
  var aNum = isFinite(na) && /^[-\d.,\s%]+$/.test(String(a));
  var bNum = isFinite(nb) && /^[-\d.,\s%]+$/.test(String(b));
  if (aNum && bNum) return na - nb;
  return String(a).localeCompare(String(b));
}

function initSortableTables() {
  $all('th[data-sortable]').forEach(function (th) {
    th.setAttribute('tabindex', '0');
    function doSort() {
      var table = th.closest('table');
      var tbody = table.querySelector('tbody');
      if (!tbody) return;
      var idx = Array.prototype.indexOf.call(th.parentNode.children, th);
      var current = th.getAttribute('aria-sort');
      var dir = current === 'ascending' ? 'descending' : 'ascending';
      $all('th[data-sortable]', table).forEach(function (o) { o.removeAttribute('aria-sort'); });
      th.setAttribute('aria-sort', dir);

      var rows = Array.prototype.slice.call(tbody.rows);
      rows.sort(function (ra, rb) {
        var ca = ra.cells[idx] ? ra.cells[idx].textContent.trim() : '';
        var cb = rb.cells[idx] ? rb.cells[idx].textContent.trim() : '';
        var r = compareCells(ca, cb);
        return dir === 'ascending' ? r : -r;
      });
      rows.forEach(function (r) { tbody.appendChild(r); });
    }
    th.addEventListener('click', doSort);
    th.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); doSort(); }
    });
  });
}

function initImports() {
  var map = {
    'import-predictions': handlePredictionsFile,
    'import-features': handleFeaturesFile,
    'import-groundtruth': handleGroundTruthFile,
    'import-audit': handleAuditFile
  };
  Object.keys(map).forEach(function (id) {
    var input = document.getElementById(id);
    if (!input) return;
    input.addEventListener('change', function () {
      var file = input.files && input.files[0];
      if (file) map[id](file);
    });
  });

  ['reset-data-btn', 'reset-data-btn-2'].forEach(function (id) {
    var btn = document.getElementById(id);
    if (btn) btn.addEventListener('click', resetImportedData);
  });
}

/* -------------------------------------------------------------------------
   15. Draw orchestration / resize
   ------------------------------------------------------------------------- */

var activeDrawn = {};

function redrawActiveCharts() {
  var visible = $all('.panel-section').filter(function (s) { return !s.hidden; })[0];
  if (!visible) return;
  var id = visible.id;
  if (id === 'dataset') { drawScenarioChart(); drawRecordsChart(); drawCoverageChart(); }
  else if (id === 'cleaning') { drawCleaningChart(); }
  else if (id === 'eda') { if (state.features) renderEDA(); }
  else if (id === 'model') { drawFlagBarChart(); if (state.predictions) renderAfterPredictions(); }
  else if (id === 'evaluation') { drawScenPerfChart(); }
  else if (id === 'threshold') { drawThresholdChart(); }
}

var resizeTimer = null;
window.addEventListener('resize', function () {
  if (resizeTimer) clearTimeout(resizeTimer);
  resizeTimer = setTimeout(redrawActiveCharts, 180);
});

/* -------------------------------------------------------------------------
   16. Init
   ------------------------------------------------------------------------- */

function init() {
  loadEmbeddedGroundTruth();
  initNav();
  initToggles();
  initFilters();
  initSortableTables();
  initImports();
  initTooltips();

  renderRegister();
  drawScenarioChart();
  drawRecordsChart();
  drawCoverageChart();
  drawCleaningChart();
  drawFlagBarChart();
  drawScenPerfChart();
  drawThresholdChart();
  updateGlobalDataState();
  drawScorePlaceholder();

  // first section is visible by default in markup; ensure hash state
  if (location.hash) showSection(location.hash.slice(1), false);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
