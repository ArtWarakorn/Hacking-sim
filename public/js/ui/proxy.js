// Proxy (Burp-lite): a history of captured requests, a Repeater to edit and resend one, and a Decoder.
// Safety: same rule as Browser — bodies are shown and edited as plain text only, never rendered as HTML.
import { h } from './dom.js';
import { parseUrl, httpRequest } from '../sim/httpsim.js';

const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'PATCH'];
const fmtHeaders = (pairs) => pairs.map(([k, v]) => `${k}: ${v}`).join('\n');
const parseHeaderLines = (text) => Object.fromEntries(text.split('\n').map((l) => l.trim()).filter(Boolean)
  .map((l) => { const i = l.indexOf(':'); return i < 0 ? [l.toLowerCase(), ''] : [l.slice(0, i).trim().toLowerCase(), l.slice(i + 1).trim()]; }));

function entryLabel(e) {
  const when = new Date(e.time).toLocaleTimeString('th-TH', { hour12: false });
  return `${when} · ${e.method} ${e.host}${e.path}${e.query ? `?${e.query}` : ''} → ${e.status}`;
}

export function mountProxy(container, { world, selfIp, bus, session, httpHistory }) {
  let tab = 'history';
  const tabBtns = {};
  const panels = {};
  const showTab = (name) => {
    tab = name;
    for (const n of Object.keys(panels)) { panels[n].hidden = n !== name; tabBtns[n].classList.toggle('active', n === name); }
  };

  // ---------------- History ----------------
  const historyList = h('ul', { class: 'proxy-history' });
  const historyDetail = h('div', { class: 'proxy-detail' }, h('p', { class: 'muted small' }, 'เลือกรายการทางซ้ายเพื่อดูรายละเอียด'));

  function renderHistory() {
    if (!httpHistory.length) { historyList.replaceChildren(h('li', { class: 'muted small' }, 'ยังไม่มี traffic — ลองเปิดเว็บด้วย Browser หรือ curl ใน Terminal ก่อน')); return; }
    historyList.replaceChildren(...httpHistory.map((e, i) => h('li', null, h('button', {
      class: 'btn link proxy-history-row', type: 'button', onClick: () => showDetail(i),
    }, entryLabel(e)))));
  }

  function showDetail(i) {
    const e = httpHistory[i];
    historyDetail.replaceChildren(
      h('div', { class: 'row wrap' }, h('span', { class: 'badge' }, e.source), h('span', { class: 'badge' }, `${e.status}`)),
      h('h4', null, 'Request'),
      h('pre', { class: 'proxy-pane' }, `${e.method} ${e.path}${e.query ? `?${e.query}` : ''} HTTP/1.1\n${fmtHeaders(Object.entries(e.reqHeaders || {}).map(([k, v]) => [k, v]))}\n\n${e.reqBody || ''}`),
      h('h4', null, 'Response'),
      h('pre', { class: 'proxy-pane' }, `HTTP/1.1 ${e.status}\n${fmtHeaders(e.resHeaders || [])}\n\n${e.resBody || ''}`),
      h('button', { class: 'btn primary', type: 'button', onClick: () => sendToRepeater(e) }, 'ส่งไปที่ Repeater'));
  }

  // ---------------- Repeater ----------------
  const rMethod = h('select', { 'aria-label': 'method' }, METHODS.map((m) => h('option', { value: m }, m)));
  const rUrl = h('input', { type: 'text', placeholder: 'http://host/path?query', 'aria-label': 'URL' });
  const rHeaders = h('textarea', { class: 'proxy-textarea', placeholder: 'Header-Name: value (บรรทัดละหนึ่ง)', 'aria-label': 'headers' });
  const rBody = h('textarea', { class: 'proxy-textarea', placeholder: 'request body (สำหรับ POST/PUT)', 'aria-label': 'body' });
  const rResponse = h('pre', { class: 'proxy-pane proxy-repeater-response' }, 'ยังไม่ได้ส่ง request');
  const rStatus = h('p', { class: 'muted small' }, '');

  function sendToRepeater(e) {
    rMethod.value = e.method;
    rUrl.value = `http://${e.host}${e.path}${e.query ? `?${e.query}` : ''}`;
    rHeaders.value = fmtHeaders(Object.entries(e.reqHeaders || {}).filter(([k]) => k !== 'host').map(([k, v]) => [k, v]));
    rBody.value = e.reqBody || '';
    showTab('repeater');
  }

  function sendRepeater() {
    const u = parseUrl(rUrl.value.trim());
    if (!u) { rStatus.textContent = 'URL ไม่ถูกต้อง'; rStatus.className = 'bad small'; return; }
    const extra = parseHeaderLines(rHeaders.value);
    const headers = { host: u.hostHeader, 'user-agent': 'HackSim-Proxy/1.0', ...extra };
    const method = rMethod.value;
    const body = ['POST', 'PUT', 'PATCH'].includes(method) ? rBody.value : '';
    const req = { ...u, method, headers, body };
    const res = httpRequest(world, req, selfIp);
    bus?.emit('net', { kind: 'http', ip: res.ip ?? null, port: u.port, session });
    if (!res.ok) { rStatus.textContent = `เชื่อมต่อไม่สำเร็จ: ${res.message}`; rStatus.className = 'bad small'; rResponse.textContent = ''; return; }
    const r = res.response;
    bus?.emit('http', {
      session, host: u.host, ip: res.ip, port: u.port, method, path: u.path, query: u.query, status: r.status,
      full: true, source: 'repeater', reqHeaders: headers, reqBody: body, resHeaders: r.headers, resBody: r.body,
    });
    rStatus.textContent = `ส่งแล้ว — HTTP ${r.status} ${r.reason}`;
    rStatus.className = 'good small';
    rResponse.textContent = `HTTP/1.1 ${r.status} ${r.reason}\n${fmtHeaders(r.headers)}\n\n${r.body}`;
  }

  // ---------------- Decoder ----------------
  const dInput = h('textarea', { class: 'proxy-textarea', placeholder: 'ข้อความที่จะเข้ารหัส/ถอดรหัส', 'aria-label': 'decoder input' });
  const dOutput = h('textarea', { class: 'proxy-textarea', readonly: true, placeholder: 'ผลลัพธ์', 'aria-label': 'decoder output' });
  const dError = h('p', { class: 'bad small' });
  const utf8ToHex = (s) => [...new TextEncoder().encode(s)].map((b) => b.toString(16).padStart(2, '0')).join('');
  const hexToUtf8 = (s) => new TextDecoder().decode(Uint8Array.from((s.trim().match(/[0-9a-f]{2}/gi) || []), (h2) => parseInt(h2, 16)));
  const decodeOps = {
    'Base64 encode': (s) => btoa(unescape(encodeURIComponent(s))),
    'Base64 decode': (s) => decodeURIComponent(escape(atob(s.trim()))),
    'URL encode': (s) => encodeURIComponent(s),
    'URL decode': (s) => decodeURIComponent(s),
    'Hex encode': utf8ToHex,
    'Hex decode': hexToUtf8,
  };
  const decoderButtons = Object.entries(decodeOps).map(([label, fn]) => h('button', {
    class: 'btn small', type: 'button', onClick: () => {
      try { dOutput.value = fn(dInput.value); dError.textContent = ''; } catch { dOutput.value = ''; dError.textContent = `ถอด/เข้ารหัสด้วย "${label}" ไม่สำเร็จ — ตรวจรูปแบบข้อความ`; }
    },
  }, label));

  // ---------------- assemble ----------------
  panels.history = h('div', { class: 'proxy-panel' }, h('div', { class: 'proxy-history-layout' }, historyList, historyDetail));
  panels.repeater = h('div', { class: 'proxy-panel' },
    h('div', { class: 'row' }, rMethod, rUrl, h('button', { class: 'btn primary', type: 'button', onClick: sendRepeater }, 'Send')),
    h('div', { class: 'row' },
      h('div', { class: 'col' }, h('label', null, 'Headers'), rHeaders),
      h('div', { class: 'col' }, h('label', null, 'Body'), rBody)),
    rStatus, h('label', null, 'Response'), rResponse);
  panels.decoder = h('div', { class: 'proxy-panel' },
    h('div', { class: 'row' },
      h('div', { class: 'col' }, h('label', null, 'ข้อความ'), dInput),
      h('div', { class: 'col' }, h('label', null, 'ผลลัพธ์'), dOutput)),
    h('div', { class: 'row wrap' }, decoderButtons), dError);

  for (const name of ['history', 'repeater', 'decoder']) {
    tabBtns[name] = h('button', { class: 'tab-btn', type: 'button', onClick: () => showTab(name) },
      { history: 'History', repeater: 'Repeater', decoder: 'Decoder' }[name]);
  }

  renderHistory();
  showTab('history');
  container.replaceChildren(h('div', { class: 'proxy' },
    h('div', { class: 'tab-bar' }, Object.values(tabBtns)),
    panels.history, panels.repeater, panels.decoder));

  const off = bus?.on('http', (e) => { if (e.full) renderHistory(); });
  return { destroy: () => off?.() };
}
