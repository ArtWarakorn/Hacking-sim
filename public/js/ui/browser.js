// A minimal in-game web browser: address bar, GET navigation (auto-follows redirects), and a
// DevTools-lite cookie panel. Lives inside the mission view as a tab alongside the terminal.
//
// Safety: the response body is only ever shown as plain text (via h()'s text nodes, never innerHTML).
// HackSim never renders a page's HTML live and never executes anything the player or a webapp returns -
// confirming XSS here means *reading* an unescaped payload in the response text, exactly how a real
// tester confirms it (by viewing source), not by watching a script actually run.
import { h } from './dom.js';
import { parseUrl, httpRequest } from '../sim/httpsim.js';

/** host -> Map(cookieName -> value). One jar per Browser instance (reset when the mission reloads). */
function makeJar() {
  const jar = new Map();
  return {
    header(host) {
      const m = jar.get(host);
      if (!m || !m.size) return '';
      return [...m.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
    },
    map(host) {
      if (!jar.has(host)) jar.set(host, new Map());
      return jar.get(host);
    },
    applySetCookie(host, headers) {
      // a response may set several cookies at once (one Set-Cookie header line each)
      for (const [k, raw] of headers) {
        if (k.toLowerCase() !== 'set-cookie') continue;
        const [pair, ...attrs] = raw.split(';').map((s) => s.trim());
        const eq = pair.indexOf('=');
        if (eq < 0) continue;
        const name = pair.slice(0, eq);
        const value = pair.slice(eq + 1);
        const m = this.map(host);
        const maxAgeZero = attrs.some((a) => /^max-age=0$/i.test(a));
        if (maxAgeZero || value === '') m.delete(name);
        else m.set(name, value);
      }
    },
  };
}

export function mountBrowser(container, { world, selfIp, bus, session, recordHttp }) {
  const jar = makeJar();
  let currentHost = null;

  const addressInput = h('input', { type: 'text', placeholder: 'http://host/path', 'aria-label': 'ที่อยู่เว็บ', autocomplete: 'off' });
  const statusLine = h('p', { class: 'browser-status muted small' }, 'ยังไม่ได้เปิดหน้าเว็บใด');
  const headersEl = h('pre', { class: 'browser-headers', hidden: true });
  const headersToggle = h('button', { class: 'btn link', type: 'button', hidden: true, onClick: () => {
    headersEl.hidden = !headersEl.hidden;
    headersToggle.textContent = headersEl.hidden ? 'แสดง response headers' : 'ซ่อน response headers';
  } }, 'แสดง response headers');
  const bodyEl = h('pre', { class: 'browser-body' }, 'พิมพ์ URL แล้วกด Go หรือ Enter');
  const cookiesEl = h('div', { class: 'cookie-rows' });

  const renderCookies = () => {
    const rows = [];
    if (currentHost) {
      const map = jar.map(currentHost);
      for (const [name, value] of map) {
        let n = name;
        const nameInput = h('input', { value: n, 'aria-label': 'ชื่อ cookie', onChange: (e) => {
          const next = e.target.value.trim();
          map.delete(n);
          if (next) map.set(next, valueInput.value);
          n = next;
        } });
        const valueInput = h('input', { value, 'aria-label': 'ค่า cookie', onChange: (e) => { if (n) map.set(n, e.target.value); } });
        const del = h('button', { class: 'btn danger small', type: 'button', title: 'ลบ cookie นี้', onClick: () => { map.delete(n); renderCookies(); } }, '✕');
        rows.push(h('div', { class: 'cookie-row' }, nameInput, valueInput, del));
      }
    }
    const addBtn = h('button', { class: 'btn small', type: 'button', disabled: !currentHost, onClick: () => {
      jar.map(currentHost).set(`cookie${jar.map(currentHost).size + 1}`, '');
      renderCookies();
    } }, '+ เพิ่ม cookie');
    cookiesEl.replaceChildren(
      currentHost ? h('p', { class: 'muted small' }, `Cookie สำหรับ ${currentHost} — แก้ไขแล้วมีผลกับคำขอถัดไปทันที`) : h('p', { class: 'muted small' }, 'เปิดเว็บไซต์ก่อนเพื่อดู/แก้ cookie (DevTools-lite)'),
      ...rows, addBtn,
    );
  };

  function showError(message) {
    statusLine.textContent = message;
    statusLine.className = 'browser-status bad small';
    headersToggle.hidden = true; headersEl.hidden = true;
    bodyEl.textContent = '';
  }

  function showResponse(displayUrl, r) {
    statusLine.className = 'browser-status small';
    statusLine.textContent = `${displayUrl} → HTTP ${r.status} ${r.reason}`;
    headersToggle.hidden = false;
    headersEl.hidden = true;
    headersToggle.textContent = 'แสดง response headers';
    headersEl.textContent = r.headers.map(([k, v]) => `${k}: ${v}`).join('\n');
    bodyEl.textContent = r.body || '(เนื้อหาว่างเปล่า)';
  }

  function navigate(urlStr, hopsLeft = 5) {
    const u = parseUrl(urlStr);
    if (!u) { showError(`ไม่สามารถแปล URL นี้ได้: ${urlStr}`); return; }
    addressInput.value = urlStr;
    const headers = { host: u.hostHeader, 'user-agent': 'Mozilla/5.0 (HackSim Browser)', accept: 'text/html,*/*' };
    const cookieHeader = jar.header(u.hostHeader);
    if (cookieHeader) headers.cookie = cookieHeader;
    const req = { ...u, method: 'GET', headers, body: '' };
    const res = httpRequest(world, req, selfIp);
    bus?.emit('net', { kind: 'http', ip: res.ip ?? null, port: u.port, session });
    if (!res.ok) { showError(`เชื่อมต่อไม่สำเร็จ: ${res.message}`); return; }
    const r = res.response;
    currentHost = u.hostHeader;
    jar.applySetCookie(u.hostHeader, r.headers);
    renderCookies();
    bus?.emit('http', {
      session, host: u.host, ip: res.ip, port: u.port, method: 'GET', path: u.path, query: u.query, status: r.status,
      full: true, source: 'browser', reqHeaders: headers, reqBody: '', resHeaders: r.headers, resBody: r.body, displayUrl: urlStr,
    });
    recordHttp?.();
    const location = r.headers.find(([k]) => k.toLowerCase() === 'location')?.[1];
    if ([301, 302, 303, 307, 308].includes(r.status) && location && hopsLeft > 0) {
      navigate(new URL(location, `${u.scheme}://${u.hostHeader}${u.path}`).href, hopsLeft - 1);
      return;
    }
    showResponse(urlStr, r);
  }

  const goBtn = h('button', { class: 'btn primary', type: 'button', onClick: () => addressInput.value.trim() && navigate(addressInput.value.trim()) }, 'Go');
  const addressForm = h('form', { class: 'browser-bar', onSubmit: (e) => { e.preventDefault(); goBtn.click(); } }, addressInput, goBtn);

  renderCookies();
  container.replaceChildren(h('div', { class: 'browser' },
    addressForm,
    h('p', { class: 'muted small' }, 'Browser เปิดได้เฉพาะ GET — ใช้ Terminal (curl) หรือ Proxy ▸ Repeater สำหรับฟอร์มแบบ POST'),
    statusLine,
    h('div', { class: 'browser-panels' },
      h('section', { class: 'browser-main' }, headersToggle, headersEl, bodyEl),
      h('aside', { class: 'browser-cookies' }, h('h3', null, 'Cookies'), cookiesEl)),
  ));

  return { focus: () => addressInput.focus() };
}
