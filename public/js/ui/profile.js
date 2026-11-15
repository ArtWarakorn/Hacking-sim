// First-run screen: pick a handle and accept the ethics pledge.
import { h } from './dom.js';

export function mountProfile(container, { store, go }) {
  const name = h('input', { type: 'text', id: 'handle', maxLength: 24, placeholder: 'เช่น zero_cool', autocomplete: 'off', required: true });
  const pledge = h('input', { type: 'checkbox', id: 'pledge' });
  const error = h('p', { class: 'form-error', role: 'alert' });

  const form = h('form', {
    class: 'card profile-card',
    onSubmit: (e) => {
      e.preventDefault();
      const handle = name.value.trim();
      if (handle.length < 2) { error.textContent = 'ชื่อ handle ต้องมีอย่างน้อย 2 ตัวอักษร'; return; }
      if (!pledge.checked) { error.textContent = 'ต้องยอมรับข้อตกลงก่อนเริ่มเล่น'; return; }
      store.update((p) => { p.profile = { name: handle, createdAt: new Date().toISOString() }; });
      go('/');
    },
  },
  h('pre', { class: 'boot' }, [
    '[ OK ] จำลองเครือข่าย ............ พร้อม',
    '[ OK ] จำลองระบบไฟล์ .............. พร้อม',
    '[ OK ] เครื่องเป้าหมายทั้งหมดเป็นของปลอม',
    '[ OK ] ไม่มี packet ออกนอกเครื่องนี้',
  ].join('\n')),
  h('h1', null, 'HackSim'),
  h('p', { class: 'muted' }, 'ฝึกเป็น pentester ตั้งแต่ศูนย์ ผ่านภารกิจจำลองที่อิงงานจริง เรียงจากง่ายไปยาก'),
  h('label', { for: 'handle' }, 'ตั้งชื่อ handle ของคุณ'),
  name,
  h('label', { class: 'check', for: 'pledge' }, pledge,
    h('span', null, 'ฉันจะใช้ความรู้จากเกมนี้กับระบบที่ได้รับอนุญาตเท่านั้น และเข้าใจว่าการเข้าถึงระบบโดยไม่ได้รับอนุญาตผิดกฎหมาย')),
  error,
  h('button', { class: 'btn primary', type: 'submit' }, 'เริ่มเล่น'));

  container.replaceChildren(h('div', { class: 'center' }, form));
  name.focus();
  return () => {};
}
