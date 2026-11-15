# HackSim

เกมจำลองการทำ Penetration Testing สำหรับฝึก pentester ตั้งแต่ระดับเริ่มต้นจนถึงระดับมืออาชีพ
ทุกอย่าง — เครื่อง เป้าหมาย เครือข่าย เว็บแอป — เป็นการ **จำลองในเบราว์เซอร์ล้วนๆ** ไม่มีการส่ง
packet หรือคำสั่งใดออกไปนอกเครื่องของคุณ จึงฝึกได้อย่างปลอดภัยและถูกกฎหมาย

## เริ่มเล่น

ไม่ต้องติดตั้ง dependency ใดๆ (ใช้ Node.js built-in ล้วน):

```bash
git clone https://github.com/ArtWarakorn/Hacking-sim.git
cd Hacking-sim
npm start
```

แล้วเปิด <http://localhost:3001> (เปลี่ยนพอร์ตได้ด้วย `PORT=xxxx npm start`)

ต้องการ Node.js >= 18

## รันเทสต์ / ตรวจเนื้อหา

```bash
npm test              # unit test ทั้งหมด (parser, VFS, mission engine, SQL engine, เครื่องมือต่างๆ)
node tools/validate.mjs   # ตรวจความถูกต้องของไฟล์เนื้อหาทั้งหมดใน content/
```

## สถานะปัจจุบัน

| บท | เนื้อหา | สถานะ |
|---|---|---|
| 0 | Onboarding & Rules of Engagement | ✅ เล่นได้ |
| 1 | Linux Fundamentals | ✅ เล่นได้ |
| 2 | Networking Fundamentals | ✅ เล่นได้ |
| 3 | Reconnaissance & Enumeration | ✅ เล่นได้ |
| 4 | Web Application Attacks (OWASP Top 10) | 🚧 มีโครงสร้าง (SQL engine, เว็บช่องโหว่ ShopZone, Browser/Proxy) ยังไม่มีด่าน |
| 5–11 | Passwords, Exploitation, Privesc, AD, Pivoting, Reporting, Capstone | ❌ ยังไม่เริ่ม |

## โครงสร้างโปรเจกต์

```
server.js            # static server + progress API (Node built-in เท่านั้น ไม่มี dependency)
public/              # ฝั่งเกม (HTML/CSS/JS, ES modules, ไม่มี build step)
  js/sim/            # ตัวจำลอง: ระบบไฟล์ (vfs), เครือข่าย (network), HTTP, SQL
  js/commands/       # คำสั่ง terminal แต่ละตัว
  js/webapps/        # เว็บแอปที่มี logic จริง (เช่น ShopZone)
  js/mission/        # mission engine: objective, คะแนน, scope enforcement
  js/ui/             # หน้าจอต่างๆ รวมถึง Terminal/Browser/Proxy
content/             # เนื้อหาเกมทั้งหมดเป็น JSON (ไม่แก้โค้ดก็เพิ่มด่านได้)
  curriculum.json    # ลำดับบท/ด่าน
  missions/          # 1 ไฟล์ต่อ 1 ด่าน
  lessons/           # บทเรียนก่อนเข้าด่าน
  machines/ network/ webapps/   # เครื่องและเว็บเป้าหมายจำลอง
tests/               # unit test (node --test)
tools/               # validate.mjs (ตรวจเนื้อหา), seal.mjs (สร้าง hash ของ flag/คำตอบ), hash.mjs
```

## เพิ่มด่านใหม่

1. เขียนไฟล์ `content/missions/<id>.json` ใส่ `"flagHash": "SEAL"` หรือ `"answerHash": "SEAL"` ไว้ก่อน
2. เพิ่ม id ด่านใน `content/curriculum.json`
3. เพิ่มเฉลยลงใน `tests/walkthroughs.json`
4. รัน `node tools/seal.mjs` เพื่อเติม hash จากเฉลยให้อัตโนมัติ
5. รัน `node tools/validate.mjs` และ `npm test` เพื่อยืนยันว่าด่านผ่านได้จริง

ทุกด่านต้องมีเฉลยที่พิสูจน์ได้ว่าเล่นผ่านจริงใน `tests/walkthroughs.json` — ถ้าไม่มี `node tools/validate.mjs` จะ error

## หลักการออกแบบ

- **ปลอดภัยเสมอ**: ไม่มีการรันคำสั่งระบบจริง ไม่มีการส่ง network request จริง และไม่มีการ render
  HTML/JavaScript ของผู้เล่นเป็น live DOM — การยืนยันช่องโหว่ (เช่น XSS) ทำโดยอ่านข้อความที่สะท้อน
  กลับมาแบบไม่ผ่านการ encode เหมือนที่ pentester มืออาชีพใช้ยืนยันจริง ไม่ใช่การรันสคริปต์จริง
- **เนื้อหาทั้งหมดเป็น JSON**: เพิ่มด่าน เครื่อง หรือเว็บแอปใหม่โดยไม่ต้องแตะโค้ด engine
- **ไม่มี dependency**: รันได้ทันทีหลัง `git clone` ด้วย Node.js เปล่าๆ
