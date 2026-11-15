// Machine runtime + shell sessions. A runtime owns the VFS (so state survives `su`/`exit`);
// a Session is "one logged-in shell" on a runtime; the SessionStack lets ssh/su nest shells.
import { VFS } from './vfs.js';

/** Build the VFS for a machine definition, generating /etc/passwd, /etc/hostname and home dirs if absent. */
export function createRuntime(def, world = null) {
  const fs = { ...(def.fs || {}) };
  if (!fs['/etc/passwd']) {
    fs['/etc/passwd'] = {
      content: def.users.map((u) => `${u.name}:x:${u.uid}:${u.gid ?? u.uid}:${u.gecos || u.name}:${u.home}:${u.shell || '/bin/bash'}`).join('\n') + '\n',
    };
  }
  if (!fs['/etc/hostname']) fs['/etc/hostname'] = { content: `${def.hostname}\n` };
  for (const u of def.users) {
    if (!fs[u.home]) fs[u.home] = { type: 'dir', owner: u.name, group: u.groups?.[0]?.name || u.name, mode: u.uid === 0 ? '700' : '755' };
  }
  return { def, vfs: new VFS(fs), world };
}

export class Session {
  constructor(runtime, user, { cwd } = {}) {
    this.runtime = runtime;
    this.machine = runtime.def;
    this.vfs = runtime.vfs;
    this.world = runtime.world; // shared network (null = no network)
    this.user = user;
    this.cwd = cwd || user.home;
    this.lastStatus = 0;
    this.env = {
      HOME: user.home, USER: user.name, LOGNAME: user.name, SHELL: user.shell || '/bin/bash',
      PATH: '/usr/local/bin:/usr/bin:/bin', PWD: this.cwd, HOSTNAME: runtime.def.hostname,
      TERM: 'xterm-256color', LANG: 'en_US.UTF-8',
    };
  }

  get host() { return this.machine.hostname; }

  prompt() {
    const home = this.user.home;
    let dir = this.cwd;
    if (dir === home) dir = '~';
    else if (dir.startsWith(`${home}/`) && home !== '/') dir = `~${dir.slice(home.length)}`;
    return `${this.user.name}@${this.host}:${dir}${this.user.uid === 0 ? '#' : '$'} `;
  }
}

export function createSession(runtime, userName = runtime.def.startUser, opts) {
  const user = runtime.def.users.find((u) => u.name === userName);
  if (!user) throw new Error(`ไม่พบ user ${userName} บนเครื่อง ${runtime.def.id}`);
  return new Session(runtime, user, opts);
}

export class SessionStack {
  constructor(first) { this.sessions = [first]; this.interactive = null; } // interactive: see submitLine() in terminal/executor.js
  get current() { return this.sessions[this.sessions.length - 1]; }
  get depth() { return this.sessions.length; }
  push(session) { this.sessions.push(session); return session; }
  pop() { return this.sessions.length > 1 ? this.sessions.pop() : null; }
}
