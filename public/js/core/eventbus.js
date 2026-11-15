// Tiny pub/sub. The mission engine (Phase 3) listens to 'command', 'file_read', 'shell', ... events.
export class EventBus {
  constructor() { this.handlers = new Map(); }
  on(event, fn) {
    if (!this.handlers.has(event)) this.handlers.set(event, new Set());
    this.handlers.get(event).add(fn);
    return () => this.handlers.get(event).delete(fn);
  }
  emit(event, data) {
    for (const fn of this.handlers.get(event) || []) {
      try { fn(data); } catch (e) { console.error(`[bus] handler for "${event}" failed`, e); }
    }
  }
}

export const bus = new EventBus();
