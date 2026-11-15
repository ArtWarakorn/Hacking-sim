import { createDefaultProgress, normalizeProgress } from '../mission/progress.js';
import { saveProgress } from './storage.js';

export class Store {
  constructor(progress, mode) {
    this.progress = progress;
    this.mode = mode; // 'server' | 'local'
    this.listeners = new Set();
  }

  /** Run `mutator(progress)`, persist, notify subscribers, and return whatever the mutator returns. */
  update(mutator) {
    const result = mutator(this.progress);
    this.commit();
    return result;
  }

  commit() {
    this.listeners.forEach((fn) => fn(this.progress));
    saveProgress(this.progress, this.mode);
  }

  replace(progress) {
    this.progress = normalizeProgress(progress);
    this.commit();
  }

  reset() { this.replace(createDefaultProgress()); }

  subscribe(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
}
