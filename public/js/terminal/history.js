export class History {
  constructor() { this.items = []; this.pos = 0; this.draft = ''; }
  push(line) {
    if (line.trim() && this.items[this.items.length - 1] !== line) this.items.push(line);
    this.pos = this.items.length;
    this.draft = '';
  }
  prev(current) {
    if (this.pos === this.items.length) this.draft = current;
    if (this.pos > 0) this.pos--;
    return this.items[this.pos] ?? current;
  }
  next() {
    if (this.pos < this.items.length) this.pos++;
    return this.pos === this.items.length ? this.draft : this.items[this.pos];
  }
}
