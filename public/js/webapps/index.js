// Registry of dynamic webapp engines. A webapp JSON file with `"engine": "shopzone"` is routed through
// the matching module's `handle(app, req, state)`. Every engine here follows the same safety rule:
// nothing the player submits is ever executed as code (no eval, no innerHTML elsewhere, no real shell) —
// "vulnerabilities" are modelled as data flowing unescaped/unvalidated through otherwise ordinary JS logic,
// so the lesson (what makes it exploitable) is real even though no actual script or command ever runs.
import { shopzone } from './shopzone.js';

const engines = { shopzone };

export const getEngine = (name) => engines[name] || null;
