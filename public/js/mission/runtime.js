// Builds the playable environment for a mission: machine (+ mission-specific file patch) -> shell.
import { createRuntime, createSession, SessionStack } from '../sim/session.js';
import { createRegistry } from '../commands/index.js';

/** Deep-ish clone of the machine definition with the mission's `fsPatch` merged in. */
export function patchMachine(machineDef, mission) {
  const def = JSON.parse(JSON.stringify(machineDef));
  def.fs = { ...(def.fs || {}), ...(mission.fsPatch || {}) };
  return def;
}

/** `world` is a fresh World for this mission (see loadWorld) or null for no network. */
export function buildMissionShell(mission, machineDef, commandDocs, world = null) {
  const runtime = createRuntime(patchMachine(machineDef, mission), world);
  const stack = new SessionStack(createSession(runtime, mission.startUser || runtime.def.startUser));
  const registry = createRegistry(commandDocs);
  return { runtime, stack, registry };
}
