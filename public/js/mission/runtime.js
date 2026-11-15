// Builds the playable environment for a mission: machine (+ mission-specific file patch) -> shell.
import { createRuntime, createSession, SessionStack } from '../sim/session.js';
import { createRegistry } from '../commands/index.js';

/** Deep-ish clone of the machine definition with the mission's `fsPatch` merged in. */
export function patchMachine(machineDef, mission) {
  const def = JSON.parse(JSON.stringify(machineDef));
  def.fs = { ...(def.fs || {}), ...(mission.fsPatch || {}) };
  return def;
}

/**
 * `world` is a fresh World for this mission (see loadWorld) or null for no network.
 * `reachableDefs` is { machineId: machineJSON } for every machine named in `mission.reachableMachines`
 * (e.g. [{ ip, machine: 'legacy01' }]) - other hosts a player might land a real shell on mid-mission
 * (an exploited backdoor, a reverse shell). Registered onto the World so any command can push a session
 * for that host (`createSession(world.machineFor(ip), user)`) the moment it earns one.
 */
export function buildMissionShell(mission, machineDef, commandDocs, world = null, reachableDefs = {}) {
  const runtime = createRuntime(patchMachine(machineDef, mission), world);
  const stack = new SessionStack(createSession(runtime, mission.startUser || runtime.def.startUser));
  const registry = createRegistry(commandDocs);
  if (world) {
    for (const { ip, machine } of mission.reachableMachines || []) {
      const def = reachableDefs[machine];
      if (def) world.setMachine(ip, createRuntime(def, world));
    }
  }
  return { runtime, stack, registry };
}
