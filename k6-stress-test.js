/**
 * Toy Soldiers — Aggressive Step-Ramp k6 Capacity / Regression Test
 *
 * Simulates concurrent multiplayer rooms (both Sandbox and Shoebox maps),
 * 25 Hz player movement updates, ~15 Hz host AI world-state broadcasts,
 * weapon fire / damage / respawn events, and continuous /api/perf polling.
 *
 * Load is added in fast steps (short ramp + short hold per step). Each step's
 * hold window is tagged `step:N`, so the end-of-test report shows game
 * responsiveness (WS ping RTT p95, server tick p95, connect success) per
 * load level and reports the MAX number of simulated units (bots) the server
 * sustained before the game slowed down too much.
 *
 * A step is "healthy" when ALL of these hold during its measurement window:
 *   - WS ping RTT p95   <= RTT_LIMIT_MS   (default 150)
 *   - Server tick p95   <= TICK_LIMIT_MS  (default 40)
 *   - WS connect rate   >= 98%
 *
 * Once a step's RTT p95 exceeds ABORT_RTT_MS (default 4x RTT_LIMIT_MS) the
 * test aborts early so we stop hammering a server that is clearly past its
 * breaking point. k6 exits with code 99 in that case; the capacity report is
 * still written.
 *
 * Usage:
 *   1. Run the default capacity test (12 steps, 1 → 128 rooms of 64v64 bots, ~4 min):
 *        k6 run k6-stress-test.js
 *
 *   2. Regression gate — fail (non-zero exit) if the server can no longer
 *      sustain at least N units within the limits:
 *        k6 run -e MIN_UNITS=4096 k6-stress-test.js
 *
 *   3. Customize target, room density, steps, and limits:
 *        k6 run -e BASE_URL=http://localhost:3000 -e PLAYERS_PER_ROOM=8 -e BOTS_PER_TEAM=64 \
 *               -e STEP_ROOMS=4,8,16,32,64 -e STEP_RAMP_SEC=5 -e STEP_HOLD_SEC=15 \
 *               -e RTT_LIMIT_MS=150 -e TICK_LIMIT_MS=40 -e ABORT_RTT_MS=0 k6-stress-test.js
 *      (ABORT_RTT_MS=0 disables the early abort; SCALE multiplies the room count of every step.)
 *
 *   4. Quick smoke test (~45 seconds, 1 → 8 rooms):
 *        k6 run -e QUICK=1 k6-stress-test.js
 *
 * Note: at high step counts the k6 machine itself must send/receive a lot of
 * traffic (every VU receives the 25 Hz room_tick with all bots). If the load
 * generator saturates its CPU or network first, RTT rises for reasons that are
 * not the server's fault — watch the k6 host's resources during big runs.
 *
 * Outputs after completion:
 *   - perf-report.json : Combined k6 metrics, per-step capacity results + /api/perf snapshot
 *   - perf-summary.txt : Human-readable capacity / breaking-point summary
 */

import http from "k6/http";
import ws from "k6/ws";
import exec from "k6/execution";
import { check, sleep } from "k6";
import { Counter, Gauge, Rate, Trend } from "k6/metrics";

const BASE_URL = (
  __ENV.BASE_URL || "https://toy-soldiers.duckdns.org"
).replace(/\/+$/, "");
const WS_URL = (
  __ENV.WS_URL || BASE_URL.replace(/^http/i, "ws")
).replace(/\/+$/, "");
const SCALE = Math.max(0.05, Number(__ENV.SCALE) || 1.0);
const QUICK = Boolean(__ENV.QUICK);
const PLAYERS_PER_ROOM = Math.max(2, Math.min(24, Number(__ENV.PLAYERS_PER_ROOM) || 8));
const BOTS_PER_TEAM = Math.max(2, Math.min(64, Number(__ENV.BOTS_PER_TEAM) || 64));

// Health limits that define "the game has slowed down too much"
const RTT_LIMIT_MS = Number(__ENV.RTT_LIMIT_MS) || 150;
const TICK_LIMIT_MS = Number(__ENV.TICK_LIMIT_MS) || 40;
const MIN_CONNECT_RATE = 0.98;
const ABORT_RTT_MS =
  __ENV.ABORT_RTT_MS !== undefined && __ENV.ABORT_RTT_MS !== ""
    ? Math.max(0, Number(__ENV.ABORT_RTT_MS) || 0)
    : RTT_LIMIT_MS * 4;
const MIN_UNITS = Math.max(0, Number(__ENV.MIN_UNITS) || 0);

// Server counts greenTotal + tanTotal per room; a team expands if more humans join than bots requested
const UNITS_PER_ROOM = 2 * Math.max(BOTS_PER_TEAM, Math.ceil(PLAYERS_PER_ROOM / 2));

// Custom k6 Metrics for Pinpointing the Breaking Point
const wsConnectSuccess = new Rate("ws_connect_success");
const wsPingRttMs = new Trend("ws_ping_rtt_ms", true);
const wsServerTickMs = new Trend("ws_server_tick_ms", true);
const wsServerMemMb = new Gauge("ws_server_mem_mb");
const wsMessagesSent = new Counter("ws_messages_sent");
const wsMessagesReceived = new Counter("ws_messages_received");

// Polled /api/perf Server Profiler Metrics
const profTickAvgMs = new Trend("profiler_tick_avg_ms", true);
const profTickP95Ms = new Trend("profiler_tick_p95_ms", true);
const profTickMaxMs = new Trend("profiler_tick_max_ms", true);
const profOutboundKBps = new Trend("profiler_outbound_kbps");
const profInboundKBps = new Trend("profiler_inbound_kbps");
const profActiveRooms = new Gauge("profiler_active_rooms");
const profOnlinePlayers = new Gauge("profiler_online_players");
const profDroppedMsgs = new Gauge("profiler_ddos_dropped_msgs");
const profUnits = new Trend("profiler_units");

// ============================================================================
// AGGRESSIVE STEP RAMP PLAN
// ============================================================================
const DEFAULT_STEP_ROOMS = QUICK
  ? [1, 2, 4, 8]
  : [1, 2, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128];
const STEP_RAMP_SEC = Math.max(1, Math.floor(Number(__ENV.STEP_RAMP_SEC) || (QUICK ? 3 : 5)));
const STEP_HOLD_SEC = Math.max(2, Math.floor(Number(__ENV.STEP_HOLD_SEC) || (QUICK ? 7 : 15)));
// Ignore the start of each hold while new rooms finish joining
const STEP_SETTLE_SEC = Math.min(5, Math.floor(STEP_HOLD_SEC / 2));
const COOLDOWN_SEC = QUICK ? 5 : 10;

const requestedStepRooms = __ENV.STEP_ROOMS
  ? String(__ENV.STEP_ROOMS)
      .split(",")
      .map((v) => Number(v.trim()))
      .filter((v) => Number.isFinite(v) && v > 0)
  : DEFAULT_STEP_ROOMS;

const stepRooms = [];
for (const r of requestedStepRooms) {
  const rooms = Math.max(1, Math.round(r * SCALE));
  if (stepRooms.length === 0 || rooms > stepRooms[stepRooms.length - 1]) {
    stepRooms.push(rooms);
  }
}
if (stepRooms.length === 0) {
  throw new Error("STEP_ROOMS produced no valid load steps");
}

const STEP_SPAN_SEC = STEP_RAMP_SEC + STEP_HOLD_SEC;
const loadSteps = stepRooms.map((rooms, i) => {
  const startSec = i * STEP_SPAN_SEC;
  return {
    step: i + 1,
    rooms,
    vus: rooms * PLAYERS_PER_ROOM,
    expectedUnits: rooms * UNITS_PER_ROOM,
    startSec,
    measureFromSec: startSec + STEP_RAMP_SEC + STEP_SETTLE_SEC,
    measureToSec: startSec + STEP_SPAN_SEC
  };
});

const rampStages = [];
for (const s of loadSteps) {
  rampStages.push({ duration: `${STEP_RAMP_SEC}s`, target: s.vus });
  rampStages.push({ duration: `${STEP_HOLD_SEC}s`, target: s.vus });
}
rampStages.push({ duration: `${COOLDOWN_SEC}s`, target: 0 });

const totalRampDurationSec = loadSteps.length * STEP_SPAN_SEC + COOLDOWN_SEC;

function elapsedSec() {
  return (Date.now() - exec.scenario.startTime) / 1000;
}

// Returns { step: "N" } tags for the load step active at `sec`.
// measureOnly = true restricts to the steady-state measurement window of each step.
function stepTagsAt(sec, measureOnly) {
  for (const s of loadSteps) {
    const from = measureOnly ? s.measureFromSec : s.startSec;
    if (sec >= from && sec < s.measureToSec) {
      return { step: String(s.step) };
    }
  }
  return undefined;
}

// Per-step submetric thresholds: these expose per-step stats to handleSummary,
// abort once a step is clearly broken, and optionally enforce the MIN_UNITS regression gate.
const thresholds = {};
for (const s of loadSteps) {
  const tag = `{step:${s.step}}`;
  thresholds[`ws_ping_rtt_ms${tag}`] =
    ABORT_RTT_MS > 0
      ? [{ threshold: `p(95)<${ABORT_RTT_MS}`, abortOnFail: true, delayAbortEval: "5s" }]
      : ["p(95)>=0"];
  thresholds[`ws_server_tick_ms${tag}`] = ["p(95)>=0"];
  thresholds[`ws_connect_success${tag}`] = ["rate>=0"];
  thresholds[`profiler_units${tag}`] = ["max>=0"];
  thresholds[`profiler_outbound_kbps${tag}`] = ["max>=0"];
}

const gateStep = MIN_UNITS > 0 ? loadSteps.find((s) => s.expectedUnits >= MIN_UNITS) : null;
if (MIN_UNITS > 0) {
  if (!gateStep) {
    throw new Error(
      `MIN_UNITS=${MIN_UNITS} exceeds the largest step (${loadSteps[loadSteps.length - 1].expectedUnits} units); add bigger STEP_ROOMS`
    );
  }
  const tag = `{step:${gateStep.step}}`;
  thresholds[`ws_ping_rtt_ms${tag}`].push(`p(95)<${RTT_LIMIT_MS}`);
  thresholds[`ws_server_tick_ms${tag}`].push(`p(95)<${TICK_LIMIT_MS}`);
  thresholds[`ws_connect_success${tag}`].push(`rate>=${MIN_CONNECT_RATE}`);
}

export const options = {
  summaryTrendStats: ["avg", "min", "med", "max", "p(90)", "p(95)", "p(99)", "count"],
  scenarios: {
    // Scenario 1: Ramping WebSocket Players & Room Hosts
    ramping_players: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: rampStages,
      gracefulRampDown: "5s",
      exec: "runPlayerSession"
    },
    // Scenario 2: Dedicated /api/perf Poller to capture server telemetry across the ramp
    profiler_monitor: {
      executor: "constant-vus",
      vus: 1,
      duration: `${totalRampDurationSec}s`,
      exec: "pollServerProfiler"
    }
  },
  thresholds
};

// Generates a distinct synthetic IP per VU so single-machine load tests
// don't trip the per-IP connection cap (MAX_CONN_PER_IP = 24), while still
// testing per-client WebSocket message & bandwidth rate limiters.
function getSyntheticIpForVu(vuId) {
  const b2 = Math.floor(vuId / 250) % 250;
  const b3 = (vuId % 250) + 1;
  return `10.42.${b2}.${b3}`;
}

// Unique per-run tag so room codes never collide with rooms left over from a
// previous run (empty rooms live on the server until their match timer ends).
export function setup() {
  const runTag = Math.floor(Math.random() * 36 ** 3)
    .toString(36)
    .toUpperCase()
    .padStart(3, "0");
  return { runTag };
}

// ============================================================================
// SCENARIO 1: RAMPING WEBSOCKET PLAYER / HOST SESSION
// ============================================================================
export function runPlayerSession(data) {
  const vuId = __VU;
  const slotInRoom = (vuId - 1) % PLAYERS_PER_ROOM;
  const roomIndex = Math.floor((vuId - 1) / PLAYERS_PER_ROOM);
  const mapType = roomIndex % 2 === 0 ? "sandbox" : "shoebox";
  const worldLimit = mapType === "shoebox" ? 28 : 80;
  const prefix = mapType === "shoebox" ? "SHOE" : "SAND";
  const roomCode = `${prefix}${(data && data.runTag) || "K6"}${roomIndex}`;
  const team = slotInRoom % 2 === 0 ? "green" : "tan";
  const playerName = `K6_${vuId}`;
  const syntheticIp = getSyntheticIpForVu(vuId);

  const params = {
    headers: {
      "X-Forwarded-For": syntheticIp,
      "X-K6-VU": String(vuId)
    }
  };

  const sessionStart = Date.now();
  const connectTags = stepTagsAt(elapsedSec(), false);
  let opened = false;
  const wsTarget = `${WS_URL}/?k6vu=${vuId}`;
  const res = ws.connect(wsTarget, params, function (socket) {
    let myUnitId = `${team}_0`;
    // Whichever VU reaches the room first creates it and becomes host (confirmed via room_joined)
    let isRoomHost = false;
    let activeRoomCode = roomCode;
    let tickStep = 0;

    // Pre-build compact quantized AI array for host_world_state broadcasts
    const totalAi = Math.max(2, BOTS_PER_TEAM * 2 - PLAYERS_PER_ROOM);
    const aiPackedTemplate = [];
    for (let i = 0; i < totalAi; i++) {
      const aiTeam = i % 2 === 0 ? "green" : "tan";
      const aiIdx = Math.floor(i / 2) + 1;
      aiPackedTemplate.push([
        `${aiTeam}_${aiIdx}`,
        (i * 310) % 2000 - 1000,
        0,
        (i * 470) % 2000 - 1000,
        150,
        0,
        85,
        25,
        1
      ]);
    }

    socket.on("open", function () {
      // Record on open (not after ws.connect returns) so sessions cut short by an abort still count
      opened = true;
      wsConnectSuccess.add(true, connectTags);

      // Every VU uses join_room: the server creates the room for the first arrival.
      // host_room would allocate a random code if a joiner got there first, splitting the room in two.
      const joinPayload = {
        type: "join_room",
        roomCode,
        password: "",
        name: playerName,
        team,
        greenTotal: BOTS_PER_TEAM,
        tanTotal: BOTS_PER_TEAM,
        mapType,
        worldLimit,
        hardcoreMode: roomIndex % 3 === 0,
        aiSkill: "intermediate",
        // Long enough to outlive the run, short enough that empty rooms are cleaned up soon after
        durationSec: Math.min(1800, totalRampDurationSec + 60)
      };
      socket.send(JSON.stringify(joinPayload));
      wsMessagesSent.add(1);

      // 1. 25 Hz (40ms) Player Movement Updates (stays below 100 msg/s DDoS threshold)
      socket.setInterval(function () {
        tickStep++;
        const angle = tickStep * 0.08 + vuId;
        const radius = mapType === "shoebox" ? 14 : 35;
        socket.send(
          JSON.stringify({
            type: "player_state",
            x: Math.cos(angle) * radius,
            y: 0,
            z: Math.sin(angle) * radius,
            yaw: angle,
            pitch: 0.05,
            moveBlend: 1,
            strideDir: 0.5
          })
        );
        wsMessagesSent.add(1);
      }, 40);

      // 2. ~14 Hz (70ms) Host AI World State Broadcasts (only if this VU is the Room Host)
      socket.setInterval(function () {
        if (!isRoomHost) return;
        socket.send(
          JSON.stringify({
            type: "host_world_state",
            aiPacked: aiPackedTemplate,
            ball:
              mapType === "sandbox"
                ? { x: 10, y: 1.85, z: -4, vx: 0.5, vy: 0, vz: -0.3 }
                : null
          })
        );
        wsMessagesSent.add(1);
      }, 70);

      // 3. Weapon Fire & Combat Damage Events (~2 Hz per player)
      socket.setInterval(function () {
        socket.send(
          JSON.stringify({
            type: "fire_shot",
            shooterUnitId: myUnitId,
            team,
            muzzlePos: { x: 0, y: 1.5, z: 0 },
            hitPoint: { x: 4, y: 1.2, z: 8 },
            hitKind: team === "green" ? "tan" : "green"
          })
        );
        wsMessagesSent.add(1);

        if (tickStep % 5 === 0) {
          const enemyTeam = team === "green" ? "tan" : "green";
          const targetId = `${enemyTeam}_${slotInRoom % BOTS_PER_TEAM}`;
          socket.send(
            JSON.stringify({
              type: "damage_unit",
              targetUnitId: targetId,
              attackerUnitId: myUnitId,
              amount: 34,
              shotDir: { x: 0, y: 0, z: 1 }
            })
          );
          wsMessagesSent.add(1);
        }
      }, 500);

      // 4. Ping + Client Perf Telemetry (~0.8 Hz)
      socket.setInterval(function () {
        socket.send(
          JSON.stringify({
            type: "ping",
            clientTime: Date.now(),
            clientPerf: {
              clientId: `k6_${vuId}`,
              mode: "multiplayer",
              roomCode: activeRoomCode,
              mapType,
              fps: 60,
              frameMs: 16.6,
              renderMs: 2.1,
              physicsMs: 0.4,
              aiMs: 0.6,
              animMs: 0.5,
              aliveUnits: BOTS_PER_TEAM * 2,
              totalUnits: BOTS_PER_TEAM * 2
            }
          })
        );
        wsMessagesSent.add(1);
      }, 1200);

      // Keep each VU session open until the end of the ramp so rooms stay populated
      socket.setTimeout(function () {
        socket.close();
      }, Math.max(1, totalRampDurationSec - elapsedSec()) * 1000);
    });

    socket.on("message", function (raw) {
      wsMessagesReceived.add(1);
      let msg;
      try {
        msg = JSON.parse(raw);
      } catch {
        return;
      }

      if (msg.type === "room_joined") {
        myUnitId = msg.unitId || myUnitId;
        isRoomHost = Boolean(msg.isHost);
        if (msg.roster && msg.roster.roomCode) {
          activeRoomCode = msg.roster.roomCode;
        }
      } else if (msg.type === "pong") {
        const tags = stepTagsAt(elapsedSec(), true);
        if (typeof msg.clientTime === "number") {
          const rtt = Math.max(0, Date.now() - msg.clientTime);
          wsPingRttMs.add(rtt, tags);
        }
        if (typeof msg.serverTickMs === "number") {
          wsServerTickMs.add(msg.serverTickMs, tags);
        }
        if (typeof msg.serverMemMB === "number") {
          wsServerMemMb.add(msg.serverMemMB);
        }
      } else if (
        msg.type === "unit_damaged" &&
        msg.targetUnitId === myUnitId &&
        msg.killed
      ) {
        // Respawn self if knocked down
        socket.send(
          JSON.stringify({
            type: "respawn_unit",
            unitId: myUnitId,
            team,
            isAI: false,
            x: 0,
            y: 0,
            z: team === "green" ? -20 : 20,
            yaw: 0
          })
        );
        wsMessagesSent.add(1);
      } else if (msg.type === "room_tick" && Array.isArray(msg.damages)) {
        for (let i = 0; i < msg.damages.length; i++) {
          const d = msg.damages[i];
          if (d.targetUnitId === myUnitId && d.killed) {
            socket.send(
              JSON.stringify({
                type: "respawn_unit",
                unitId: myUnitId,
                team,
                isAI: false,
                x: 0,
                y: 0,
                z: team === "green" ? -20 : 20,
                yaw: 0
              })
            );
            wsMessagesSent.add(1);
            break;
          }
        }
      }
    });
  });

  check(res, {
    "WebSocket handshake status is 101": (r) => r && r.status === 101
  });
  if (!opened) {
    wsConnectSuccess.add(false, connectTags);
  }

  // Prevent 0ms tight reconnect spin if the server or proxy closes the socket early
  if (Date.now() - sessionStart < 1000) {
    sleep(1);
  }
}

// ============================================================================
// SCENARIO 2: CONTINUOUS /api/perf PROFILER POLLER
// ============================================================================
export function pollServerProfiler() {
  const res = http.get(`${BASE_URL}/api/perf?k6vu=poller`, {
    headers: {
      "X-Forwarded-For": "10.254.254.1",
      "X-K6-VU": "poller"
    },
    timeout: "5s"
  });

  if (res.status === 200) {
    try {
      const p = JSON.parse(res.body);
      if (p && p.server && p.network && p.scalingSummary) {
        const tags = stepTagsAt(elapsedSec(), true);
        profTickAvgMs.add(p.server.tickAvgMs || 0);
        profTickP95Ms.add(p.server.tickP95Ms || 0);
        profTickMaxMs.add(p.server.tickMaxMs || 0);
        profOutboundKBps.add(p.network.outboundKBPerSec || 0, tags);
        profInboundKBps.add(p.network.inboundKBPerSec || 0);
        profUnits.add(p.scalingSummary.totalSimulatedUnits || 0, tags);
        profActiveRooms.add(p.scalingSummary.activeRooms || 0);
        profOnlinePlayers.add(p.scalingSummary.totalOnlinePlayers || 0);
        profDroppedMsgs.add(
          (p.ddosProtection && p.ddosProtection.droppedMessages) || 0
        );

        const warn =
          p.server.tickP95Ms > 10
            ? " [!] HIGH SERVER TICK"
            : p.ddosProtection && p.ddosProtection.droppedMessages > 0
            ? " [!] DDOS DROPS"
            : "";

        console.log(
          `[PROFILER] Step: ${tags ? tags.step : "-"}/${loadSteps.length} | ` +
            `Rooms: ${p.scalingSummary.activeRooms} | ` +
            `Players: ${p.scalingSummary.totalOnlinePlayers} | ` +
            `Units: ${p.scalingSummary.totalSimulatedUnits} | ` +
            `Tick avg/p95/max: ${p.server.tickAvgMs}/${p.server.tickP95Ms}/${p.server.tickMaxMs} ms | ` +
            `Net In/Out: ${p.network.inboundKBPerSec}/${p.network.outboundKBPerSec} KB/s ` +
            `(${p.network.inboundPktPerSec}/${p.network.outboundPktPerSec} pkt/s) | ` +
            `RSS: ${p.server.rssMB} MB${warn}`
        );
      }
    } catch {
      // Ignore parse errors
    }
  }

  sleep(3);
}

// ============================================================================
// END-OF-TEST SUMMARY & AI PROFILER REPORT GENERATOR
// ============================================================================
function numMetric(data, name, stat) {
  const m = data && data.metrics && data.metrics[name];
  if (!m || !m.values || typeof m.values[stat] !== "number") return null;
  return Number(m.values[stat].toFixed(2));
}

function analyzeCapacity(data) {
  const steps = [];
  let maxHealthy = null;
  let breaking = null;

  for (const s of loadSteps) {
    const sub = (name, stat) => numMetric(data, `${name}{step:${s.step}}`, stat);
    const rttCount = sub("ws_ping_rtt_ms", "count") || 0;
    const connectPasses = sub("ws_connect_success", "passes") || 0;
    const connectFails = sub("ws_connect_success", "fails") || 0;
    const connectRate =
      connectPasses + connectFails > 0 ? connectPasses / (connectPasses + connectFails) : null;
    const measuredUnits = sub("profiler_units", "max");

    const result = {
      step: s.step,
      rooms: s.rooms,
      vus: s.vus,
      expectedUnits: s.expectedUnits,
      measuredUnits: measuredUnits || null,
      rttSamples: rttCount,
      rttAvgMs: sub("ws_ping_rtt_ms", "avg"),
      rttP95Ms: sub("ws_ping_rtt_ms", "p(95)"),
      rttP99Ms: sub("ws_ping_rtt_ms", "p(99)"),
      serverTickP95Ms: sub("ws_server_tick_ms", "p(95)"),
      connectRate: connectRate === null ? null : Number(connectRate.toFixed(4)),
      outboundKBpsMax: sub("profiler_outbound_kbps", "max"),
      status: "not reached",
      reasons: []
    };

    if (rttCount > 0) {
      if (result.rttP95Ms > RTT_LIMIT_MS) {
        result.reasons.push(`RTT p95 ${result.rttP95Ms}ms > ${RTT_LIMIT_MS}ms`);
      }
      if (result.serverTickP95Ms !== null && result.serverTickP95Ms > TICK_LIMIT_MS) {
        result.reasons.push(`tick p95 ${result.serverTickP95Ms}ms > ${TICK_LIMIT_MS}ms`);
      }
      if (connectRate !== null && connectRate < MIN_CONNECT_RATE) {
        result.reasons.push(`connect ${(connectRate * 100).toFixed(1)}% < ${MIN_CONNECT_RATE * 100}%`);
      }
      result.status = result.reasons.length === 0 ? "healthy" : "degraded";
    } else if (connectPasses + connectFails > 0) {
      result.status = "no data";
      result.reasons.push("no pong samples in measurement window");
    }

    if (!breaking) {
      if (result.status === "healthy") {
        maxHealthy = result;
      } else if (result.status !== "not reached") {
        breaking = result;
      }
    }
    steps.push(result);
  }

  // Headline uses the units this test drove; measuredUnits is the server-wide total and
  // can include real players' rooms or empty rooms left over from earlier runs.
  const unitsOf = (r) => (r ? r.expectedUnits : 0);
  return {
    limits: {
      rttP95Ms: RTT_LIMIT_MS,
      serverTickP95Ms: TICK_LIMIT_MS,
      minConnectRate: MIN_CONNECT_RATE,
      abortRttP95Ms: ABORT_RTT_MS || null
    },
    unitsPerRoom: UNITS_PER_ROOM,
    maxSustainedUnits: unitsOf(maxHealthy),
    maxSustainedStep: maxHealthy,
    breakingStep: breaking,
    breakingPointReached: Boolean(breaking),
    regressionGate:
      MIN_UNITS > 0
        ? {
            minUnits: MIN_UNITS,
            gateStep: gateStep.step,
            passed: unitsOf(maxHealthy) >= gateStep.expectedUnits
          }
        : null,
    steps
  };
}

function fmt(v, suffix) {
  return v === null || v === undefined ? "-" : `${v}${suffix || ""}`;
}

export function handleSummary(data) {
  let finalServerPerf = null;
  try {
    const res = http.get(`${BASE_URL}/api/perf`, {
      headers: { "X-Forwarded-For": "10.254.254.2" },
      timeout: "5s"
    });
    if (res.status === 200) {
      finalServerPerf = JSON.parse(res.body);
    }
  } catch {
    // Server may be unreachable if it crashed at the breaking point
  }

  // Analyze history from /api/perf to find peak load & any degradation point
  const history = (finalServerPerf && finalServerPerf.history) || [];
  let peakOutboundKBps = 0;
  let peakInboundPkts = 0;
  let peakOutboundPkts = 0;
  let peakRooms = 0;
  let peakTickMs = 0;
  let peakRssMB = 0;

  for (let i = 0; i < history.length; i++) {
    const h = history[i];
    if ((h.outboundKBPerSec || 0) > peakOutboundKBps) peakOutboundKBps = h.outboundKBPerSec;
    if ((h.inboundPktPerSec || 0) > peakInboundPkts) peakInboundPkts = h.inboundPktPerSec;
    if ((h.outboundPktPerSec || 0) > peakOutboundPkts) peakOutboundPkts = h.outboundPktPerSec;
    if ((h.activeRooms || 0) > peakRooms) peakRooms = h.activeRooms;
    if ((h.tickMs || 0) > peakTickMs) peakTickMs = h.tickMs;
    if ((h.rssMB || 0) > peakRssMB) peakRssMB = h.rssMB;
  }

  const capacity = analyzeCapacity(data);

  const combinedReport = {
    generatedAt: new Date().toISOString(),
    target: {
      baseUrl: BASE_URL,
      wsUrl: WS_URL,
      scale: SCALE,
      playersPerRoom: PLAYERS_PER_ROOM,
      botsPerTeam: BOTS_PER_TEAM,
      stepRampSec: STEP_RAMP_SEC,
      stepHoldSec: STEP_HOLD_SEC
    },
    capacity,
    k6Summary: {
      wsConnectSuccessRate: numMetric(data, "ws_connect_success", "rate"),
      wsPingRttAvgMs: numMetric(data, "ws_ping_rtt_ms", "avg"),
      wsPingRttP95Ms: numMetric(data, "ws_ping_rtt_ms", "p(95)"),
      wsPingRttMaxMs: numMetric(data, "ws_ping_rtt_ms", "max"),
      serverTickAvgMs: numMetric(data, "profiler_tick_avg_ms", "avg"),
      serverTickP95Ms: numMetric(data, "profiler_tick_p95_ms", "p(95)"),
      serverTickMaxMs: numMetric(data, "profiler_tick_max_ms", "max"),
      outboundKBpsAvg: numMetric(data, "profiler_outbound_kbps", "avg"),
      outboundKBpsMax: numMetric(data, "profiler_outbound_kbps", "max"),
      inboundKBpsMax: numMetric(data, "profiler_inbound_kbps", "max"),
      totalWsMsgsSent: numMetric(data, "ws_messages_sent", "count"),
      totalWsMsgsReceived: numMetric(data, "ws_messages_received", "count")
    },
    peakObservedFromProfilerHistory: {
      peakRooms,
      peakInboundPkts,
      peakOutboundPkts,
      peakOutboundKBps,
      peakTickMs,
      peakRssMB
    },
    serverProfilerSnapshot: finalServerPerf
  };

  const reportJson = JSON.stringify(combinedReport, null, 2);

  // Also upload the finished report to the server's /api/perf/report endpoint
  // so that even when k6 is run from a separate PC, the AI can pull the report directly!
  try {
    http.post(`${BASE_URL}/api/perf/report?k6vu=summary`, reportJson, {
      headers: {
        "Content-Type": "application/json",
        "X-K6-VU": "summary"
      },
      timeout: "5s"
    });
  } catch {
    // Ignore if server is unreachable
  }

  const ms = capacity.maxSustainedStep;
  const bp = capacity.breakingStep;
  const stepLines = capacity.steps.map(
    (r) =>
      `   ${String(r.step).padStart(4)} ${String(r.rooms).padStart(6)} ${String(r.vus).padStart(6)} ` +
      `${String(r.expectedUnits).padStart(7)} ${fmt(r.rttP95Ms).padStart(9)} ` +
      `${fmt(r.serverTickP95Ms).padStart(9)} ` +
      `${(r.connectRate === null ? "-" : (r.connectRate * 100).toFixed(1) + "%").padStart(8)} ` +
      `${fmt(r.outboundKBpsMax).padStart(10)}  ${r.status}${r.reasons.length ? " (" + r.reasons.join("; ") + ")" : ""}`
  );

  const lines = [
    "================================================================================",
    " TOY SOLDIERS — K6 AGGRESSIVE STEP-RAMP CAPACITY REPORT",
    "================================================================================",
    ` Target Server          : ${BASE_URL} (${WS_URL})`,
    ` Room Config            : ${PLAYERS_PER_ROOM} human VUs/room, ${BOTS_PER_TEAM}v${BOTS_PER_TEAM} bots/room (${UNITS_PER_ROOM} units/room)`,
    ` Health Limits          : RTT p95 <= ${RTT_LIMIT_MS}ms, server tick p95 <= ${TICK_LIMIT_MS}ms, connect >= ${MIN_CONNECT_RATE * 100}%`,
    "--------------------------------------------------------------------------------",
    ` MAX SUSTAINED LOAD     : ${
      ms
        ? `${capacity.maxSustainedUnits} units (${ms.rooms} rooms, ${ms.vus} VUs) at step ${ms.step}`
        : "none — the very first step was already degraded"
    }`,
    ` BREAKING POINT         : ${
      bp
        ? `step ${bp.step} — ${bp.expectedUnits} units (${bp.rooms} rooms): ${bp.reasons.join("; ")}`
        : "not reached — server stayed healthy at every step; add bigger STEP_ROOMS to push further"
    }`,
    ...(capacity.regressionGate
      ? [
          ` REGRESSION GATE        : ${capacity.regressionGate.passed ? "PASS" : "FAIL"} (need >= ${MIN_UNITS} units, gate step ${capacity.regressionGate.gateStep})`
        ]
      : []),
    "--------------------------------------------------------------------------------",
    "   Step  Rooms    VUs   Units   RTT p95  Tick p95  Connect   Out KB/s  Status",
    ...stepLines,
    "--------------------------------------------------------------------------------",
    ` WS Connect Success     : ${
      combinedReport.k6Summary.wsConnectSuccessRate === null
        ? "-"
        : (combinedReport.k6Summary.wsConnectSuccessRate * 100).toFixed(1) + "%"
    }`,
    ` WS Ping RTT (avg/p95)  : ${combinedReport.k6Summary.wsPingRttAvgMs} ms / ${combinedReport.k6Summary.wsPingRttP95Ms} ms (max ${combinedReport.k6Summary.wsPingRttMaxMs} ms)`,
    ` Server Tick (avg/p95)  : ${combinedReport.k6Summary.serverTickAvgMs} ms / ${combinedReport.k6Summary.serverTickP95Ms} ms (max ${combinedReport.k6Summary.serverTickMaxMs} ms)`,
    ` Peak Outbound Bandwidth: ${combinedReport.k6Summary.outboundKBpsMax} KB/s (avg ${combinedReport.k6Summary.outboundKBpsAvg} KB/s)`,
    ` Peak Inbound Bandwidth : ${combinedReport.k6Summary.inboundKBpsMax} KB/s`,
    ` Total WS Packets       : ${combinedReport.k6Summary.totalWsMsgsSent} sent / ${combinedReport.k6Summary.totalWsMsgsReceived} received`,
    "--------------------------------------------------------------------------------",
    " SERVER MESSAGE HANDLER PROFILING (/api/perf):",
    ...(finalServerPerf && finalServerPerf.messageProfiling
      ? Object.entries(finalServerPerf.messageProfiling).map(
          ([type, st]) =>
            `   - ${type.padEnd(18)} : count=${String(st.count).padEnd(8)} avg=${st.avgMs}ms  max=${st.maxMs}ms  total=${st.totalMs}ms`
        )
      : ["   (No final /api/perf snapshot available)"]),
    "--------------------------------------------------------------------------------",
    ` Published report to    : ${BASE_URL}/api/perf/report`,
    " Saved local report to  : perf-report.json",
    "================================================================================",
    ""
  ];

  const summaryText = lines.join("\n");

  return {
    stdout: summaryText,
    "perf-report.json": reportJson,
    "perf-summary.txt": summaryText
  };
}
