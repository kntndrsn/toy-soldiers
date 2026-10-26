/**
 * Toy Soldiers — Ramping k6 WebSocket & Server Profiler Stress Test
 *
 * Simulates concurrent multiplayer rooms (both Sandbox and Shoebox maps),
 * 25 Hz player movement updates, ~15 Hz host AI world-state broadcasts,
 * weapon fire / damage / respawn events, and continuous /api/perf polling
 * to identify the server's scaling breaking point.
 *
 * Usage:
 *   1. Start the server:
 *        node server.js
 *
 *   2. Run the default ramping breaking-point test:
 *        k6 run k6-stress-test.js
 *
 *   3. Customize target URL, scale, or room density:
 *        k6 run -e BASE_URL=http://localhost:3000 -e WS_URL=ws://localhost:3000 -e SCALE=1.0 -e PLAYERS_PER_ROOM=8 k6-stress-test.js
 *
 *   4. Quick smoke test (30 seconds, lower VUs):
 *        k6 run -e SCALE=0.2 -e QUICK=1 k6-stress-test.js
 *
 * Outputs after completion:
 *   - perf-report.json : Combined k6 metrics + /api/perf server profiler JSON (ready for AI review)
 *   - perf-summary.txt : Human-readable breaking-point & bottleneck summary
 */

import http from "k6/http";
import ws from "k6/ws";
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
const BOTS_PER_TEAM = Math.max(2, Math.min(40, Number(__ENV.BOTS_PER_TEAM) || 8));

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

const rampStages = QUICK
  ? [
      { duration: "10s", target: Math.max(4, Math.round(40 * SCALE)) },
      { duration: "15s", target: Math.max(8, Math.round(100 * SCALE)) },
      { duration: "15s", target: Math.max(16, Math.round(200 * SCALE)) },
      { duration: "5s", target: 0 }
    ]
  : [
      { duration: "20s", target: Math.max(8, Math.round(32 * SCALE)) },   // Warmup: ~4 rooms
      { duration: "30s", target: Math.max(16, Math.round(80 * SCALE)) },  // Light load: ~10 rooms
      { duration: "35s", target: Math.max(32, Math.round(160 * SCALE)) }, // Medium load: ~20 rooms
      { duration: "35s", target: Math.max(48, Math.round(280 * SCALE)) }, // Heavy load: ~35 rooms
      { duration: "35s", target: Math.max(64, Math.round(420 * SCALE)) }, // Stress / breaking point: ~52 rooms
      { duration: "15s", target: 0 }                                      // Cooldown
    ];

const totalRampDurationSec = rampStages.reduce((acc, s) => {
  const n = parseInt(s.duration, 10) || 0;
  return acc + n;
}, 0);

export const options = {
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
  thresholds: {
    ws_connect_success: ["rate>0.98"],
    ws_ping_rtt_ms: ["p(95)<150", "p(99)<300"],
    profiler_tick_p95_ms: ["p(95)<15"]
  }
};

// Generates a distinct synthetic IP per VU so single-machine load tests
// don't trip the per-IP connection cap (MAX_CONN_PER_IP = 24), while still
// testing per-client WebSocket message & bandwidth rate limiters.
function getSyntheticIpForVu(vuId) {
  const b2 = Math.floor(vuId / 250) % 250;
  const b3 = (vuId % 250) + 1;
  return `10.42.${b2}.${b3}`;
}

// ============================================================================
// SCENARIO 1: RAMPING WEBSOCKET PLAYER / HOST SESSION
// ============================================================================
export function runPlayerSession() {
  const vuId = __VU;
  const slotInRoom = (vuId - 1) % PLAYERS_PER_ROOM;
  const roomIndex = Math.floor((vuId - 1) / PLAYERS_PER_ROOM);
  const isHostCandidate = slotInRoom === 0;
  const mapType = roomIndex % 2 === 0 ? "sandbox" : "shoebox";
  const worldLimit = mapType === "shoebox" ? 28 : 80;
  const prefix = mapType === "shoebox" ? "SHOE" : "SAND";
  const roomCode = `${prefix}${100 + roomIndex}`;
  const team = slotInRoom % 2 === 0 ? "green" : "tan";
  const playerName = `K6_${vuId}`;
  const syntheticIp = getSyntheticIpForVu(vuId);

  // Brief stagger on initial join when a room is spinning up so the host creates the room first
  if (!isHostCandidate) {
    sleep(0.15 + (slotInRoom % 4) * 0.05);
  }

  const params = {
    headers: {
      "X-Forwarded-For": syntheticIp,
      "X-K6-VU": String(vuId)
    }
  };

  const sessionStart = Date.now();
  const wsTarget = `${WS_URL}/?k6vu=${vuId}`;
  const res = ws.connect(wsTarget, params, function (socket) {
    let myUnitId = `${team}_0`;
    let isRoomHost = isHostCandidate;
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
      const joinPayload = {
        type: isHostCandidate ? "host_room" : "join_room",
        roomCode,
        password: "",
        name: playerName,
        team,
        greenTotal: BOTS_PER_TEAM,
        tanTotal: BOTS_PER_TEAM,
        mapType,
        worldLimit,
        hardcoreMode: roomIndex % 3 === 0,
        durationSec: 600
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

      // Keep each VU session open for 15s before cycling
      socket.setTimeout(function () {
        socket.close();
      }, 15000);
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
        if (typeof msg.clientTime === "number") {
          const rtt = Math.max(0, Date.now() - msg.clientTime);
          wsPingRttMs.add(rtt);
        }
        if (typeof msg.serverTickMs === "number") {
          wsServerTickMs.add(msg.serverTickMs);
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
      }
    });
  });

  const ok = check(res, {
    "WebSocket handshake status is 101": (r) => r && r.status === 101
  });
  wsConnectSuccess.add(ok);

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
        profTickAvgMs.add(p.server.tickAvgMs || 0);
        profTickP95Ms.add(p.server.tickP95Ms || 0);
        profTickMaxMs.add(p.server.tickMaxMs || 0);
        profOutboundKBps.add(p.network.outboundKBPerSec || 0);
        profInboundKBps.add(p.network.inboundKBPerSec || 0);
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
          `[PROFILER] Rooms: ${p.scalingSummary.activeRooms} | ` +
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

  sleep(5);
}

// ============================================================================
// END-OF-TEST SUMMARY & AI PROFILER REPORT GENERATOR
// ============================================================================
function numMetric(data, name, stat) {
  const m = data && data.metrics && data.metrics[name];
  if (!m || !m.values || typeof m.values[stat] !== "number") return null;
  return Number(m.values[stat].toFixed(2));
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

  const combinedReport = {
    generatedAt: new Date().toISOString(),
    target: { baseUrl: BASE_URL, wsUrl: WS_URL, scale: SCALE, playersPerRoom: PLAYERS_PER_ROOM, botsPerTeam: BOTS_PER_TEAM },
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

  const lines = [
    "================================================================================",
    " TOY SOLDIERS — K6 RAMPING STRESS TEST & PROFILER REPORT",
    "================================================================================",
    ` Target Server          : ${BASE_URL} (${WS_URL})`,
    ` Room Config            : ${PLAYERS_PER_ROOM} human VUs/room, ${BOTS_PER_TEAM}v${BOTS_PER_TEAM} units/room`,
    ` WS Connect Success     : ${((combinedReport.k6Summary.wsConnectSuccessRate || 0) * 100).toFixed(1)}%`,
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
