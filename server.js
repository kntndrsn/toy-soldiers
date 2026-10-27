const http = require("http");
const fs = require("fs");
const path = require("path");
const { WebSocketServer, WebSocket } = require("ws");

const PORT = process.env.PORT || 3000;
const INDEX_PATH = path.join(__dirname, "index.html");
const FAVICON_DIR = path.join(__dirname, "favicon");
const MODELS_DIR = path.join(__dirname, "models");
const MATERIALS_DIR = path.join(__dirname, "materials");
const GEOMETRY_DIR = path.join(__dirname, "geometry");
const PARTICLES_DIR = path.join(__dirname, "particles");
const GUI_DIR = path.join(__dirname, "gui");
const FLOWGRAPHS_DIR = path.join(__dirname, "flowgraphs");

const FAVICON_MIME_TYPES = {
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json",
  ".glb": "model/gltf-binary"
};

const FAVICON_FILES = new Set([
  "favicon-96x96.png",
  "favicon.svg",
  "favicon.ico",
  "apple-touch-icon.png",
  "site.webmanifest",
  "web-app-manifest-192x192.png",
  "web-app-manifest-512x512.png"
]);

const MODEL_FILES = new Set([
  "Meshy_AI_rigged_green_All_Animations.glb",
  "Meshy_AI_vintage_toy_m16_rifle.glb"
]);

// Node Material Editor graphs (NME JSON) served at /materials/<file>
const MATERIAL_FILES = new Set([
  "sandboxSand.json"
]);

// Node Geometry Editor graphs (NGE JSON) served at /geometry/<file>
const GEOMETRY_FILES = new Set([
  "sandboxFrame.json",
  "sandcastle.json",
  "toyBrick.json",
  "beachBucket.json",
  "armyTruck.json",
  "armyJeep.json",
  "shoeboxShell.json",
  "tissueSheet.json",
  "kitchenPlate.json"
]);

// Node Particle Editor graphs (NPE JSON) served at /particles/<file>
const PARTICLE_FILES = new Set([
  "sandPuff.json",
  "plasticSparks.json"
]);

// GUI Editor layouts (AdvancedDynamicTexture JSON) served at /gui/<file>
const GUI_FILES = new Set([
  "overheadPlates.json"
]);

// Flow Graph coordinators (presentation/control flow only) served at /flowgraphs/<file>
const FLOWGRAPH_FILES = new Set([
  "matchUiFlow.json"
]);

const GRAPH_ROUTES = [
  { prefix: "materials/", dir: MATERIALS_DIR, files: MATERIAL_FILES },
  { prefix: "geometry/", dir: GEOMETRY_DIR, files: GEOMETRY_FILES },
  { prefix: "particles/", dir: PARTICLES_DIR, files: PARTICLE_FILES },
  { prefix: "gui/", dir: GUI_DIR, files: GUI_FILES },
  { prefix: "flowgraphs/", dir: FLOWGRAPHS_DIR, files: FLOWGRAPH_FILES }
];

// ============================================================================
// 1. DDoS PROTECTION, RATE LIMITING & PERFORMANCE PROFILER STATE
// ============================================================================
const MAX_WS_PAYLOAD_BYTES = 16 * 1024; // 16 KB max frame size
const MAX_BOTS_PER_TEAM = 64;           // Practical max bot cap per team (64v64)
const MAX_CONN_PER_IP = Number(process.env.MAX_CONN_PER_IP) || 128;
const MAX_WS_MSGS_PER_SEC = Number(process.env.MAX_WS_MSGS_PER_SEC) || 180;
const MAX_WS_BYTES_PER_SEC = Number(process.env.MAX_WS_BYTES_PER_SEC) || 128 * 1024;
const MAX_ROOM_ACTIONS_PER_10S = 20;
const MAX_HTTP_REQ_PER_10S = 600;
const IP_BAN_DURATION_MS = 30 * 1000;

// Cached process memory telemetry (updated once per second to avoid synchronous OS syscalls on every ping)
let cachedRssMB = Math.round((process.memoryUsage().rss / (1024 * 1024)) * 10) / 10;
let cachedHeapUsedMB = Math.round((process.memoryUsage().heapUsed / (1024 * 1024)) * 10) / 10;
let cachedHeapTotalMB = Math.round((process.memoryUsage().heapTotal / (1024 * 1024)) * 10) / 10;

// Map<ip, { connCount, httpCount, httpWindowStart, bannedUntil, violations }>
const ipSecurityState = new Map();

const ddosTelemetry = {
  droppedMessages: 0,
  rateLimitedClients: 0,
  blockedConnections: 0,
  httpRateLimited: 0,
  malformedPackets: 0
};

function getClientIp(req) {
  // Allow k6 virtual users (even behind a reverse proxy that overwrites X-Forwarded-For)
  // to have isolated per-VU connection/rate buckets while still testing per-socket limits
  const k6VuHeader = req && req.headers && req.headers["x-k6-vu"];
  if (typeof k6VuHeader === "string" && k6VuHeader.length > 0) {
    return "k6_" + k6VuHeader.slice(0, 24);
  }
  if (req && typeof req.url === "string" && req.url.includes("k6vu=")) {
    const m = req.url.match(/[?&]k6vu=([a-zA-Z0-9_-]+)/);
    if (m && m[1]) return "k6_" + m[1].slice(0, 24);
  }
  const xff = req && req.headers && req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) {
    return xff.split(",")[0].trim();
  }
  return (req && req.socket && req.socket.remoteAddress) || "127.0.0.1";
}

function getIpRecord(ip) {
  let rec = ipSecurityState.get(ip);
  if (!rec) {
    rec = {
      connCount: 0,
      httpCount: 0,
      httpWindowStart: Date.now(),
      bannedUntil: 0,
      violations: 0
    };
    ipSecurityState.set(ip, rec);
  }
  return rec;
}

function isIpBanned(ip) {
  const rec = ipSecurityState.get(ip);
  if (!rec) return false;
  if (rec.bannedUntil > Date.now()) return true;
  return false;
}

function checkHttpRateLimit(ip) {
  const now = Date.now();
  const rec = getIpRecord(ip);
  if (rec.bannedUntil > now) {
    ddosTelemetry.httpRateLimited++;
    return false;
  }
  if (now - rec.httpWindowStart > 10000) {
    rec.httpWindowStart = now;
    rec.httpCount = 0;
  }
  rec.httpCount++;
  if (rec.httpCount > MAX_HTTP_REQ_PER_10S) {
    ddosTelemetry.httpRateLimited++;
    rec.violations++;
    if (rec.violations >= 6) {
      rec.bannedUntil = now + IP_BAN_DURATION_MS;
    }
    return false;
  }
  return true;
}

// Performance Profiling State (consumed by /api/perf and /perf dashboard)
const perfMetrics = {
  startTime: Date.now(),
  tickHistoryMs: [], // rolling last 120 ticks
  inboundPktsSec: 0,
  outboundPktsSec: 0,
  inboundBytesSec: 0,
  outboundBytesSec: 0,
  _inPktsAccum: 0,
  _outPktsAccum: 0,
  _inBytesAccum: 0,
  _outBytesAccum: 0,
  _lastRateSampleTime: Date.now(),
  totalInboundPkts: 0,
  totalOutboundPkts: 0,
  msgStats: new Map(), // Map<msgType, { count, totalMs, maxMs }>
  clientProfiles: new Map(), // Map<clientId, ClientPerfSnapshot>
  history: [], // rolling 60s of 1s snapshots
  lastK6Report: null
};

function recordMsgProfile(type, durationMs) {
  let st = perfMetrics.msgStats.get(type);
  if (!st) {
    st = { count: 0, totalMs: 0, maxMs: 0 };
    perfMetrics.msgStats.set(type, st);
  }
  st.count += 1;
  st.totalMs += durationMs;
  if (durationMs > st.maxMs) st.maxMs = durationMs;
}

function percentile(arr, p) {
  if (!arr || arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * p));
  return sorted[idx];
}

function getRoomsSummary(requestClientToken = null) {
  const now = Date.now();
  const summary = [];
  for (const room of rooms.values()) {
    if (room.matchEnded || room.endedByHost || now >= room.matchEndTime) {
      continue;
    }
    const roster = serializeRoster(room);
    if (
      requestClientToken &&
      room.originalHostToken &&
      room.originalHostToken === requestClientToken
    ) {
      roster.isHostRoom = true;
    }
    summary.push(roster);
  }
  return summary;
}

function getTakenPlayerNames() {
  const names = [];
  const seen = new Set();
  for (const room of rooms.values()) {
    for (const c of room.clients.values()) {
      const clean = String(c.name || "").trim();
      const lower = clean.toLowerCase();
      if (clean && !seen.has(lower)) {
        seen.add(lower);
        names.push(clean);
      }
    }
  }
  return names;
}

function buildPerfApiPayload() {
  const now = Date.now();
  const ticks = perfMetrics.tickHistoryMs;
  const avgTick =
    ticks.length > 0
      ? ticks.reduce((a, b) => a + b, 0) / ticks.length
      : lastServerTickMs;
  const p95Tick = percentile(ticks, 0.95);
  const maxTick = ticks.length > 0 ? Math.max(...ticks) : lastServerTickMs;

  let totalOnlinePlayers = 0;
  let totalSimulatedUnits = 0;
  const roomDetails = [];
  for (const room of rooms.values()) {
    const pCount = room.clients.size;
    const uCount = room.greenTotal + room.tanTotal;
    totalOnlinePlayers += pCount;
    totalSimulatedUnits += uCount;
    roomDetails.push({
      roomCode: room.code,
      mapType: room.mapType || "sandbox",
      worldLimit: room.worldLimit,
      hardcoreMode: Boolean(room.hardcoreMode),
      hasPassword: Boolean(room.password),
      playersOnline: pCount,
      greenTotal: room.greenTotal,
      tanTotal: room.tanTotal,
      totalUnits: uCount,
      remainingSec: Math.round(Math.max(0, (room.matchEndTime - now) / 1000))
    });
  }

  // Prune stale client profiles (> 15s old)
  for (const [cid, prof] of perfMetrics.clientProfiles.entries()) {
    if (now - prof.updatedAt > 15000) {
      perfMetrics.clientProfiles.delete(cid);
    }
  }

  const clientList = Array.from(perfMetrics.clientProfiles.values());
  const avgClientFps =
    clientList.length > 0
      ? Number((clientList.reduce((acc, c) => acc + (c.fps || 0), 0) / clientList.length).toFixed(1))
      : null;
  const minClientFps =
    clientList.length > 0
      ? Number(Math.min(...clientList.map((c) => c.fps || 60)).toFixed(1))
      : null;
  const avgClientFrameMs =
    clientList.length > 0
      ? Number((clientList.reduce((acc, c) => acc + (c.frameMs || 0), 0) / clientList.length).toFixed(2))
      : null;

  const messageProfiling = {};
  for (const [type, st] of perfMetrics.msgStats.entries()) {
    messageProfiling[type] = {
      count: st.count,
      avgMs: Number((st.totalMs / Math.max(1, st.count)).toFixed(4)),
      maxMs: Number(st.maxMs.toFixed(4)),
      totalMs: Number(st.totalMs.toFixed(2))
    };
  }

  let activeIpBans = 0;
  for (const rec of ipSecurityState.values()) {
    if (rec.bannedUntil > now) activeIpBans++;
  }

  // Automated scaling & bottleneck diagnostics for AI / developer consumption
  const recommendations = [];
  if (p95Tick > 10) {
    recommendations.push(
      `High server tick p95 (${p95Tick.toFixed(2)}ms): consider reducing host_world_state broadcast rate or room count.`
    );
  }
  if (avgClientFps !== null && avgClientFps < 45) {
    recommendations.push(
      `Low average client FPS (${avgClientFps}): inspect clientProfiles renderMs/aiMs/physicsMs breakdown.`
    );
  }
  if (perfMetrics.outboundBytesSec > 512 * 1024) {
    recommendations.push(
      `High outbound bandwidth (${(perfMetrics.outboundBytesSec / 1024).toFixed(1)} KB/s): quantize or delta-compress world_state updates.`
    );
  }
  if (recommendations.length === 0) {
    recommendations.push("All server and client performance metrics are within healthy scaling thresholds.");
  }

  return {
    ok: true,
    timestamp: new Date(now).toISOString(),
    uptimeSec: Math.round((now - perfMetrics.startTime) / 1000),
    server: {
      tickLastMs: Number(lastServerTickMs.toFixed(3)),
      tickAvgMs: Number(avgTick.toFixed(3)),
      tickP95Ms: Number(p95Tick.toFixed(3)),
      tickMaxMs: Number(maxTick.toFixed(3)),
      rssMB: cachedRssMB,
      heapUsedMB: cachedHeapUsedMB,
      heapTotalMB: cachedHeapTotalMB
    },
    network: {
      inboundPktPerSec: perfMetrics.inboundPktsSec,
      outboundPktPerSec: perfMetrics.outboundPktsSec,
      inboundKBPerSec: Number((perfMetrics.inboundBytesSec / 1024).toFixed(2)),
      outboundKBPerSec: Number((perfMetrics.outboundBytesSec / 1024).toFixed(2)),
      totalInboundPkts: perfMetrics.totalInboundPkts,
      totalOutboundPkts: perfMetrics.totalOutboundPkts
    },
    ddosProtection: {
      maxPayloadBytes: MAX_WS_PAYLOAD_BYTES,
      maxConnPerIp: MAX_CONN_PER_IP,
      maxMsgsPerSec: MAX_WS_MSGS_PER_SEC,
      maxBytesPerSec: MAX_WS_BYTES_PER_SEC,
      droppedMessages: ddosTelemetry.droppedMessages,
      rateLimitedClients: ddosTelemetry.rateLimitedClients,
      blockedConnections: ddosTelemetry.blockedConnections,
      httpRateLimited: ddosTelemetry.httpRateLimited,
      malformedPackets: ddosTelemetry.malformedPackets,
      activeIpBans
    },
    scalingSummary: {
      activeRooms: rooms.size,
      totalOnlinePlayers,
      totalSimulatedUnits,
      reportedClients: clientList.length,
      avgClientFps,
      minClientFps,
      avgClientFrameMs,
      recommendations
    },
    messageProfiling,
    rooms: roomDetails,
    clientProfiles: clientList,
    history: perfMetrics.history,
    lastK6Report: perfMetrics.lastK6Report
  };
}

function renderPerfDashboardHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Toy Soldiers — Performance & Scaling Profiler</title>
  <link rel="icon" type="image/png" href="favicon/favicon-96x96.png" sizes="96x96" />
  <link rel="icon" type="image/svg+xml" href="favicon/favicon.svg" />
  <link rel="shortcut icon" href="favicon/favicon.ico" />
  <link rel="apple-touch-icon" sizes="180x180" href="favicon/apple-touch-icon.png" />
  <link rel="manifest" href="favicon/site.webmanifest" />
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 20px;
      background: #0d120e;
      color: #e4f0e2;
      font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
    }
    .header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 18px;
      padding-bottom: 12px;
      border-bottom: 1px solid rgba(132, 255, 120, 0.25);
    }
    .header h1 {
      margin: 0;
      font-size: 22px;
      color: #84ff78;
    }
    .btn {
      padding: 8px 14px;
      border-radius: 6px;
      border: 1px solid rgba(122, 215, 255, 0.45);
      background: rgba(25, 42, 30, 0.85);
      color: #ffffff;
      font-weight: bold;
      font-size: 13px;
      cursor: pointer;
      text-decoration: none;
    }
    .btn:hover { background: rgba(40, 70, 48, 0.95); }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      margin-bottom: 18px;
    }
    .card {
      background: rgba(22, 30, 22, 0.9);
      border: 1px solid rgba(255, 255, 255, 0.14);
      border-radius: 10px;
      padding: 14px 16px;
    }
    .card-label {
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.6px;
      color: #9ab098;
      margin-bottom: 6px;
    }
    .card-value {
      font-size: 24px;
      font-weight: bold;
      color: #84ff78;
      font-family: Consolas, monospace;
    }
    .card-sub {
      font-size: 12px;
      color: #b8c8b6;
      margin-top: 4px;
      font-family: Consolas, monospace;
    }
    .panel {
      background: rgba(22, 30, 22, 0.9);
      border: 1px solid rgba(255, 255, 255, 0.14);
      border-radius: 10px;
      padding: 16px;
      margin-bottom: 16px;
    }
    .panel h2 {
      margin: 0 0 10px 0;
      font-size: 15px;
      color: #7ad7ff;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
      font-family: Consolas, monospace;
    }
    th, td {
      padding: 8px 10px;
      text-align: left;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }
    th {
      color: #9ab098;
      font-size: 11.5px;
      text-transform: uppercase;
    }
    .rec-item {
      padding: 8px 12px;
      background: rgba(132, 255, 120, 0.08);
      border-left: 3px solid #84ff78;
      border-radius: 4px;
      margin-bottom: 6px;
      font-size: 13.5px;
    }
    canvas.chart {
      width: 100%;
      height: 150px;
      background: rgba(0, 0, 0, 0.35);
      border-radius: 6px;
      display: block;
    }
  </style>
</head>
<body>
  <div class="header">
    <div>
      <h1>Toy Soldiers — Performance & Scaling Profiler</h1>
      <div style="font-size: 12.5px; color: #9ab098;">Live Server, Network, DDoS & Client Frame Breakdown &bull; AI JSON Endpoint: <code>/api/perf</code></div>
    </div>
    <div style="display: flex; gap: 8px;">
      <button class="btn" id="copy-json-btn" type="button">Copy AI JSON (/api/perf)</button>
      <a class="btn" href="/api/perf" target="_blank">Raw JSON</a>
      <a class="btn" href="/">Back to Game</a>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <div class="card-label">Client FPS (Avg / Min)</div>
      <div class="card-value" id="kpi-fps">--</div>
      <div class="card-sub" id="kpi-framems">Frame: -- ms</div>
    </div>
    <div class="card">
      <div class="card-label">Server Tick (Avg / P95)</div>
      <div class="card-value" id="kpi-tick">--</div>
      <div class="card-sub" id="kpi-mem">RSS: -- MB &bull; Heap: -- MB</div>
    </div>
    <div class="card">
      <div class="card-label">Network Throughput</div>
      <div class="card-value" id="kpi-net">--</div>
      <div class="card-sub" id="kpi-bw">In: -- KB/s &bull; Out: -- KB/s</div>
    </div>
    <div class="card">
      <div class="card-label">Active Rooms & Units</div>
      <div class="card-value" id="kpi-rooms">0 Rooms</div>
      <div class="card-sub" id="kpi-units">0 Players &bull; 0 Units</div>
    </div>
    <div class="card">
      <div class="card-label">DDoS / Rate Limiter</div>
      <div class="card-value" id="kpi-ddos">0 Dropped</div>
      <div class="card-sub" id="kpi-bans">Blocked: 0 &bull; Active Bans: 0</div>
    </div>
  </div>

  <div class="panel">
    <h2>Scaling Diagnostics & Recommendations</h2>
    <div id="recommendations-box">Loading...</div>
  </div>

  <div class="panel">
    <h2>Live History (Last 60 Seconds — Client FPS & Server Outbound KB/s)</h2>
    <canvas id="history-chart" class="chart" width="900" height="150"></canvas>
  </div>

  <div class="panel">
    <h2>Client Render & Simulation Breakdown</h2>
    <table>
      <thead>
        <tr>
          <th>Client</th>
          <th>Mode / Room</th>
          <th>Map</th>
          <th>Units</th>
          <th>FPS</th>
          <th>Frame (ms)</th>
          <th>Render (ms)</th>
          <th>Physics (ms)</th>
          <th>AI (ms)</th>
          <th>Anim/IK (ms)</th>
        </tr>
      </thead>
      <tbody id="clients-tbody">
        <tr><td colspan="10">No active client profiles reported yet. Open the game to stream telemetry.</td></tr>
      </tbody>
    </table>
  </div>

  <div class="panel">
    <h2>Server WebSocket Message Handler Profiling</h2>
    <table>
      <thead>
        <tr>
          <th>Message Type</th>
          <th>Total Count</th>
          <th>Avg Exec (ms)</th>
          <th>Max Exec (ms)</th>
          <th>Total CPU (ms)</th>
        </tr>
      </thead>
      <tbody id="msg-tbody">
        <tr><td colspan="5">No WebSocket messages recorded yet.</td></tr>
      </tbody>
    </table>
  </div>

  <div class="panel">
    <h2>Active Multiplayer Rooms</h2>
    <table>
      <thead>
        <tr>
          <th>Room Code</th>
          <th>Map</th>
          <th>Hardcore</th>
          <th>Password</th>
          <th>Players Online</th>
          <th>Total Units</th>
          <th>Time Left</th>
        </tr>
      </thead>
      <tbody id="rooms-tbody">
        <tr><td colspan="7">No active multiplayer rooms.</td></tr>
      </tbody>
    </table>
  </div>

  <script>
    let latestPerfData = null;

    function drawChart(history) {
      const canvas = document.getElementById("history-chart");
      if (!canvas) return;
      const ctx = canvas.getContext("2d");
      const w = canvas.width;
      const h = canvas.height;
      ctx.clearRect(0, 0, w, h);

      ctx.strokeStyle = "rgba(255,255,255,0.08)";
      ctx.beginPath();
      ctx.moveTo(0, h * 0.5);
      ctx.lineTo(w, h * 0.5);
      ctx.stroke();

      if (!Array.isArray(history) || history.length < 2) return;

      // Plot FPS (green, 0-120 scale)
      ctx.strokeStyle = "#84ff78";
      ctx.lineWidth = 2;
      ctx.beginPath();
      history.forEach((pt, i) => {
        const x = (i / (history.length - 1)) * (w - 20) + 10;
        const fps = pt.avgClientFps !== null ? pt.avgClientFps : 60;
        const y = h - Math.min(1, Math.max(0, fps / 120)) * (h - 20) - 10;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();

      // Plot Outbound KB/s (blue, 0-200 KB/s scale)
      ctx.strokeStyle = "#7ad7ff";
      ctx.lineWidth = 2;
      ctx.beginPath();
      history.forEach((pt, i) => {
        const x = (i / (history.length - 1)) * (w - 20) + 10;
        const kb = pt.outboundKBPerSec || 0;
        const y = h - Math.min(1, Math.max(0, kb / 200)) * (h - 20) - 10;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.stroke();
    }

    async function refreshPerf() {
      try {
        const res = await fetch("/api/perf");
        const data = await res.json();
        latestPerfData = data;

        const sc = data.scalingSummary || {};
        const sv = data.server || {};
        const nw = data.network || {};
        const dd = data.ddosProtection || {};

        document.getElementById("kpi-fps").textContent =
          sc.avgClientFps !== null ? sc.avgClientFps + " / " + sc.minClientFps + " FPS" : "No Clients";
        document.getElementById("kpi-framems").textContent =
          "Avg Frame: " + (sc.avgClientFrameMs !== null ? sc.avgClientFrameMs + " ms" : "--");

        document.getElementById("kpi-tick").textContent =
          sv.tickAvgMs + " / " + sv.tickP95Ms + " ms";
        document.getElementById("kpi-mem").textContent =
          "RSS: " + sv.rssMB + " MB • Heap: " + sv.heapUsedMB + " MB";

        document.getElementById("kpi-net").textContent =
          (nw.inboundPktPerSec + nw.outboundPktPerSec) + " pkt/s";
        document.getElementById("kpi-bw").textContent =
          "In: " + nw.inboundKBPerSec + " KB/s • Out: " + nw.outboundKBPerSec + " KB/s";

        document.getElementById("kpi-rooms").textContent = sc.activeRooms + " Rooms";
        document.getElementById("kpi-units").textContent =
          sc.totalOnlinePlayers + " Players • " + sc.totalSimulatedUnits + " Units";

        document.getElementById("kpi-ddos").textContent = dd.droppedMessages + " Dropped";
        document.getElementById("kpi-bans").textContent =
          "Blocked: " + dd.blockedConnections + " • Active Bans: " + dd.activeIpBans;

        const recBox = document.getElementById("recommendations-box");
        recBox.innerHTML = (sc.recommendations || [])
          .map((r) => '<div class="rec-item">' + r + "</div>")
          .join("");

        const cBody = document.getElementById("clients-tbody");
        if (Array.isArray(data.clientProfiles) && data.clientProfiles.length > 0) {
          cBody.innerHTML = data.clientProfiles
            .map(
              (c) =>
                "<tr>" +
                "<td>" + (c.clientId || "local") + "</td>" +
                "<td>" + (c.mode || "solo") + (c.roomCode ? " (" + c.roomCode + ")" : "") + "</td>" +
                "<td>" + (c.mapType === "kitchen" ? "Kitchen Table" : c.mapType === "shoebox" ? "Shoebox" : "Sandbox") + "</td>" +
                "<td>" + (c.aliveUnits || 0) + "/" + (c.totalUnits || 0) + "</td>" +
                "<td style='color:#84ff78;font-weight:bold;'>" + (c.fps || 0) + "</td>" +
                "<td>" + (c.frameMs || 0) + "</td>" +
                "<td>" + (c.renderMs || 0) + "</td>" +
                "<td>" + (c.physicsMs || 0) + "</td>" +
                "<td>" + (c.aiMs || 0) + "</td>" +
                "<td>" + (c.animMs || 0) + "</td>" +
                "</tr>"
            )
            .join("");
        } else {
          cBody.innerHTML = '<tr><td colspan="10">No active client profiles reported in the last 15s.</td></tr>';
        }

        const mBody = document.getElementById("msg-tbody");
        const mEntries = Object.entries(data.messageProfiling || {});
        if (mEntries.length > 0) {
          mBody.innerHTML = mEntries
            .map(
              ([k, v]) =>
                "<tr><td>" + k + "</td><td>" + v.count + "</td><td>" + v.avgMs + "</td><td>" + v.maxMs + "</td><td>" + v.totalMs + "</td></tr>"
            )
            .join("");
        }

        const rBody = document.getElementById("rooms-tbody");
        if (Array.isArray(data.rooms) && data.rooms.length > 0) {
          rBody.innerHTML = data.rooms
            .map(
              (r) =>
                "<tr>" +
                "<td>" + r.roomCode + "</td>" +
                "<td>" + (r.mapType === "kitchen" ? "Kitchen Table" : r.mapType === "shoebox" ? "Shoebox" : "Sandbox") + "</td>" +
                "<td>" + (r.hardcoreMode ? "Yes" : "No") + "</td>" +
                "<td>" + (r.hasPassword ? "🔒 Protected" : "Open") + "</td>" +
                "<td>" + r.playersOnline + "</td>" +
                "<td>" + r.totalUnits + " (" + r.greenTotal + "v" + r.tanTotal + ")</td>" +
                "<td>" + r.remainingSec + "s</td>" +
                "</tr>"
            )
            .join("");
        } else {
          rBody.innerHTML = '<tr><td colspan="7">No active multiplayer rooms.</td></tr>';
        }

        drawChart(data.history || []);
      } catch (err) {}
    }

    document.getElementById("copy-json-btn").addEventListener("click", () => {
      if (!latestPerfData) return;
      navigator.clipboard.writeText(JSON.stringify(latestPerfData, null, 2));
      const btn = document.getElementById("copy-json-btn");
      btn.textContent = "Copied!";
      setTimeout(() => { btn.textContent = "Copy AI JSON (/api/perf)"; }, 1500);
    });

    refreshPerf();
    setInterval(refreshPerf, 1000);
  </script>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  const clientIp = getClientIp(req);
  if (!checkHttpRateLimit(clientIp)) {
    res.writeHead(429, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: false, error: "Too many requests. Please slow down." }));
    return;
  }

  const cleanUrl = (req.url || "/").split("?")[0];

  if (cleanUrl === "/health" || cleanUrl === "/rooms") {
    let reqClientToken = null;
    const qIdx = (req.url || "").indexOf("?");
    if (qIdx !== -1) {
      try {
        const params = new URLSearchParams(req.url.slice(qIdx + 1));
        const tok = params.get("clientToken");
        if (tok) reqClientToken = String(tok).trim().slice(0, 64);
      } catch {}
    }
    const activeRooms = getRoomsSummary(reqClientToken);
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
      "Pragma": "no-cache",
      "Expires": "0"
    });
    res.end(
      JSON.stringify({
        ok: true,
        roomCount: activeRooms.length,
        takenNames: getTakenPlayerNames(),
        rooms: activeRooms
      })
    );
    return;
  }

  if (cleanUrl === "/rooms/end" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => {
      if (body.length < 4096) body += chunk;
    });
    req.on("end", () => {
      try {
        const data = JSON.parse(body || "{}");
        const code = String(data.roomCode || "").toUpperCase().trim();
        const tok = String(data.clientToken || "").trim().slice(0, 64);
        const room = rooms.get(code);
        if (!room || !tok || room.originalHostToken !== tok) {
          res.writeHead(403, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: "Not authorized to end this match." }));
          return;
        }
        endRoomByHost(room);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, roomCode: code }));
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false }));
      }
    });
    return;
  }

  // AI & Developer Performance Profiling JSON API
  if (cleanUrl === "/api/perf" || cleanUrl === "/perf.json") {
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache"
    });
    res.end(JSON.stringify(buildPerfApiPayload(), null, 2));
    return;
  }

  // Remote k6 Stress Test Report Storage & Retrieval (so k6 run on another PC can publish its summary to the server)
  if (cleanUrl === "/api/perf/report") {
    if (req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => {
        if (body.length < 256 * 1024) body += chunk;
      });
      req.on("end", () => {
        try {
          perfMetrics.lastK6Report = JSON.parse(body);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: true }));
        } catch {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: false }));
        }
      });
      return;
    }
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Cache-Control": "no-cache"
    });
    res.end(
      JSON.stringify(
        {
          ok: true,
          hasReport: Boolean(perfMetrics.lastK6Report),
          lastK6Report: perfMetrics.lastK6Report
        },
        null,
        2
      )
    );
    return;
  }

  // Client Performance Telemetry Ingestion Endpoint (supports both Solo & Multiplayer profiling)
  if (cleanUrl === "/api/perf/client" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => {
      if (body.length < 8192) body += chunk;
    });
    req.on("end", () => {
      try {
        const data = JSON.parse(body);
        const cid = String(data.clientId || "solo_" + clientIp).slice(0, 28);
        perfMetrics.clientProfiles.set(cid, {
          clientId: cid,
          mode: data.mode === "multiplayer" ? "multiplayer" : "solo",
          roomCode: data.roomCode ? String(data.roomCode).slice(0, 12) : null,
          mapType: resolveMapType(data.mapType),
          fps: Number(Number(data.fps || 0).toFixed(1)),
          frameMs: Number(Number(data.frameMs || 0).toFixed(2)),
          renderMs: Number(Number(data.renderMs || 0).toFixed(2)),
          physicsMs: Number(Number(data.physicsMs || 0).toFixed(2)),
          aiMs: Number(Number(data.aiMs || 0).toFixed(2)),
          animMs: Number(Number(data.animMs || 0).toFixed(2)),
          aliveUnits: Number(data.aliveUnits) || 0,
          totalUnits: Number(data.totalUnits) || 0,
          updatedAt: Date.now()
        });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      } catch {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false }));
      }
    });
    return;
  }

  // Live Performance & Scaling Dashboard Web Page
  if (cleanUrl === "/perf" || cleanUrl === "/perf.html") {
    res.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache"
    });
    res.end(renderPerfDashboardHtml());
    return;
  }

  if (cleanUrl === "/" || cleanUrl === "/index.html") {
    fs.readFile(INDEX_PATH, (err, content) => {
      if (err) {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("Error loading index.html");
        return;
      }
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-cache"
      });
      res.end(content);
    });
    return;
  }

  // Serve favicon & web-app manifest assets at both /favicon/<file> and root /<file>
  const strippedPath = cleanUrl.replace(/^\/+/, "");
  const assetName = strippedPath.startsWith("favicon/")
    ? strippedPath.slice("favicon/".length)
    : strippedPath;
  if (FAVICON_FILES.has(assetName)) {
    const filePath = path.join(FAVICON_DIR, assetName);
    const ext = path.extname(assetName).toLowerCase();
    const contentType = FAVICON_MIME_TYPES[ext] || "application/octet-stream";
    fs.readFile(filePath, (err, content) => {
      if (err) {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("Not Found");
        return;
      }
      res.writeHead(200, {
        "Content-Type": contentType,
        "Cache-Control": "public, max-age=86400"
      });
      res.end(content);
    });
    return;
  }

  // Serve 3D GLB model assets at both /models/<file> and root /<file>
  const modelAssetName = strippedPath.startsWith("models/")
    ? strippedPath.slice("models/".length)
    : strippedPath;
  if (MODEL_FILES.has(modelAssetName)) {
    const modelPath = path.join(MODELS_DIR, modelAssetName);
    fs.readFile(modelPath, (err, content) => {
      if (err) {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("Not Found");
        return;
      }
      res.writeHead(200, {
        "Content-Type": "model/gltf-binary",
        "Cache-Control": "public, max-age=86400"
      });
      res.end(content);
    });
    return;
  }

  const graphRoute = GRAPH_ROUTES.find((route) => strippedPath.startsWith(route.prefix));
  if (graphRoute) {
    const graphName = strippedPath.slice(graphRoute.prefix.length);
    if (graphRoute.files.has(graphName)) {
      fs.readFile(path.join(graphRoute.dir, graphName), (err, content) => {
        if (err) {
          res.writeHead(404, { "Content-Type": "text/plain" });
          res.end("Not Found");
          return;
        }
        res.writeHead(200, {
          "Content-Type": "application/json; charset=utf-8",
          "Cache-Control": "no-cache"
        });
        res.end(content);
      });
      return;
    }
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not Found");
});

// ============================================================================
// 2. WEBSOCKET MULTIPLAYER ROOM SERVER (WITH DDoS & PASSWORD PROTECTION)
// ============================================================================
const wss = new WebSocketServer({
  server,
  maxPayload: MAX_WS_PAYLOAD_BYTES
});

// Map<roomCode, RoomState>
const rooms = new Map();
let nextClientId = 1;
let nextRoomSyncSlot = 0;

function safeSend(ws, payload) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return;
  const data = typeof payload === "string" ? payload : JSON.stringify(payload);
  try {
    ws.send(data);
    perfMetrics._outPktsAccum += 1;
    perfMetrics._outBytesAccum += data.length;
    perfMetrics.totalOutboundPkts += 1;
  } catch {
    // Ignore transient send errors on closing sockets so one bad socket cannot disrupt other rooms
  }
}

function resolveMapType(mapType, limit) {
  if (mapType === "kitchen") return "kitchen";
  return mapType === "shoebox" || Number(limit) <= 50 ? "shoebox" : "sandbox";
}

function resolveWorldLimit(mapType, limit) {
  return mapType === "kitchen" ? 64 : mapType === "shoebox" ? 28
    : Math.max(50, Math.min(130, Number(limit) || 80));
}

function getSpawnBounds(room) {
  return {
    maxX: room.mapType === "kitchen" ? 38 : room.mapType === "shoebox" ? 18 : Math.max(30, room.worldLimit - 10),
    minZ: room.mapType === "shoebox" ? 10 : Math.max(18, room.worldLimit * 0.35),
    maxZ: room.mapType === "shoebox" ? 25 : Math.max(28, room.worldLimit - 8)
  };
}

function sanitizeCode(raw, mapType = "sandbox") {
  const fallbackPrefix = mapType === "kitchen" ? "KITC" : mapType === "shoebox" ? "SHOE" : "SAND";
  const cleaned = String(raw || "")
    .toUpperCase()
    .replace(/[^A-Z0-9_-]/g, "")
    .slice(0, 12);
  return cleaned || `${fallbackPrefix}${Math.floor(100 + Math.random() * 900)}`;
}

function allocateUniqueRoomCode(requestedRaw, mapType = "sandbox") {
  const prefix = mapType === "kitchen" ? "KITC" : mapType === "shoebox" ? "SHOE" : "SAND";
  const cleaned = sanitizeCode(requestedRaw, mapType);
  // If the requested code matches the selected map prefix and is unused, keep it
  const matchesMapPrefix = cleaned.startsWith(prefix);
  if (cleaned && cleaned !== "SAND1" && cleaned !== "SHOE1" && cleaned !== "KITC1" && matchesMapPrefix && !rooms.has(cleaned)) {
    return cleaned;
  }
  if (cleaned && !cleaned.startsWith("SAND") && !cleaned.startsWith("SHOE") && !cleaned.startsWith("KITC") && !rooms.has(cleaned)) {
    return cleaned;
  }
  for (let attempt = 0; attempt < 200; attempt++) {
    const candidate = `${prefix}${Math.floor(100 + Math.random() * 900)}`;
    if (!rooms.has(candidate)) {
      return candidate;
    }
  }
  let seq = 1;
  while (rooms.has(`${prefix}${seq}`)) {
    seq++;
  }
  return `${prefix}${seq}`;
}

function getUnitStat(room, unitId) {
  let st = room.unitStats.get(unitId);
  if (!st) {
    st = { kills: 0, deaths: 0, health: 100, alive: true };
    room.unitStats.set(unitId, st);
    room.statsDirty = true;
    room.statsDirtyForSync = true;
  }
  return st;
}

function serializeUnitStats(room) {
  if (!room.statsDirty && room.cachedUnitStats) {
    return room.cachedUnitStats;
  }
  const obj = {};
  for (const [unitId, st] of room.unitStats.entries()) {
    obj[unitId] = {
      kills: st.kills,
      deaths: st.deaths,
      health: st.health,
      alive: st.alive
    };
  }
  room.cachedUnitStats = obj;
  room.statsDirty = false;
  return obj;
}

function resetRoomMatchState(room) {
  room.matchEndTime = Date.now() + room.durationSec * 1000;
  room.matchEnded = false;
  room.endedByHost = false;
  room.lastWorldState = null;
  room.pendingWorldState = null;
  if (room.dirtyPlayers) room.dirtyPlayers.clear();
  if (room.pendingShots) room.pendingShots.length = 0;
  if (room.pendingDamages) room.pendingDamages.length = 0;
  if (room.pendingRespawns) room.pendingRespawns.length = 0;
  if (room.disconnectedPlayers) {
    room.disconnectedPlayers.clear();
  }
  room.unitStats.clear();
  for (let i = 0; i < room.greenTotal; i++) {
    room.unitStats.set(`green_${i}`, { kills: 0, deaths: 0, health: 100, alive: true });
  }
  for (let i = 0; i < room.tanTotal; i++) {
    room.unitStats.set(`tan_${i}`, { kills: 0, deaths: 0, health: 100, alive: true });
  }
  for (const c of room.clients.values()) {
    c.health = 100;
    c.alive = true;
  }
  room.statsDirty = true;
  room.statsDirtyForSync = true;
}

function isRoomOwner(room, clientId, clientToken) {
  if (!room) return false;
  if (room.originalHostToken) {
    return Boolean(
      (clientToken && room.originalHostToken === clientToken) ||
        (room.originalHostClientId && room.originalHostClientId === clientId)
    );
  }
  return room.hostId === clientId;
}

function endRoomByHost(room) {
  if (!room) return;
  room.matchEnded = true;
  room.endedByHost = true;
  room.matchEndTime = Date.now();
  room.pendingWorldState = null;
  if (room.dirtyPlayers) room.dirtyPlayers.clear();
  if (room.pendingShots) room.pendingShots.length = 0;
  if (room.pendingDamages) room.pendingDamages.length = 0;
  if (room.pendingRespawns) room.pendingRespawns.length = 0;

  const hostName = room.originalHostName || room.hostName || "Host";
  if (room.clients.size > 0) {
    broadcastToRoom(
      room,
      {
        type: "match_ended",
        endedByHost: true,
        hostName,
        roomCode: room.code,
        remainingSec: 0,
        unitStats: serializeUnitStats(room),
        roster: serializeRoster(room)
      },
      null
    );
  } else {
    rooms.delete(room.code);
  }
}

function getOrCreateRoom(
  roomCode,
  greenTotal,
  tanTotal,
  hostName,
  worldLimit,
  durationSec,
  mapType,
  hardcoreMode,
  password,
  hostToken = null
) {
  let room = rooms.get(roomCode);
  if (!room) {
    const dur = Math.max(60, Math.min(1800, Number(durationSec) || 300));
    const resolvedMap = resolveMapType(mapType, worldLimit);
    const lim = resolveWorldLimit(resolvedMap, worldLimit);
    room = {
      code: roomCode,
      syncSlot: nextRoomSyncSlot++ & 7, // Stagger timer_sync across 8 x 250ms ticks (2.0s cycle)
      hostId: null,
      hostName: hostName || "Host",
      originalHostToken: hostToken || null,
      originalHostName: hostName || "Host",
      originalHostClientId: null,
      password: String(password || "").trim().slice(0, 32),
      greenTotal: Math.max(1, Math.min(MAX_BOTS_PER_TEAM + 1, Math.floor(Number(greenTotal) || 4))),
      tanTotal: Math.max(1, Math.min(MAX_BOTS_PER_TEAM + 1, Math.floor(Number(tanTotal) || 4))),
      mapType: resolvedMap,
      worldLimit: lim,
      hardcoreMode: Boolean(hardcoreMode),
      durationSec: dur,
      matchEndTime: Date.now() + dur * 1000,
      matchEnded: false,
      endedByHost: false,
      lastWorldState: null,
      unitStats: new Map(),
      statsDirty: true,
      statsDirtyForSync: true,
      cachedUnitStats: null,
      dirtyPlayers: new Map(), // Map<clientId, PlayerStateDelta> coalesced at 25 Hz
      pendingShots: [],        // Array<ShotEvent> coalesced at 25 Hz
      pendingDamages: [],      // Array<DamageEvent> coalesced at 25 Hz
      pendingRespawns: [],     // Array<RespawnEvent> coalesced at 25 Hz
      pendingWorldState: null, // Latest host_world_state coalesced at 25 Hz
      clients: new Map(), // Map<clientId, ClientInfo>
      disconnectedPlayers: new Map(), // Map<clientToken, SavedPlayerSlot>
      matchId: 1
    };
    resetRoomMatchState(room);
    rooms.set(roomCode, room);
  }
  return room;
}

function serializeRoster(room) {
  const players = [];
  for (const c of room.clients.values()) {
    players.push({
      id: c.id,
      name: c.name,
      team: c.team,
      slotIndex: c.slotIndex,
      unitId: c.unitId,
      x: c.x,
      y: c.y,
      z: c.z,
      yaw: c.yaw,
      pitch: c.pitch,
      health: c.health,
      alive: c.alive
    });
  }
  const remainingSec = Math.max(0, (room.matchEndTime - Date.now()) / 1000);
  return {
    roomCode: room.code,
    hostId: room.hostId,
    originalHostClientId: room.originalHostClientId || null,
    hostName: room.originalHostName || room.hostName || "Host",
    isHostOnline: Boolean(room.originalHostClientId && room.clients.has(room.originalHostClientId)),
    hasPassword: Boolean(room.password),
    greenTotal: room.greenTotal,
    tanTotal: room.tanTotal,
    mapType: room.mapType || "sandbox",
    worldLimit: room.worldLimit,
    hardcoreMode: Boolean(room.hardcoreMode),
    durationSec: room.durationSec,
    remainingSec,
    matchEnded: room.matchEnded,
    endedByHost: Boolean(room.endedByHost),
    unitStats: serializeUnitStats(room),
    matchId: room.matchId,
    players
  };
}

function broadcastToRoom(room, payload, excludeClientId = null) {
  const data = typeof payload === "string" ? payload : JSON.stringify(payload);
  for (const client of room.clients.values()) {
    if (client.id !== excludeClientId && client.ws.readyState === WebSocket.OPEN) {
      safeSend(client.ws, data);
    }
  }
}

function assignSlotForPlayer(room, team) {
  const usedSlots = new Set();
  for (const c of room.clients.values()) {
    if (c.team === team) {
      usedSlots.add(c.slotIndex);
    }
  }
  if (room.disconnectedPlayers) {
    for (const saved of room.disconnectedPlayers.values()) {
      if (saved && saved.team === team && typeof saved.slotIndex === "number") {
        usedSlots.add(saved.slotIndex);
      }
    }
  }
  let slot = 0;
  if (usedSlots.size < MAX_BOTS_PER_TEAM + 1) {
    while (usedSlots.has(slot)) {
      slot++;
    }
    return slot;
  }
  // If all team slots are occupied or reserved, evict the oldest non-owner disconnected reservation
  if (room.disconnectedPlayers) {
    for (const [tok, saved] of room.disconnectedPlayers.entries()) {
      if (saved && saved.team === team && tok !== room.originalHostToken) {
        room.disconnectedPlayers.delete(tok);
        return saved.slotIndex;
      }
    }
  }
  const activeSlots = new Set();
  for (const c of room.clients.values()) {
    if (c.team === team) {
      activeSlots.add(c.slotIndex);
    }
  }
  slot = 0;
  while (activeSlots.has(slot)) {
    slot++;
  }
  return slot;
}

wss.on("connection", (ws, req) => {
  const clientIp = getClientIp(req);
  const ipRec = getIpRecord(clientIp);

  // DDoS Check 1: Reject banned IPs or excessive concurrent connections per IP
  if (isIpBanned(clientIp) || ipRec.connCount >= MAX_CONN_PER_IP) {
    ddosTelemetry.blockedConnections++;
    try {
      ws.close(1008, "Connection rate limit exceeded");
    } catch {}
    return;
  }

  ipRec.connCount++;
  const clientId = "p_" + nextClientId++;
  let currentRoom = null;

  // Per-client sliding-window rate limiter state
  const rateState = {
    windowStart: Date.now(),
    msgCount: 0,
    byteCount: 0,
    roomActionWindowStart: Date.now(),
    roomActions: 0,
    violations: 0
  };

  ws.on("message", (rawMessage) => {
    const now = Date.now();
    const rawStr = typeof rawMessage === "string" ? rawMessage : rawMessage.toString();
    const byteLen = rawStr.length;

    // DDoS Check 2: Payload size & per-second message/bandwidth rate limit
    if (byteLen > MAX_WS_PAYLOAD_BYTES) {
      ddosTelemetry.droppedMessages++;
      rateState.violations++;
      return;
    }

    if (now - rateState.windowStart >= 1000) {
      rateState.windowStart = now;
      rateState.msgCount = 0;
      rateState.byteCount = 0;
    }

    rateState.msgCount += 1;
    rateState.byteCount += byteLen;
    perfMetrics._inPktsAccum += 1;
    perfMetrics._inBytesAccum += byteLen;
    perfMetrics.totalInboundPkts += 1;

    if (
      rateState.msgCount > MAX_WS_MSGS_PER_SEC ||
      rateState.byteCount > MAX_WS_BYTES_PER_SEC
    ) {
      ddosTelemetry.droppedMessages++;
      if (rateState.msgCount === MAX_WS_MSGS_PER_SEC + 1) {
        ddosTelemetry.rateLimitedClients++;
        rateState.violations++;
        ipRec.violations++;
      }
      // Disconnect & temporarily ban extreme flooders
      if (rateState.msgCount > MAX_WS_MSGS_PER_SEC * 2 || rateState.violations >= 8) {
        ipRec.bannedUntil = now + IP_BAN_DURATION_MS;
        ddosTelemetry.blockedConnections++;
        try {
          ws.close(1008, "Rate limit exceeded");
        } catch {}
      }
      return;
    }

    let msg;
    try {
      msg = JSON.parse(rawStr);
    } catch {
      ddosTelemetry.malformedPackets++;
      rateState.violations++;
      if (rateState.violations >= 5) {
        ipRec.bannedUntil = now + IP_BAN_DURATION_MS;
        try {
          ws.close(1008, "Malformed packets");
        } catch {}
      }
      return;
    }

    if (!msg || typeof msg.type !== "string") return;
    const handlerStart = process.hrtime.bigint();

    switch (msg.type) {
      // Host creates/configures a room (settings come from the Host device)
      // or Joiner joins an existing room (inherits the Host's room settings)
      case "host_room":
      case "join_room": {
        if (now - rateState.roomActionWindowStart > 10000) {
          rateState.roomActionWindowStart = now;
          rateState.roomActions = 0;
        }
        rateState.roomActions++;
        if (rateState.roomActions > MAX_ROOM_ACTIONS_PER_10S) {
          ddosTelemetry.droppedMessages++;
          break;
        }

        const isHosting = msg.type === "host_room";
        const clientToken = msg.clientToken
          ? String(msg.clientToken).trim().slice(0, 64)
          : null;
        const requestedMapType = resolveMapType(msg.mapType, msg.worldLimit);
        const suppliedPassword = String(msg.password || "").trim().slice(0, 32);
        const team = msg.team === "tan" ? "tan" : "green";
        const name = String(msg.name || "Washington").slice(0, 18);
        const requestedGreen = Number(msg.greenTotal) || 4;
        const requestedTan = Number(msg.tanTotal) || 4;
        const requestedLimit = resolveWorldLimit(requestedMapType, msg.worldLimit);
        const requestedHardcore = Boolean(msg.hardcoreMode);
        const requestedDuration = Number(msg.durationSec) || 300;

        if (isHosting) {
          // Check if this host already has an existing room (active or waiting on end screen)
          // so that starting a new match pulls all connected players in their room into the new match!
          let existingHostRoom = null;
          if (currentRoom && isRoomOwner(currentRoom, clientId, clientToken)) {
            existingHostRoom = currentRoom;
          } else if (clientToken) {
            for (const r of rooms.values()) {
              if (r.originalHostToken === clientToken) {
                existingHostRoom = r;
                break;
              }
            }
          }

          if (currentRoom && currentRoom !== existingHostRoom) {
            removeClientFromRoom(currentRoom, clientId);
            currentRoom = null;
          }

          if (existingHostRoom) {
            // Evict any stale socket belonging to the same clientToken
            if (clientToken) {
              for (const [cid, c] of existingHostRoom.clients.entries()) {
                if (cid !== clientId && c.clientToken === clientToken) {
                  existingHostRoom.clients.delete(cid);
                  try {
                    c.ws.close(4001, "Duplicate session replaced");
                  } catch {}
                }
              }
            }

            // Update generated room codes when the host changes maps.
            const prefix = requestedMapType === "kitchen" ? "KITC" : requestedMapType === "shoebox" ? "SHOE" : "SAND";
            const cleanedReq = sanitizeCode(msg.roomCode, requestedMapType);
            let nextRoomCode = existingHostRoom.code;
            if (
              (existingHostRoom.code.startsWith("SAND") ||
                existingHostRoom.code.startsWith("SHOE") ||
                existingHostRoom.code.startsWith("KITC")) &&
              !existingHostRoom.code.startsWith(prefix)
            ) {
              nextRoomCode = allocateUniqueRoomCode(cleanedReq, requestedMapType);
            } else if (
              cleanedReq &&
              cleanedReq !== existingHostRoom.code &&
              !cleanedReq.startsWith("SAND") &&
              !cleanedReq.startsWith("SHOE") &&
              !cleanedReq.startsWith("KITC") &&
              !rooms.has(cleanedReq)
            ) {
              nextRoomCode = cleanedReq;
            }
            if (nextRoomCode !== existingHostRoom.code) {
              rooms.delete(existingHostRoom.code);
              existingHostRoom.code = nextRoomCode;
              rooms.set(nextRoomCode, existingHostRoom);
            }

            existingHostRoom.hostId = clientId;
            existingHostRoom.originalHostClientId = clientId;
            if (clientToken) {
              existingHostRoom.originalHostToken = clientToken;
            }
            existingHostRoom.hostName = name;
            existingHostRoom.originalHostName = name;
            existingHostRoom.password = suppliedPassword;
            existingHostRoom.greenTotal = Math.max(
              1,
              Math.min(MAX_BOTS_PER_TEAM + 1, Math.floor(requestedGreen))
            );
            existingHostRoom.tanTotal = Math.max(
              1,
              Math.min(MAX_BOTS_PER_TEAM + 1, Math.floor(requestedTan))
            );
            existingHostRoom.mapType = requestedMapType;
            existingHostRoom.worldLimit = requestedLimit;
            existingHostRoom.hardcoreMode = requestedHardcore;
            existingHostRoom.durationSec = Math.max(60, Math.min(1800, requestedDuration));

            const { maxX: spawnMaxX, minZ: spawnMinZ, maxZ: spawnMaxZ } = getSpawnBounds(existingHostRoom);

            // Upsert host client in existingHostRoom.clients
            let hostClient = existingHostRoom.clients.get(clientId);
            if (!hostClient) {
              hostClient = {
                id: clientId,
                clientToken,
                ws,
                name,
                team,
                slotIndex: 0,
                unitId: `${team}_0`,
                x: 0,
                y: 0,
                z: 0,
                yaw: team === "green" ? 0 : Math.PI,
                pitch: 0,
                health: 100,
                alive: true
              };
              existingHostRoom.clients.set(clientId, hostClient);
            } else {
              hostClient.ws = ws;
              hostClient.clientToken = clientToken || hostClient.clientToken;
              hostClient.name = name;
              hostClient.team = team;
            }

            // Reassign non-colliding slot indices per team (host gets slot 0 on their chosen team)
            let greenSlotCounter = team === "green" ? 1 : 0;
            let tanSlotCounter = team === "tan" ? 1 : 0;
            hostClient.slotIndex = 0;
            hostClient.unitId = `${team}_0`;

            for (const c of existingHostRoom.clients.values()) {
              if (c.id !== clientId) {
                if (c.team === "green") {
                  c.slotIndex = greenSlotCounter++;
                } else {
                  c.slotIndex = tanSlotCounter++;
                }
                c.unitId = `${c.team}_${c.slotIndex}`;
              }
              const rX = Math.round((Math.random() * 2 - 1) * spawnMaxX * 100) / 100;
              const rZMag =
                Math.round((spawnMinZ + Math.random() * (spawnMaxZ - spawnMinZ)) * 100) / 100;
              c.x = rX;
              c.y = 0;
              c.z = c.team === "green" ? -rZMag : rZMag;
              c.yaw = c.team === "green" ? 0 : Math.PI;
              c.pitch = 0;
              c.health = 100;
              c.alive = true;
            }

            const totalGreenHumans = team === "green" ? greenSlotCounter : greenSlotCounter;
            const totalTanHumans = team === "tan" ? tanSlotCounter : tanSlotCounter;
            if (totalGreenHumans > existingHostRoom.greenTotal) {
              existingHostRoom.greenTotal = Math.min(MAX_BOTS_PER_TEAM + 1, totalGreenHumans);
            }
            if (totalTanHumans > existingHostRoom.tanTotal) {
              existingHostRoom.tanTotal = Math.min(MAX_BOTS_PER_TEAM + 1, totalTanHumans);
            }

            resetRoomMatchState(existingHostRoom);
            existingHostRoom.matchId++;
            currentRoom = existingHostRoom;

            const rosterSnapshot = serializeRoster(existingHostRoom);

            safeSend(ws, {
              type: "room_joined",
              clientId,
              unitId: hostClient.unitId,
              team: hostClient.team,
              slotIndex: hostClient.slotIndex,
              isHost: true,
              isHostOwner: true,
              roster: rosterSnapshot
            });

            if (existingHostRoom.clients.size > 1) {
              broadcastToRoom(
                existingHostRoom,
                {
                  type: "match_restarted",
                  startedByHost: true,
                  hostName: name,
                  roster: rosterSnapshot
                },
                clientId
              );
            }
            break;
          }

          // Brand-new hosted room
          const roomCode = allocateUniqueRoomCode(msg.roomCode, requestedMapType);
          const room = getOrCreateRoom(
            roomCode,
            requestedGreen,
            requestedTan,
            name,
            requestedLimit,
            requestedDuration,
            requestedMapType,
            requestedHardcore,
            suppliedPassword,
            clientToken
          );

          room.hostId = clientId;
          room.originalHostClientId = clientId;
          room.originalHostToken = clientToken;
          room.hostName = name;
          room.originalHostName = name;
          room.password = suppliedPassword;
          room.greenTotal = Math.max(
            1,
            Math.min(MAX_BOTS_PER_TEAM + 1, Math.floor(requestedGreen))
          );
          room.tanTotal = Math.max(
            1,
            Math.min(MAX_BOTS_PER_TEAM + 1, Math.floor(requestedTan))
          );
          room.mapType = requestedMapType;
          room.worldLimit = requestedLimit;
          room.hardcoreMode = requestedHardcore;
          room.durationSec = Math.max(60, Math.min(1800, requestedDuration));
          resetRoomMatchState(room);

          const slotIndex = assignSlotForPlayer(room, team);
          const unitId = `${team}_${slotIndex}`;
          getUnitStat(room, unitId);
          const { maxX: spawnMaxX, minZ: spawnMinZ, maxZ: spawnMaxZ } = getSpawnBounds(room);
          const randX = Math.round((Math.random() * 2 - 1) * spawnMaxX * 100) / 100;
          const randZMag =
            Math.round((spawnMinZ + Math.random() * (spawnMaxZ - spawnMinZ)) * 100) / 100;

          const clientInfo = {
            id: clientId,
            clientToken,
            ws,
            name,
            team,
            slotIndex,
            unitId,
            x: randX,
            y: 0,
            z: team === "green" ? -randZMag : randZMag,
            yaw: team === "green" ? 0 : Math.PI,
            pitch: 0,
            health: 100,
            alive: true
          };

          room.clients.set(clientId, clientInfo);
          currentRoom = room;

          const rosterSnapshot = serializeRoster(room);

          safeSend(ws, {
            type: "room_joined",
            clientId,
            unitId,
            team,
            slotIndex,
            isHost: true,
            isHostOwner: true,
            roster: rosterSnapshot
          });
          break;
        }

        // ----- JOIN EXISTING ROOM (OR RECONNECT AS HOST / PLAYER) -----
        const targetCode = sanitizeCode(msg.roomCode, requestedMapType);
        const existingRoom = rooms.get(targetCode);
        const isReturningHost = Boolean(
          existingRoom &&
            clientToken &&
            existingRoom.originalHostToken &&
            existingRoom.originalHostToken === clientToken
        );

        if (existingRoom && (existingRoom.endedByHost || existingRoom.matchEnded)) {
          safeSend(ws, {
            type: "join_error",
            reason: "match_ended",
            roomCode: targetCode,
            message: `Match ${targetCode} has already ended.`
          });
          break;
        }

        if (!existingRoom && (msg.isReconnect || clientToken)) {
          safeSend(ws, {
            type: "join_error",
            reason: "room_not_found",
            roomCode: targetCode,
            message: `Match ${targetCode} is no longer active.`
          });
          break;
        }

        if (
          existingRoom &&
          existingRoom.password &&
          !isReturningHost &&
          existingRoom.password !== suppliedPassword
        ) {
          safeSend(ws, {
            type: "join_error",
            reason: "bad_password",
            roomCode: targetCode,
            message: `Incorrect password for room ${targetCode}.`
          });
          break;
        }

        if (currentRoom && currentRoom !== existingRoom) {
          removeClientFromRoom(currentRoom, clientId);
          currentRoom = null;
        }

        const roomExisted = Boolean(existingRoom);
        const room =
          existingRoom ||
          getOrCreateRoom(
            targetCode,
            requestedGreen,
            requestedTan,
            name,
            requestedLimit,
            requestedDuration,
            requestedMapType,
            requestedHardcore,
            ""
          );

        // Check if this clientToken had an existing/stale socket or saved disconnected slot in this room
        let restoredSlot = null;
        if (clientToken) {
          for (const [cid, c] of room.clients.entries()) {
            if (cid !== clientId && c.clientToken === clientToken) {
              restoredSlot = {
                slotIndex: c.slotIndex,
                team: c.team,
                unitId: c.unitId,
                x: c.x,
                y: c.y,
                z: c.z,
                yaw: c.yaw
              };
              room.clients.delete(cid);
              if (room.dirtyPlayers) room.dirtyPlayers.delete(cid);
              try {
                c.ws.close(4001, "Duplicate session replaced");
              } catch {}
            }
          }
          if (!restoredSlot && room.disconnectedPlayers && room.disconnectedPlayers.has(clientToken)) {
            restoredSlot = room.disconnectedPlayers.get(clientToken);
            room.disconnectedPlayers.delete(clientToken);
          }
        }

        if (room.clients.has(clientId)) {
          room.clients.delete(clientId);
        }

        if (!roomExisted) {
          room.hostId = clientId;
          room.hostName = name;
          room.originalHostName = name;
        } else if (isReturningHost) {
          room.hostId = clientId;
          room.originalHostClientId = clientId;
          room.hostName = name;
          room.originalHostName = name;
        } else if (!room.hostId || !room.clients.has(room.hostId)) {
          // Original host is temporarily offline; let this connected client simulate AI until original host returns
          room.hostId = clientId;
        }

        const finalTeam =
          msg.isReconnect && restoredSlot && (restoredSlot.team === "green" || restoredSlot.team === "tan")
            ? restoredSlot.team
            : team;

        let slotIndex = -1;
        if (restoredSlot && restoredSlot.team === finalTeam) {
          let slotTaken = false;
          for (const c of room.clients.values()) {
            if (c.team === finalTeam && c.slotIndex === restoredSlot.slotIndex) {
              slotTaken = true;
              break;
            }
          }
          if (!slotTaken) {
            slotIndex = restoredSlot.slotIndex;
          }
        }
        if (slotIndex < 0) {
          slotIndex = assignSlotForPlayer(room, finalTeam);
        }

        // Expand team total only if more humans join than current total (capped at MAX_BOTS_PER_TEAM + 1)
        if (finalTeam === "green" && slotIndex + 1 > room.greenTotal) {
          room.greenTotal = Math.min(MAX_BOTS_PER_TEAM + 1, slotIndex + 1);
        } else if (finalTeam === "tan" && slotIndex + 1 > room.tanTotal) {
          room.tanTotal = Math.min(MAX_BOTS_PER_TEAM + 1, slotIndex + 1);
        }

        const unitId = `${finalTeam}_${slotIndex}`;
        const unitStat = getUnitStat(room, unitId);
        let revivedDeadUnit = false;
        if (!unitStat.alive || unitStat.health <= 0) {
          unitStat.health = 100;
          unitStat.alive = true;
          room.statsDirty = true;
          room.statsDirtyForSync = true;
          revivedDeadUnit = true;
        }

        const { maxX: spawnMaxX, minZ: spawnMinZ, maxZ: spawnMaxZ } = getSpawnBounds(room);
        const randX = Math.round((Math.random() * 2 - 1) * spawnMaxX * 100) / 100;
        const randZMag =
          Math.round((spawnMinZ + Math.random() * (spawnMaxZ - spawnMinZ)) * 100) / 100;

        const spawnX =
          restoredSlot && restoredSlot.team === finalTeam && typeof restoredSlot.x === "number"
            ? restoredSlot.x
            : randX;
        const spawnY =
          restoredSlot && restoredSlot.team === finalTeam && typeof restoredSlot.y === "number"
            ? restoredSlot.y
            : 0;
        const spawnZ =
          restoredSlot && restoredSlot.team === finalTeam && typeof restoredSlot.z === "number"
            ? restoredSlot.z
            : finalTeam === "green"
            ? -randZMag
            : randZMag;
        const spawnYaw =
          restoredSlot && restoredSlot.team === finalTeam && typeof restoredSlot.yaw === "number"
            ? restoredSlot.yaw
            : finalTeam === "green"
            ? 0
            : Math.PI;

        const clientInfo = {
          id: clientId,
          clientToken,
          ws,
          name,
          team: finalTeam,
          slotIndex,
          unitId,
          x: spawnX,
          y: spawnY,
          z: spawnZ,
          yaw: spawnYaw,
          pitch: 0,
          health: unitStat.health,
          alive: unitStat.alive
        };

        room.clients.set(clientId, clientInfo);
        currentRoom = room;

        const rosterSnapshot = serializeRoster(room);
        const isHostOwner = Boolean(
          isReturningHost || (!room.originalHostToken && room.hostId === clientId)
        );

        // Send welcome packet to joining/reconnecting client
        safeSend(ws, {
          type: "room_joined",
          clientId,
          unitId,
          team: finalTeam,
          slotIndex,
          isHost: room.hostId === clientId,
          isHostOwner,
          rejoined: Boolean(restoredSlot || isReturningHost),
          roster: rosterSnapshot,
          world: room.lastWorldState || null
        });

        // Notify everyone else in the room (skip serialization if solo host)
        if (room.clients.size > 1) {
          broadcastToRoom(
            room,
            {
              type: "roster_update",
              event: isReturningHost ? "host_rejoined" : "player_joined",
              player: { id: clientId, name, team: finalTeam, unitId },
              roster: rosterSnapshot
            },
            clientId
          );
          if (revivedDeadUnit) {
            broadcastToRoom(
              room,
              {
                type: "unit_respawned",
                senderClientId: clientId,
                unitId,
                playerName: name,
                team: finalTeam,
                isAI: false,
                x: spawnX,
                y: spawnY,
                z: spawnZ,
                yaw: spawnYaw,
                unitStats: {
                  [unitId]: {
                    kills: unitStat.kills,
                    deaths: unitStat.deaths,
                    health: unitStat.health,
                    alive: unitStat.alive
                  }
                }
              },
              clientId
            );
          }
        }
        break;
      }

      // Live transform/animation update from a human player (~25 Hz)
      case "player_state": {
        if (!currentRoom) break;
        const c = currentRoom.clients.get(clientId);
        if (!c) break;

        c.x = Math.round((Number(msg.x) || 0) * 100) / 100;
        c.y = Math.round((Number(msg.y) || 0) * 100) / 100;
        c.z = Math.round((Number(msg.z) || 0) * 100) / 100;
        c.yaw = Math.round((Number(msg.yaw) || 0) * 100) / 100;
        c.pitch = Math.round((Number(msg.pitch) || 0) * 100) / 100;
        c.moveBlend = Math.round((Number(msg.moveBlend) || 0) * 100) / 100;
        c.strideDir = Math.round((Number(msg.strideDir) || 0) * 100) / 100;

        // Skip broadcast if this player is the only human in the room
        if (currentRoom.clients.size <= 1) break;

        // Coalesce into the room's 25 Hz (40ms) tick flush
        currentRoom.dirtyPlayers.set(clientId, {
          clientId,
          unitId: c.unitId,
          x: c.x,
          y: c.y,
          z: c.z,
          yaw: c.yaw,
          pitch: c.pitch,
          moveBlend: c.moveBlend,
          strideDir: c.strideDir
        });
        break;
      }

      // Room Host broadcasts AI soldier states & dynamic beach ball state (~12-20 Hz)
      case "host_world_state": {
        if (!currentRoom || currentRoom.hostId !== clientId) break;
        const remainingSec =
          Math.round(Math.max(0, (currentRoom.matchEndTime - now) / 1000) * 10) / 10;
        const maxAiCount = MAX_BOTS_PER_TEAM * 2;
        const worldSnap = {
          remainingSec,
          matchEnded: currentRoom.matchEnded,
          aiPacked: Array.isArray(msg.aiPacked) ? msg.aiPacked.slice(0, maxAiCount) : null,
          aiUnits: Array.isArray(msg.aiUnits) ? msg.aiUnits.slice(0, maxAiCount) : null,
          ball: msg.ball || null
        };
        currentRoom.lastWorldState = worldSnap;
        if (currentRoom.clients.size <= 1) break; // Skip broadcast flush if host is the only player in room
        currentRoom.pendingWorldState = worldSnap;
        break;
      }

      // Weapon fired (coalesced into the 25 Hz room flush to avoid O(N^2) per-shot socket writes)
      case "fire_shot": {
        if (!currentRoom || currentRoom.clients.size <= 1) break;
        if (currentRoom.pendingShots.length < 32) {
          currentRoom.pendingShots.push({
            shooterClientId: clientId,
            shooterUnitId: msg.shooterUnitId,
            team: msg.team,
            muzzlePos: msg.muzzlePos,
            hitPoint: msg.hitPoint,
            hitKind: msg.hitKind
          });
        }
        break;
      }

      // Authoritative damage & Kill/Death tracking across all clients in the room
      case "damage_unit": {
        if (!currentRoom || currentRoom.matchEnded) break;
        const targetUnitId = String(msg.targetUnitId || "");
        const tableFall = msg.cause === "table_fall";
        let fallPosition = null;
        if (tableFall) {
          const pos = msg.fallPosition;
          const sender = currentRoom.clients.get(clientId);
          const targetIsHuman = Array.from(currentRoom.clients.values()).some((c) => c.unitId === targetUnitId);
          if (currentRoom.mapType !== "kitchen" || !currentRoom.unitStats.has(targetUnitId) || !sender ||
              (sender.unitId !== targetUnitId && (currentRoom.hostId !== clientId || targetIsHuman)) ||
              !pos || ![pos.x, pos.y, pos.z].every(Number.isFinite) ||
              (Math.abs(pos.x) <= 48 && Math.abs(pos.z) <= 64)) break;
          fallPosition = { x: pos.x, y: pos.y, z: pos.z };
        }
        const attackerUnitId = !tableFall && msg.attackerUnitId ? String(msg.attackerUnitId) : null;
        const rawAmount = Math.max(0, Number(msg.amount) || 0);
        const amount = tableFall ? 100 : currentRoom.hardcoreMode ? Math.max(rawAmount, 100) : rawAmount;
        if (!targetUnitId || amount <= 0) break;

        const targetStat = getUnitStat(currentRoom, targetUnitId);
        if (!targetStat.alive) break; // Already eliminated; ignore duplicate hit packets

        targetStat.health = Math.max(0, targetStat.health - amount);
        let killed = false;
        if (targetStat.health <= 0) {
          targetStat.alive = false;
          targetStat.deaths += 1;
          killed = true;
          if (attackerUnitId && attackerUnitId !== targetUnitId) {
            const attackerStat = getUnitStat(currentRoom, attackerUnitId);
            attackerStat.kills += 1;
          }
        }
        currentRoom.statsDirty = true;
        currentRoom.statsDirtyForSync = true;

        const deltaStats = {
          [targetUnitId]: {
            kills: targetStat.kills,
            deaths: targetStat.deaths,
            health: targetStat.health,
            alive: targetStat.alive
          }
        };
        if (attackerUnitId && attackerUnitId !== targetUnitId) {
          const att = getUnitStat(currentRoom, attackerUnitId);
          deltaStats[attackerUnitId] = {
            kills: att.kills,
            deaths: att.deaths,
            health: att.health,
            alive: att.alive
          };
        }

        const dmgEvent = {
          type: "unit_damaged",
          targetUnitId,
          attackerUnitId,
          amount,
          health: targetStat.health,
          alive: targetStat.alive,
          killed,
          shotDir: msg.shotDir || null,
          unitStats: deltaStats
        };
        if (tableFall) {
          dmgEvent.cause = "table_fall";
          dmgEvent.fallPosition = fallPosition;
        }

        // For 1-player rooms, reply immediately; for multi-player rooms, coalesce into 25 Hz room_tick
        if (currentRoom.clients.size <= 1) {
          safeSend(ws, dmgEvent);
        } else if (currentRoom.pendingDamages.length < 32) {
          currentRoom.pendingDamages.push(dmgEvent);
        }
        break;
      }

      // Beach ball impulse (kicked or shot)
      case "ball_impulse": {
        if (!currentRoom || currentRoom.clients.size <= 1) break;
        broadcastToRoom(
          currentRoom,
          {
            type: "ball_impulse",
            vx: Number(msg.vx) || 0,
            vy: Number(msg.vy) || 0,
            vz: Number(msg.vz) || 0
          },
          clientId
        );
        break;
      }

      // Individual player (or Host auto-respawning AI) respawns a single soldier without resetting the match
      case "respawn_unit": {
        if (!currentRoom || currentRoom.matchEnded) break;
        const c = currentRoom.clients.get(clientId);
        if (!c) break;

        const targetUnitId = msg.unitId || c.unitId;
        const targetStat = getUnitStat(currentRoom, targetUnitId);
        targetStat.health = 100;
        targetStat.alive = true;
        currentRoom.statsDirty = true;
        currentRoom.statsDirtyForSync = true;

        const isSelf = targetUnitId === c.unitId;
        if (isSelf) {
          c.health = 100;
          c.alive = true;
          c.x = Number(msg.x) || 0;
          c.y = Number(msg.y) || 0;
          c.z = Number(msg.z) || 0;
          c.yaw = Number(msg.yaw) || 0;
        }

        if (currentRoom.clients.size > 1 && currentRoom.pendingRespawns.length < 32) {
          currentRoom.pendingRespawns.push({
            type: "unit_respawned",
            senderClientId: clientId,
            unitId: targetUnitId,
            playerName: isSelf ? c.name : null,
            team: msg.team || c.team,
            isAI: Boolean(msg.isAI),
            x: Number(msg.x) || 0,
            y: Number(msg.y) || 0,
            z: Number(msg.z) || 0,
            yaw: Number(msg.yaw) || 0,
            unitStats: {
              [targetUnitId]: {
                kills: targetStat.kills,
                deaths: targetStat.deaths,
                health: targetStat.health,
                alive: targetStat.alive
              }
            }
          });
        }
        break;
      }

      // Ping / Pong + Server & Client Performance Telemetry
      case "ping": {
        if (msg.clientPerf && typeof msg.clientPerf === "object") {
          const cp = msg.clientPerf;
          perfMetrics.clientProfiles.set(clientId, {
            clientId,
            mode: "multiplayer",
            roomCode: currentRoom ? currentRoom.code : null,
            mapType: currentRoom ? currentRoom.mapType : cp.mapType || "sandbox",
            fps: Number(Number(cp.fps || 0).toFixed(1)),
            frameMs: Number(Number(cp.frameMs || 0).toFixed(2)),
            renderMs: Number(Number(cp.renderMs || 0).toFixed(2)),
            physicsMs: Number(Number(cp.physicsMs || 0).toFixed(2)),
            aiMs: Number(Number(cp.aiMs || 0).toFixed(2)),
            animMs: Number(Number(cp.animMs || 0).toFixed(2)),
            aliveUnits: Number(cp.aliveUnits) || 0,
            totalUnits: Number(cp.totalUnits) || 0,
            updatedAt: now
          });
        }
        safeSend(ws, {
          type: "pong",
          clientTime: msg.clientTime,
          serverTickMs: Number(lastServerTickMs.toFixed(2)),
          serverMemMB: Math.round(cachedRssMB)
        });
        break;
      }

      // Host explicitly ends the match from the menu, notifying all players in the room
      case "end_match": {
        const clientToken = msg.clientToken
          ? String(msg.clientToken).trim().slice(0, 64)
          : null;
        let targetRoom = currentRoom;
        if (!targetRoom && msg.roomCode) {
          targetRoom = rooms.get(String(msg.roomCode).toUpperCase().trim()) || null;
        }
        if (!targetRoom) break;

        if (!isRoomOwner(targetRoom, clientId, clientToken)) break;

        endRoomByHost(targetRoom);
        break;
      }

      // Restart match for everyone in the room (only the room Host can alter room settings)
      case "restart_match": {
        if (!currentRoom) break;
        const clientToken = msg.clientToken
          ? String(msg.clientToken).trim().slice(0, 64)
          : null;
        const isRoomHost = isRoomOwner(currentRoom, clientId, clientToken);
        if (!isRoomHost) break;

        if (isRoomHost) {
          if (msg.greenTotal) {
            currentRoom.greenTotal = Math.max(1, Math.min(MAX_BOTS_PER_TEAM + 1, Math.floor(Number(msg.greenTotal))));
          }
          if (msg.tanTotal) {
            currentRoom.tanTotal = Math.max(1, Math.min(MAX_BOTS_PER_TEAM + 1, Math.floor(Number(msg.tanTotal))));
          }
          if (msg.mapType === "shoebox" || msg.mapType === "sandbox" || msg.mapType === "kitchen") {
            currentRoom.mapType = msg.mapType;
          }
          if (msg.worldLimit) {
            currentRoom.mapType = resolveMapType(currentRoom.mapType, msg.worldLimit);
            currentRoom.worldLimit = resolveWorldLimit(currentRoom.mapType, msg.worldLimit);
          }
          currentRoom.worldLimit = resolveWorldLimit(currentRoom.mapType, currentRoom.worldLimit);
          if (typeof msg.hardcoreMode === "boolean") {
            currentRoom.hardcoreMode = msg.hardcoreMode;
          }
          if (msg.durationSec) {
            currentRoom.durationSec = Math.max(60, Math.min(1800, Number(msg.durationSec)));
          }
        }
        resetRoomMatchState(currentRoom);
        currentRoom.matchId++;

        broadcastToRoom(currentRoom, {
          type: "match_restarted",
          startedByHost: true,
          hostName: currentRoom.originalHostName || currentRoom.hostName || "Host",
          roster: serializeRoster(currentRoom)
        });
        break;
      }
    }

    const handlerEnd = process.hrtime.bigint();
    recordMsgProfile(msg.type, Number(handlerEnd - handlerStart) / 1e6);
  });

  ws.on("close", () => {
    ipRec.connCount = Math.max(0, ipRec.connCount - 1);
    perfMetrics.clientProfiles.delete(clientId);
    if (currentRoom) {
      removeClientFromRoom(currentRoom, clientId);
      currentRoom = null;
    }
  });

  ws.on("error", () => {
    // Prevent unhandled socket error events from crashing the server process
  });
});

function removeClientFromRoom(room, clientId) {
  const leaving = room.clients.get(clientId);
  room.clients.delete(clientId);
  if (room.dirtyPlayers) {
    room.dirtyPlayers.delete(clientId);
  }
  if (leaving && leaving.clientToken && !room.matchEnded && !room.endedByHost) {
    if (!room.disconnectedPlayers) room.disconnectedPlayers = new Map();
    room.disconnectedPlayers.set(leaving.clientToken, {
      slotIndex: leaving.slotIndex,
      team: leaving.team,
      unitId: leaving.unitId,
      name: leaving.name,
      x: leaving.x,
      y: leaving.y,
      z: leaving.z,
      yaw: leaving.yaw
    });
  }
  if (room.originalHostClientId === clientId) {
    room.originalHostClientId = null;
  }

  const isMatchStillRunning =
    !room.matchEnded && !room.endedByHost && Date.now() < room.matchEndTime;

  if (room.clients.size === 0) {
    room.hostId = null;
    room.hostName = room.originalHostName || room.hostName || "Host";
    // Persist the match until it is over or explicitly ended by the host!
    if (!isMatchStillRunning) {
      rooms.delete(room.code);
    }
    return;
  }

  // If the simulation authority left while other players remain, assign temporary simulation authority
  // so the match stays going until the original host reconnects
  if (room.hostId === clientId) {
    if (room.originalHostClientId && room.clients.has(room.originalHostClientId)) {
      const orig = room.clients.get(room.originalHostClientId);
      room.hostId = orig.id;
      room.hostName = orig.name;
    } else {
      const nextEntry = room.clients.values().next().value;
      room.hostId = nextEntry ? nextEntry.id : null;
      if (!room.originalHostName && nextEntry) {
        room.hostName = nextEntry.name;
      }
    }
  }

  broadcastToRoom(room, {
    type: "roster_update",
    event: "player_left",
    player: leaving
      ? { id: leaving.id, name: leaving.name, team: leaving.team, unitId: leaving.unitId }
      : null,
    roster: serializeRoster(room)
  });
}

// 25 Hz (40ms) Unified Room Broadcast Flush (Coalesces player_state, fire_shot, damage_unit, respawn_unit & host_world_state)
// Eliminates O(N^2) per-packet JSON.stringify & ws.send storms across all active rooms!
setInterval(() => {
  for (const room of rooms.values()) {
    const hasPlayers = room.dirtyPlayers && room.dirtyPlayers.size > 0;
    const hasShots = room.pendingShots && room.pendingShots.length > 0;
    const hasDamages = room.pendingDamages && room.pendingDamages.length > 0;
    const hasRespawns = room.pendingRespawns && room.pendingRespawns.length > 0;
    const hasWorld = room.pendingWorldState !== null;

    if (!hasPlayers && !hasShots && !hasDamages && !hasRespawns && !hasWorld) continue;

    if (room.clients.size <= 1) {
      if (hasPlayers) room.dirtyPlayers.clear();
      if (hasShots) room.pendingShots.length = 0;
      if (hasDamages) room.pendingDamages.length = 0;
      if (hasRespawns) room.pendingRespawns.length = 0;
      room.pendingWorldState = null;
      continue;
    }

    // Fast path: only 1 player moved and nothing else happened
    if (hasPlayers && room.dirtyPlayers.size === 1 && !hasShots && !hasDamages && !hasRespawns && !hasWorld) {
      const single = room.dirtyPlayers.values().next().value;
      room.dirtyPlayers.clear();
      broadcastToRoom(
        room,
        {
          type: "remote_player_state",
          clientId: single.clientId,
          unitId: single.unitId,
          x: single.x,
          y: single.y,
          z: single.z,
          yaw: single.yaw,
          pitch: single.pitch,
          moveBlend: single.moveBlend,
          strideDir: single.strideDir
        },
        single.clientId
      );
      continue;
    }

    // Unified room_tick or remote_players_batch packet (1 JSON.stringify + 1 ws.send per client!)
    const playersArr = hasPlayers ? Array.from(room.dirtyPlayers.values()) : null;
    const shotsArr = hasShots ? room.pendingShots.slice() : null;
    const damagesArr = hasDamages ? room.pendingDamages.slice() : null;
    const respawnsArr = hasRespawns ? room.pendingRespawns.slice() : null;
    const worldObj = room.pendingWorldState;

    if (hasPlayers) room.dirtyPlayers.clear();
    if (hasShots) room.pendingShots.length = 0;
    if (hasDamages) room.pendingDamages.length = 0;
    if (hasRespawns) room.pendingRespawns.length = 0;
    room.pendingWorldState = null;

    if (playersArr && !shotsArr && !damagesArr && !respawnsArr && !worldObj) {
      broadcastToRoom(
        room,
        {
          type: "remote_players_batch",
          players: playersArr
        },
        null
      );
    } else {
      broadcastToRoom(
        room,
        {
          type: "room_tick",
          players: playersArr,
          shots: shotsArr,
          damages: damagesArr,
          respawns: respawnsArr,
          world: worldObj
        },
        null
      );
    }
  }
}, 40);

// ============================================================================
// 3. SERVER-AUTHORITATIVE MATCH TIMER, SCOREBOARD SYNC & TELEMETRY LOOP
// ============================================================================
let tickCounter = 0;
let lastServerTickMs = 0.1;

setInterval(() => {
  const tickStart = process.hrtime.bigint();
  tickCounter++;
  const now = Date.now();
  const currentSyncSlot = tickCounter & 7;

  for (const room of rooms.values()) {
    const remainingSec = Math.max(0, (room.matchEndTime - now) / 1000);

    // Trigger simultaneous match end for all players when the server clock hits 0
    if (remainingSec <= 0 && !room.matchEnded) {
      room.matchEnded = true;
      if (room.clients.size === 0) {
        rooms.delete(room.code);
        continue;
      }
      broadcastToRoom(
        room,
        {
          type: "match_ended",
          remainingSec: 0,
          unitStats: serializeUnitStats(room),
          roster: serializeRoster(room)
        },
        null
      );
      continue;
    }

    if (room.clients.size === 0) {
      if (room.matchEnded || room.endedByHost) {
        rooms.delete(room.code);
      }
      continue;
    }

    // Staggered 2-second lightweight clock sync (only 12.5% of rooms per 250ms tick)
    if (!room.matchEnded && room.syncSlot === currentSyncSlot) {
      broadcastToRoom(
        room,
        {
          type: "timer_sync",
          remainingSec: Math.round(remainingSec * 10) / 10,
          matchEnded: room.matchEnded
        },
        null
      );
    }
  }

  const tickEnd = process.hrtime.bigint();
  lastServerTickMs = Number(tickEnd - tickStart) / 1e6;
  perfMetrics.tickHistoryMs.push(lastServerTickMs);
  if (perfMetrics.tickHistoryMs.length > 120) {
    perfMetrics.tickHistoryMs.shift();
  }

  // Once per second: sample memory, packet/bandwidth rates & append to 60s rolling history
  if (tickCounter % 4 === 0) {
    const mem = process.memoryUsage();
    cachedRssMB = Number((mem.rss / (1024 * 1024)).toFixed(1));
    cachedHeapUsedMB = Number((mem.heapUsed / (1024 * 1024)).toFixed(1));
    cachedHeapTotalMB = Number((mem.heapTotal / (1024 * 1024)).toFixed(1));

    const elapsedSec = Math.max(0.1, (now - perfMetrics._lastRateSampleTime) / 1000);
    perfMetrics.inboundPktsSec = Math.round(perfMetrics._inPktsAccum / elapsedSec);
    perfMetrics.outboundPktsSec = Math.round(perfMetrics._outPktsAccum / elapsedSec);
    perfMetrics.inboundBytesSec = Math.round(perfMetrics._inBytesAccum / elapsedSec);
    perfMetrics.outboundBytesSec = Math.round(perfMetrics._outBytesAccum / elapsedSec);
    perfMetrics._inPktsAccum = 0;
    perfMetrics._outPktsAccum = 0;
    perfMetrics._inBytesAccum = 0;
    perfMetrics._outBytesAccum = 0;
    perfMetrics._lastRateSampleTime = now;

    const clientList = Array.from(perfMetrics.clientProfiles.values());
    const avgClientFps =
      clientList.length > 0
        ? Number((clientList.reduce((acc, c) => acc + (c.fps || 0), 0) / clientList.length).toFixed(1))
        : null;
    const recentTicks = perfMetrics.tickHistoryMs.slice(-4);
    const avgLastSecTickMs =
      recentTicks.length > 0
        ? recentTicks.reduce((a, b) => a + b, 0) / recentTicks.length
        : lastServerTickMs;

    perfMetrics.history.push({
      t: now,
      tickMs: Number(avgLastSecTickMs.toFixed(3)),
      rssMB: cachedRssMB,
      inboundPktPerSec: perfMetrics.inboundPktsSec,
      outboundPktPerSec: perfMetrics.outboundPktsSec,
      outboundKBPerSec: Number((perfMetrics.outboundBytesSec / 1024).toFixed(2)),
      activeRooms: rooms.size,
      avgClientFps
    });
    if (perfMetrics.history.length > 60) {
      perfMetrics.history.shift();
    }
  }
}, 250);

server.listen(PORT, () => {
  console.log(`Plastic Army Men Server running on http://localhost:${PORT}`);
});
