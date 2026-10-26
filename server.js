const http = require("http");
const fs = require("fs");
const path = require("path");
const { WebSocketServer, WebSocket } = require("ws");

const PORT = process.env.PORT || 3000;
const INDEX_PATH = path.join(__dirname, "index.html");
const FAVICON_DIR = path.join(__dirname, "favicon");

const FAVICON_MIME_TYPES = {
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".webmanifest": "application/manifest+json"
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

// ============================================================================
// 1. DDoS PROTECTION, RATE LIMITING & PERFORMANCE PROFILER STATE
// ============================================================================
const MAX_WS_PAYLOAD_BYTES = 16 * 1024; // 16 KB max frame size
const MAX_CONN_PER_IP = Number(process.env.MAX_CONN_PER_IP) || 24;
const MAX_WS_MSGS_PER_SEC = Number(process.env.MAX_WS_MSGS_PER_SEC) || 100;
const MAX_WS_BYTES_PER_SEC = Number(process.env.MAX_WS_BYTES_PER_SEC) || 96 * 1024;
const MAX_ROOM_ACTIONS_PER_10S = 10;
const MAX_HTTP_REQ_PER_10S = 120;
const IP_BAN_DURATION_MS = 30 * 1000;

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

function getRoomsSummary() {
  const summary = [];
  for (const room of rooms.values()) {
    summary.push(serializeRoster(room));
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
  const mem = process.memoryUsage();
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
      rssMB: Number((mem.rss / (1024 * 1024)).toFixed(1)),
      heapUsedMB: Number((mem.heapUsed / (1024 * 1024)).toFixed(1)),
      heapTotalMB: Number((mem.heapTotal / (1024 * 1024)).toFixed(1))
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
                "<td>" + (c.mapType === "shoebox" ? "Shoebox" : "Sandbox") + "</td>" +
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
                "<td>" + (r.mapType === "shoebox" ? "Shoebox" : "Sandbox") + "</td>" +
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
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        ok: true,
        roomCount: rooms.size,
        takenNames: getTakenPlayerNames(),
        rooms: getRoomsSummary()
      })
    );
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
          mapType: data.mapType === "shoebox" ? "shoebox" : "sandbox",
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

function sanitizeCode(raw, mapType = "sandbox") {
  const fallbackPrefix = mapType === "shoebox" ? "SHOE" : "SAND";
  const cleaned = String(raw || "")
    .toUpperCase()
    .replace(/[^A-Z0-9_-]/g, "")
    .slice(0, 12);
  return cleaned || `${fallbackPrefix}${Math.floor(100 + Math.random() * 900)}`;
}

function allocateUniqueRoomCode(requestedRaw, mapType = "sandbox") {
  const prefix = mapType === "shoebox" ? "SHOE" : "SAND";
  const cleaned = sanitizeCode(requestedRaw, mapType);
  // If the requested code matches the selected map prefix and is unused, keep it
  const matchesMapPrefix = cleaned.startsWith(prefix);
  if (cleaned && cleaned !== "SAND1" && cleaned !== "SHOE1" && matchesMapPrefix && !rooms.has(cleaned)) {
    return cleaned;
  }
  if (cleaned && !cleaned.startsWith("SAND") && !cleaned.startsWith("SHOE") && !rooms.has(cleaned)) {
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
  }
  return st;
}

function serializeUnitStats(room) {
  const obj = {};
  for (const [unitId, st] of room.unitStats.entries()) {
    obj[unitId] = {
      kills: st.kills,
      deaths: st.deaths,
      health: st.health,
      alive: st.alive
    };
  }
  return obj;
}

function resetRoomMatchState(room) {
  room.matchEndTime = Date.now() + room.durationSec * 1000;
  room.matchEnded = false;
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
  password
) {
  let room = rooms.get(roomCode);
  if (!room) {
    const dur = Math.max(60, Math.min(1800, Number(durationSec) || 300));
    const resolvedMap = mapType === "shoebox" || Number(worldLimit) <= 50 ? "shoebox" : "sandbox";
    const lim = resolvedMap === "shoebox"
      ? 28
      : Math.max(50, Math.min(130, Number(worldLimit) || 80));
    room = {
      code: roomCode,
      hostId: null,
      hostName: hostName || "Host",
      password: String(password || "").trim().slice(0, 32),
      greenTotal: Math.max(1, Math.floor(Number(greenTotal) || 4)),
      tanTotal: Math.max(1, Math.floor(Number(tanTotal) || 4)),
      mapType: resolvedMap,
      worldLimit: lim,
      hardcoreMode: Boolean(hardcoreMode),
      durationSec: dur,
      matchEndTime: Date.now() + dur * 1000,
      matchEnded: false,
      unitStats: new Map(),
      clients: new Map(), // Map<clientId, ClientInfo>
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
    hostName: room.hostName || "Host",
    hasPassword: Boolean(room.password),
    greenTotal: room.greenTotal,
    tanTotal: room.tanTotal,
    mapType: room.mapType || "sandbox",
    worldLimit: room.worldLimit,
    hardcoreMode: Boolean(room.hardcoreMode),
    durationSec: room.durationSec,
    remainingSec,
    matchEnded: room.matchEnded,
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
  let slot = 0;
  while (usedSlots.has(slot)) {
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
      if (rateState.msgCount > MAX_WS_MSGS_PER_SEC * 2 || rateState.violations >= 5) {
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
        const requestedMapType =
          msg.mapType === "shoebox" || Number(msg.worldLimit) <= 50 ? "shoebox" : "sandbox";
        const suppliedPassword = String(msg.password || "").trim().slice(0, 32);

        // If joining an existing room, verify password BEFORE leaving currentRoom or mutating state
        if (!isHosting) {
          const targetCode = sanitizeCode(msg.roomCode, requestedMapType);
          const existingRoom = rooms.get(targetCode);
          if (existingRoom && existingRoom.password && existingRoom.password !== suppliedPassword) {
            safeSend(ws, {
              type: "join_error",
              reason: "bad_password",
              roomCode: targetCode,
              message: `Incorrect password for room ${targetCode}.`
            });
            break;
          }
        }

        if (currentRoom) {
          removeClientFromRoom(currentRoom, clientId);
          currentRoom = null;
        }

        const roomCode = isHosting
          ? allocateUniqueRoomCode(msg.roomCode, requestedMapType)
          : sanitizeCode(msg.roomCode, requestedMapType);
        const team = msg.team === "tan" ? "tan" : "green";
        const name = String(msg.name || "Washington").slice(0, 18);
        const requestedGreen = Number(msg.greenTotal) || 4;
        const requestedTan = Number(msg.tanTotal) || 4;
        const requestedLimit =
          requestedMapType === "shoebox" ? 28 : Number(msg.worldLimit) || 80;
        const requestedHardcore = Boolean(msg.hardcoreMode);
        const requestedDuration = Number(msg.durationSec) || 300;

        const room = getOrCreateRoom(
          roomCode,
          requestedGreen,
          requestedTan,
          name,
          requestedLimit,
          requestedDuration,
          requestedMapType,
          requestedHardcore,
          isHosting ? suppliedPassword : ""
        );

        // If this device clicked Host (or room had no host), apply their match settings & reset round
        if (isHosting || !room.hostId) {
          room.hostId = clientId;
          room.hostName = name;
          if (isHosting) {
            room.password = suppliedPassword;
          }
          room.greenTotal = Math.max(1, Math.floor(requestedGreen));
          room.tanTotal = Math.max(1, Math.floor(requestedTan));
          room.mapType = requestedMapType;
          room.worldLimit =
            requestedMapType === "shoebox"
              ? 28
              : Math.max(50, Math.min(130, requestedLimit));
          room.hardcoreMode = requestedHardcore;
          room.durationSec = Math.max(60, Math.min(1800, requestedDuration));
          resetRoomMatchState(room);
        }

        const slotIndex = assignSlotForPlayer(room, team);
        // Expand team total only if more humans join than current total
        if (team === "green" && slotIndex + 1 > room.greenTotal) {
          room.greenTotal = slotIndex + 1;
        } else if (team === "tan" && slotIndex + 1 > room.tanTotal) {
          room.tanTotal = slotIndex + 1;
        }

        const unitId = `${team}_${slotIndex}`;
        getUnitStat(room, unitId);
        const spawnZ = room.mapType === "shoebox" ? 24 : 30;
        const clientInfo = {
          id: clientId,
          ws,
          name,
          team,
          slotIndex,
          unitId,
          x: 0,
          y: 0,
          z: team === "green" ? -spawnZ : spawnZ - 2,
          yaw: team === "green" ? 0 : Math.PI,
          pitch: 0,
          health: 100,
          alive: true
        };

        room.clients.set(clientId, clientInfo);
        currentRoom = room;

        console.log(
          `[${new Date().toISOString()}] [Room ${room.code}] ${name} (${clientId}) ${isHosting ? "HOSTED" : "joined"} ${team.toUpperCase()} as ${unitId} [${room.greenTotal}v${room.tanTotal}] (${room.clients.size} online)`
        );

        // Send welcome packet to joining/hosting client
        safeSend(ws, {
          type: "room_joined",
          clientId,
          unitId,
          team,
          slotIndex,
          isHost: room.hostId === clientId,
          roster: serializeRoster(room)
        });

        // Notify everyone else in the room
        broadcastToRoom(
          room,
          {
            type: "roster_update",
            event: "player_joined",
            player: { id: clientId, name, team, unitId },
            roster: serializeRoster(room)
          },
          clientId
        );
        break;
      }

      // Live transform/animation update from a human player (~25 Hz)
      case "player_state": {
        if (!currentRoom) break;
        const c = currentRoom.clients.get(clientId);
        if (!c) break;

        c.x = Number(msg.x) || 0;
        c.y = Number(msg.y) || 0;
        c.z = Number(msg.z) || 0;
        c.yaw = Number(msg.yaw) || 0;
        c.pitch = Number(msg.pitch) || 0;

        broadcastToRoom(
          currentRoom,
          {
            type: "remote_player_state",
            clientId,
            unitId: c.unitId,
            x: c.x,
            y: c.y,
            z: c.z,
            yaw: c.yaw,
            pitch: c.pitch,
            moveBlend: Number(msg.moveBlend) || 0,
            strideDir: Number(msg.strideDir) || 0
          },
          clientId
        );
        break;
      }

      // Room Host broadcasts AI soldier states & dynamic beach ball state (~12-20 Hz)
      case "host_world_state": {
        if (!currentRoom || currentRoom.hostId !== clientId) break;
        if (currentRoom.clients.size <= 1) break; // Skip serialization if host is the only player in room
        const remainingSec = Math.max(0, (currentRoom.matchEndTime - Date.now()) / 1000);
        broadcastToRoom(
          currentRoom,
          {
            type: "world_state",
            remainingSec,
            matchEnded: currentRoom.matchEnded,
            aiPacked: msg.aiPacked || null,
            aiUnits: msg.aiUnits || null,
            ball: msg.ball || null
          },
          clientId
        );
        break;
      }

      // Weapon fired (renders tracer & muzzle flash on all clients)
      case "fire_shot": {
        if (!currentRoom) break;
        broadcastToRoom(
          currentRoom,
          {
            type: "remote_shot",
            shooterUnitId: msg.shooterUnitId,
            team: msg.team,
            muzzlePos: msg.muzzlePos,
            hitPoint: msg.hitPoint,
            hitKind: msg.hitKind
          },
          clientId
        );
        break;
      }

      // Authoritative damage & Kill/Death tracking across all clients in the room
      case "damage_unit": {
        if (!currentRoom || currentRoom.matchEnded) break;
        const targetUnitId = String(msg.targetUnitId || "");
        const attackerUnitId = msg.attackerUnitId ? String(msg.attackerUnitId) : null;
        const rawAmount = Math.max(0, Number(msg.amount) || 0);
        const amount = currentRoom.hardcoreMode ? Math.max(rawAmount, 100) : rawAmount;
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

        const deltaStats = { [targetUnitId]: targetStat };
        if (attackerUnitId && attackerUnitId !== targetUnitId) {
          deltaStats[attackerUnitId] = getUnitStat(currentRoom, attackerUnitId);
        }

        // Broadcast to ALL clients (including sender) so everyone's K/D & health stay identical
        broadcastToRoom(
          currentRoom,
          {
            type: "unit_damaged",
            targetUnitId,
            attackerUnitId,
            amount,
            health: targetStat.health,
            alive: targetStat.alive,
            killed,
            shotDir: msg.shotDir || null,
            unitStats: deltaStats
          },
          null
        );
        break;
      }

      // Beach ball impulse (kicked or shot)
      case "ball_impulse": {
        if (!currentRoom) break;
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

        const isSelf = targetUnitId === c.unitId;
        if (isSelf) {
          c.health = 100;
          c.alive = true;
          c.x = Number(msg.x) || 0;
          c.y = Number(msg.y) || 0;
          c.z = Number(msg.z) || 0;
          c.yaw = Number(msg.yaw) || 0;
        }

        broadcastToRoom(
          currentRoom,
          {
            type: "unit_respawned",
            unitId: targetUnitId,
            playerName: isSelf ? c.name : null,
            team: msg.team || c.team,
            isAI: Boolean(msg.isAI),
            x: Number(msg.x) || 0,
            y: Number(msg.y) || 0,
            z: Number(msg.z) || 0,
            yaw: Number(msg.yaw) || 0,
            unitStats: { [targetUnitId]: targetStat }
          },
          clientId
        );
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
        const memMB = Math.round(process.memoryUsage().rss / (1024 * 1024));
        safeSend(ws, {
          type: "pong",
          clientTime: msg.clientTime,
          serverTickMs: Number(lastServerTickMs.toFixed(2)),
          serverMemMB: memMB
        });
        break;
      }

      // Restart match for everyone in the room (only the room Host can alter room settings)
      case "restart_match": {
        if (!currentRoom) break;
        const isRoomHost = currentRoom.hostId === clientId;
        if (!isRoomHost && !currentRoom.matchEnded) break;

        if (isRoomHost) {
          if (msg.greenTotal) {
            currentRoom.greenTotal = Math.max(1, Math.floor(Number(msg.greenTotal)));
          }
          if (msg.tanTotal) {
            currentRoom.tanTotal = Math.max(1, Math.floor(Number(msg.tanTotal)));
          }
          if (msg.mapType === "shoebox" || msg.mapType === "sandbox") {
            currentRoom.mapType = msg.mapType;
          }
          if (msg.worldLimit) {
            if (currentRoom.mapType === "shoebox" || Number(msg.worldLimit) <= 50) {
              currentRoom.mapType = "shoebox";
              currentRoom.worldLimit = 28;
            } else {
              currentRoom.worldLimit = Math.max(50, Math.min(130, Number(msg.worldLimit)));
            }
          }
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

  if (leaving) {
    console.log(
      `[${new Date().toISOString()}] [Room ${room.code}] ${leaving.name} (${clientId}) left (${room.clients.size} remaining)`
    );
  }

  if (room.clients.size === 0) {
    rooms.delete(room.code);
    return;
  }

  // Reassign host if the previous host left
  if (room.hostId === clientId) {
    const nextEntry = room.clients.values().next().value;
    room.hostId = nextEntry ? nextEntry.id : null;
    room.hostName = nextEntry ? nextEntry.name : "Host";
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

// ============================================================================
// 3. SERVER-AUTHORITATIVE MATCH TIMER, SCOREBOARD SYNC & TELEMETRY LOOP
// ============================================================================
let tickCounter = 0;
let lastServerTickMs = 0.1;

setInterval(() => {
  const tickStart = process.hrtime.bigint();
  tickCounter++;
  const now = Date.now();

  for (const room of rooms.values()) {
    if (room.clients.size === 0) continue;

    const remainingSec = Math.max(0, (room.matchEndTime - now) / 1000);

    // Trigger simultaneous match end for all players when the server clock hits 0
    if (remainingSec <= 0 && !room.matchEnded) {
      room.matchEnded = true;
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

    // Broadcast authoritative clock & K/D stats once per second to keep all clients locked in sync
    if (!room.matchEnded && tickCounter % 4 === 0) {
      broadcastToRoom(
        room,
        {
          type: "timer_sync",
          remainingSec,
          matchEnded: room.matchEnded,
          unitStats: serializeUnitStats(room)
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

  // Once per second: sample packet/bandwidth rates & append to 60s rolling history
  if (tickCounter % 4 === 0) {
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

    perfMetrics.history.push({
      t: now,
      tickMs: Number(lastServerTickMs.toFixed(3)),
      rssMB: Number((process.memoryUsage().rss / (1024 * 1024)).toFixed(1)),
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
