const http = require("http");
const fs = require("fs");
const path = require("path");
const { WebSocketServer, WebSocket } = require("ws");

const PORT = process.env.PORT || 3000;
const INDEX_PATH = path.join(__dirname, "index.html");

// ============================================================================
// 1. HTTP SERVER (Serves index.html, /rooms, and /health)
// ============================================================================
function getRoomsSummary() {
  const summary = [];
  for (const room of rooms.values()) {
    summary.push(serializeRoster(room));
  }
  return summary;
}

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");

  if (req.url === "/health" || req.url === "/rooms") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        ok: true,
        roomCount: rooms.size,
        rooms: getRoomsSummary()
      })
    );
    return;
  }

  if (req.url === "/" || req.url.startsWith("/index.html") || req.url.startsWith("/?")) {
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

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not Found");
});

// ============================================================================
// 2. WEBSOCKET MULTIPLAYER ROOM SERVER
// ============================================================================
const wss = new WebSocketServer({ server });

// Map<roomCode, RoomState>
const rooms = new Map();
let nextClientId = 1;

function sanitizeCode(raw) {
  const cleaned = String(raw || "SAND")
    .toUpperCase()
    .replace(/[^A-Z0-9_-]/g, "")
    .slice(0, 12);
  return cleaned || "SAND";
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

function getOrCreateRoom(roomCode, greenTotal, tanTotal, hostName, worldLimit, durationSec, mapType, hardcoreMode) {
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
      client.ws.send(data);
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

wss.on("connection", (ws) => {
  const clientId = "p_" + nextClientId++;
  let currentRoom = null;

  ws.on("message", (rawMessage) => {
    let msg;
    try {
      msg = JSON.parse(rawMessage.toString());
    } catch {
      return;
    }

    switch (msg.type) {
      // Host creates/configures a room (settings come from the Host device)
      // or Joiner joins an existing room (inherits the Host's room settings)
      case "host_room":
      case "join_room": {
        if (currentRoom) {
          removeClientFromRoom(currentRoom, clientId);
        }

        const isHosting = msg.type === "host_room";
        const roomCode = sanitizeCode(msg.roomCode);
        const team = msg.team === "tan" ? "tan" : "green";
        const name = String(msg.name || "Soldier").slice(0, 18);
        const requestedGreen = Number(msg.greenTotal) || 4;
        const requestedTan = Number(msg.tanTotal) || 4;
        const requestedMapType =
          msg.mapType === "shoebox" || Number(msg.worldLimit) <= 50 ? "shoebox" : "sandbox";
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
          requestedHardcore
        );

        // If this device clicked Host (or room had no host), apply their match settings & reset round
        if (isHosting || !room.hostId) {
          room.hostId = clientId;
          room.hostName = name;
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
        ws.send(
          JSON.stringify({
            type: "room_joined",
            clientId,
            unitId,
            team,
            slotIndex,
            isHost: room.hostId === clientId,
            roster: serializeRoster(room)
          })
        );

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
        if (!currentRoom) return;
        const c = currentRoom.clients.get(clientId);
        if (!c) return;

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
        if (!currentRoom || currentRoom.hostId !== clientId) return;
        if (currentRoom.clients.size <= 1) return; // Skip serialization if host is the only player in room
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
        if (!currentRoom) return;
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
        if (!currentRoom || currentRoom.matchEnded) return;
        const targetUnitId = String(msg.targetUnitId || "");
        const attackerUnitId = msg.attackerUnitId ? String(msg.attackerUnitId) : null;
        const rawAmount = Math.max(0, Number(msg.amount) || 0);
        const amount = currentRoom.hardcoreMode ? Math.max(rawAmount, 100) : rawAmount;
        if (!targetUnitId || amount <= 0) return;

        const targetStat = getUnitStat(currentRoom, targetUnitId);
        if (!targetStat.alive) return; // Already eliminated; ignore duplicate hit packets

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
        if (!currentRoom) return;
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
        if (!currentRoom || currentRoom.matchEnded) return;
        const c = currentRoom.clients.get(clientId);
        if (!c) return;

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

      // Ping / Pong + Server Performance Telemetry
      case "ping": {
        const memMB = Math.round(process.memoryUsage().rss / (1024 * 1024));
        ws.send(
          JSON.stringify({
            type: "pong",
            clientTime: msg.clientTime,
            serverTickMs: Number(lastServerTickMs.toFixed(2)),
            serverMemMB: memMB
          })
        );
        break;
      }

      // Restart match for everyone in the room
      case "restart_match": {
        if (!currentRoom) return;
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
        resetRoomMatchState(currentRoom);
        currentRoom.matchId++;

        broadcastToRoom(currentRoom, {
          type: "match_restarted",
          roster: serializeRoster(currentRoom)
        });
        break;
      }
    }
  });

  ws.on("close", () => {
    if (currentRoom) {
      removeClientFromRoom(currentRoom, clientId);
      currentRoom = null;
    }
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
// 3. SERVER-AUTHORITATIVE MATCH TIMER & SCOREBOARD SYNC LOOP
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
}, 250);

server.listen(PORT, () => {
  console.log(`Plastic Army Men Server running on http://localhost:${PORT}`);
});
