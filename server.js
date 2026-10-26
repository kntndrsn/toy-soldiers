const http = require("http");
const fs = require("fs");
const path = require("path");
const { WebSocketServer, WebSocket } = require("ws");

const PORT = process.env.PORT || 3000;
const INDEX_PATH = path.join(__dirname, "index.html");

// ============================================================================
// 1. HTTP SERVER (Serves index.html and health check)
// ============================================================================
const server = http.createServer((req, res) => {
  if (req.url === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, rooms: rooms.size }));
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

function getOrCreateRoom(roomCode, greenTotal, tanTotal) {
  let room = rooms.get(roomCode);
  if (!room) {
    room = {
      code: roomCode,
      hostId: null,
      greenTotal: Math.max(1, Math.min(13, greenTotal || 4)),
      tanTotal: Math.max(1, Math.min(16, tanTotal || 4)),
      clients: new Map(), // Map<clientId, ClientInfo>
      matchId: 1
    };
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
  return {
    roomCode: room.code,
    hostId: room.hostId,
    greenTotal: room.greenTotal,
    tanTotal: room.tanTotal,
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
      // Player joins or creates a multiplayer room
      case "join_room": {
        if (currentRoom) {
          removeClientFromRoom(currentRoom, clientId);
        }

        const roomCode = sanitizeCode(msg.roomCode);
        const team = msg.team === "tan" ? "tan" : "green";
        const name = String(msg.name || "Soldier").slice(0, 18);
        const requestedGreen = Number(msg.greenTotal) || 4;
        const requestedTan = Number(msg.tanTotal) || 4;

        const room = getOrCreateRoom(roomCode, requestedGreen, requestedTan);
        if (!room.hostId) {
          room.hostId = clientId;
          room.greenTotal = Math.max(1, Math.min(13, requestedGreen));
          room.tanTotal = Math.max(1, Math.min(16, requestedTan));
        }

        const slotIndex = assignSlotForPlayer(room, team);
        // Expand team total if more humans join than current total
        if (team === "green" && slotIndex + 1 > room.greenTotal) {
          room.greenTotal = slotIndex + 1;
        } else if (team === "tan" && slotIndex + 1 > room.tanTotal) {
          room.tanTotal = slotIndex + 1;
        }

        const unitId = `${team}_${slotIndex}`;
        const clientInfo = {
          id: clientId,
          ws,
          name,
          team,
          slotIndex,
          unitId,
          x: 0,
          y: 0,
          z: team === "green" ? -30 : 28,
          yaw: team === "green" ? 0 : Math.PI,
          pitch: 0,
          health: 100,
          alive: true
        };

        room.clients.set(clientId, clientInfo);
        currentRoom = room;

        // Send welcome packet to joining client
        ws.send(
          JSON.stringify({
            type: "room_joined",
            clientId,
            unitId,
            team,
            slotIndex,
            roster: serializeRoster(room)
          })
        );

        // Notify everyone else in the room
        broadcastToRoom(
          room,
          {
            type: "roster_update",
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

      // Room Host broadcasts AI soldier states & dynamic beach ball state (~20 Hz)
      case "host_world_state": {
        if (!currentRoom || currentRoom.hostId !== clientId) return;
        broadcastToRoom(
          currentRoom,
          {
            type: "world_state",
            aiUnits: msg.aiUnits || [],
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

      // Damage dealt to a soldier (AI or human)
      case "damage_unit": {
        if (!currentRoom) return;
        broadcastToRoom(
          currentRoom,
          {
            type: "unit_damaged",
            targetUnitId: msg.targetUnitId,
            amount: Number(msg.amount) || 0,
            shotDir: msg.shotDir || null
          },
          clientId
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

      // Restart match for everyone in the room
      case "restart_match": {
        if (!currentRoom) return;
        if (msg.greenTotal) {
          currentRoom.greenTotal = Math.max(1, Math.min(13, Number(msg.greenTotal)));
        }
        if (msg.tanTotal) {
          currentRoom.tanTotal = Math.max(1, Math.min(16, Number(msg.tanTotal)));
        }
        currentRoom.matchId++;

        for (const c of currentRoom.clients.values()) {
          c.health = 100;
          c.alive = true;
        }

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
  room.clients.delete(clientId);

  if (room.clients.size === 0) {
    rooms.delete(room.code);
    return;
  }

  // Reassign host if the previous host left
  if (room.hostId === clientId) {
    const nextHost = room.clients.keys().next().value;
    room.hostId = nextHost || null;
  }

  broadcastToRoom(room, {
    type: "roster_update",
    roster: serializeRoster(room)
  });
}

server.listen(PORT, () => {
  console.log(`Plastic Army Men Server running on http://localhost:${PORT}`);
});
