const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const DATA_FILE = process.env.DATA_FILE
  ? path.resolve(process.env.DATA_FILE)
  : path.join(__dirname, 'data.json');
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';

function gid(n = 12) {
  return crypto.randomBytes(Math.ceil(n / 2)).toString('hex').slice(0, n);
}

function now() { return Date.now(); }
function makeServerId() { return `srv_${gid(8)}`; }

function freshInvite(serverId) {
  const code = gid(10);
  return {
    code,
    serverId,
    createdAt: now(),
    expiresAt: now() + 24 * 60 * 60 * 1000,
    url: `/invite/${code}`,
  };
}

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const seed = {
      users: {},
      sessions: {},
      servers: {},
      invites: {},
      bans: { byIp: {}, byUser: {} },
      admin: { password: process.env.ADMIN_PASSWORD || 'mrvall106' },
      tombstones: {},
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(seed, null, 2));
    return seed;
  }
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

let db = loadData();
if (!db.tombstones) db.tombstones = {};
function save() { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }

function isServerAdmin(userId, srv) {
  return Boolean(srv) && (srv.ownerId === userId || userId === 'admin');
}


function serializeServer(s) {
  return {
    id: s.id,
    ownerId: s.ownerId,
    type: s.type || 'NORMAL',
    name: s.name,
    org: s.org || '',
    sections: s.sections || [],
    channels: s.channels || {},
    members: s.members || [],
    createdAt: s.createdAt,
    status: s.status || 'active',
    invite: s.invite || null,
  };
}

function deleteServerEverywhere(serverId) {
  const srv = db.servers[serverId];
  if (!srv) return false;
  if (srv.invite?.code) delete db.invites[srv.invite.code];
  Object.values(db.users).forEach((u) => {
    u.servers = (u.servers || []).filter((id) => id !== serverId);
  });
  db.tombstones[serverId] = { reason: 'server_deleted', at: now() };
  delete db.servers[serverId];
  return true;
}


setInterval(() => {
  const t = now();
  for (const [code, inv] of Object.entries(db.invites)) {
    if (inv.expiresAt <= t) {
      const srv = db.servers[inv.serverId];
      if (srv && srv.invite?.code === code) {
        const ni = freshInvite(inv.serverId);
        srv.invite = ni;
        db.invites[ni.code] = ni;
      }
      delete db.invites[code];
    }
  }
  save();
}, 60 * 1000);

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: CORS_ORIGIN } });

app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));
app.use(express.static(__dirname));

function ipOf(req) {
  const xff = req.headers['x-forwarded-for'];
  const raw = (Array.isArray(xff) ? xff[0] : xff) || req.ip || req.socket.remoteAddress || '';
  return String(raw).split(',')[0].trim();
}

function auth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
  const sess = token ? db.sessions[token] : null;
  if (!sess) return res.status(401).json({ error: 'unauthorized' });
  const ip = ipOf(req);
  if (db.bans.byIp[ip]) return res.status(403).json({ error: 'banned', reason: db.bans.byIp[ip].reason || '' });
  req.session = sess;
  req.user = db.users[sess.userId];
  if (!req.user) return res.status(401).json({ error: 'session user missing' });
  next();
}

app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/', (_req, res) => res.redirect('/login'));
app.get('/admmrv', (_req, res) => res.sendFile(path.join(__dirname, 'morv-admin.html')));
app.get('/login', (_req, res) => res.sendFile(path.join(__dirname, 'morv-full-release-2_0.html')));
app.get('/invite/:code', (_req, res) => res.sendFile(path.join(__dirname, 'morv-full-release-2_0.html')));
app.get('/servers/:code', (_req, res) => res.sendFile(path.join(__dirname, 'morv-full-release-2_0.html')));
app.get('/ban', (_req, res) => res.sendFile(path.join(__dirname, 'morv-full-release-2_0.html')));

app.post('/api/auth/device', (req, res) => {
  const ip = ipOf(req);
  if (db.bans.byIp[ip]) return res.status(403).json({ error: 'banned', reason: db.bans.byIp[ip].reason || '' });
  const deviceCode = String(req.body.deviceCode || gid(16));
  let user = Object.values(db.users).find((u) => u.deviceCode === deviceCode);
  if (!user) {
    const id = gid(12);
    user = { id, name: `user_${gid(5)}`, deviceCode, createdAt: now(), servers: [] };
    db.users[id] = user;
  }
  const token = gid(36);
  db.sessions[token] = { token, userId: user.id, ip, createdAt: now() };
  save();
  res.json({ token, user: { id: user.id, name: user.name } });
});

app.post('/api/panic', auth, (req, res) => {
  const uid = req.user.id;
  Object.keys(db.sessions).forEach((t) => { if (db.sessions[t].userId === uid) delete db.sessions[t]; });
  delete db.users[uid];
  Object.values(db.servers).forEach((s) => {
    s.members = s.members.filter((m) => m !== uid);
    Object.values(s.channels).forEach((c) => {
      c.messages = c.messages.filter((m) => m.authorId !== uid);
    });
  });
  save();
  res.json({ ok: true });
});

app.post('/api/servers', auth, (req, res) => {
  const id = makeServerId();
  const serverObj = {
    id,
    ownerId: req.user.id,
    type: String(req.body.type || 'NORMAL').toUpperCase(),
    org: String(req.body.org || ''),
    name: (req.body.name || `server-${id}`).toString(),
    sections: Array.isArray(req.body.sections) ? req.body.sections : [],
    channels: {},
    members: [req.user.id],
    createdAt: now(),
    status: 'active',
  };
  const inv = freshInvite(id);
  serverObj.invite = inv;
  db.servers[id] = serverObj;
  db.invites[inv.code] = inv;
  req.user.servers = req.user.servers || [];
  req.user.servers.push(id);
  save();
  res.json({ server: serializeServer(serverObj) });
});

app.get('/api/servers', auth, (req, res) => {
  const servers = Object.values(db.servers).filter((s) => s.members.includes(req.user.id)).map(serializeServer);
  res.json({ servers });
});

app.post('/api/servers/:id/sections', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!isServerAdmin(req.user.id, s)) return res.status(403).json({ error: 'forbidden' });
  const name = String(req.body.name || '').trim().toUpperCase();
  if (!name) return res.status(400).json({ error: 'bad section name' });
  s.sections = Array.isArray(s.sections) ? s.sections : [];
  s.sections.push({ name, channels: [] });
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ server: serializeServer(s) });
});

app.post('/api/servers/:id/channels', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!isServerAdmin(req.user.id, s)) return res.status(403).json({ error: 'forbidden' });
  const name = String(req.body.name || 'new-channel').trim().toLowerCase().replace(/\s+/g, '-');
  const type = req.body.type === 'voice' ? 'voice' : 'text';
  const secIndex = Number.isInteger(req.body.sectionIndex) ? req.body.sectionIndex : -1;
  if (!Array.isArray(s.sections) || secIndex < 0 || secIndex >= s.sections.length) return res.status(400).json({ error: 'bad section index' });
  const cid = gid(10);
  s.channels[cid] = { id: cid, name, type, messages: [] };
  s.sections[secIndex].channels = Array.isArray(s.sections[secIndex].channels) ? s.sections[secIndex].channels : [];
  s.sections[secIndex].channels.push({ id: cid, name, type: type === 'voice' ? 'голос' : 'текст' });
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ server: serializeServer(s), channel: s.channels[cid] });
});

app.post('/api/servers/:id/channels/:channelId/messages', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (s.status === 'banned') return res.status(403).json({ error: 'banned', reason: 'Доступ к Morv был ограничен' });
  const ch = s.channels?.[req.params.channelId];
  if (!ch || ch.type !== 'text') return res.status(404).json({ error: 'channel not found' });
  const text = String(req.body.text || '').trim();
  if (!text) return res.status(400).json({ error: 'empty message' });
  const msg = { id: gid(12), authorId: req.user.id, ts: now(), ciphertext: text, iv: '', keyId: 'local', reactions: {} };
  ch.messages = Array.isArray(ch.messages) ? ch.messages : [];
  ch.messages.push(msg);
  save();
  io.to(`server:${s.id}`).emit('message:new', { serverId: s.id, channelId: ch.id, msg });
  res.json({ msg });
});

app.post('/api/servers/:id/channels/:channelId/reactions', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  const ch = s.channels?.[req.params.channelId];
  if (!ch) return res.status(404).json({ error: 'channel not found' });
  const messageId = String(req.body.messageId || '');
  const emoji = String(req.body.emoji || '');
  const m = (ch.messages || []).find((x) => x.id === messageId);
  if (!m || !emoji) return res.status(404).json({ error: 'message not found' });
  m.reactions = m.reactions || {};
  m.reactions[emoji] = m.reactions[emoji] || [];
  const idx = m.reactions[emoji].indexOf(req.user.id);
  if (idx >= 0) m.reactions[emoji].splice(idx, 1);
  else m.reactions[emoji].push(req.user.id);
  save();
  io.to(`server:${s.id}`).emit('reaction:update', { serverId: s.id, channelId: ch.id, messageId: m.id, reactions: m.reactions });
  res.json({ reactions: m.reactions });
});

app.get('/api/servers/:id/state', auth, (req, res) => {
  const sid = req.params.id;
  if (db.tombstones[sid]) return res.status(404).json({ error: 'server deleted' });
  const s = db.servers[sid];
  if (!s) return res.status(404).json({ error: 'server not found' });
  if (!s.members.includes(req.user.id)) return res.status(403).json({ error: 'removed' });
  if (s.status === 'banned') return res.status(403).json({ error: 'banned', reason: 'Доступ к Morv был ограничен' });
  res.json({ ok: true, server: serializeServer(s) });
});

app.get('/api/servers/:id/invite', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!s.invite || s.invite.expiresAt < now()) {
    if (s.invite?.code) delete db.invites[s.invite.code];
    const inv = freshInvite(s.id);
    s.invite = inv;
    db.invites[inv.code] = inv;
    save();
  }
  res.json({ invite: s.invite, url: `/invite/${s.invite.code}` });
});

app.post('/api/invites/:code/join', auth, (req, res) => {
  const inv = db.invites[req.params.code];
  if (!inv || inv.expiresAt < now()) return res.status(404).json({ error: 'invite expired' });
  const s = db.servers[inv.serverId];
  if (!s) return res.status(404).json({ error: db.tombstones[inv.serverId] ? 'server deleted' : 'server not found' });
  if (!s.members.includes(req.user.id)) s.members.push(req.user.id);
  req.user.servers = req.user.servers || [];
  if (!req.user.servers.includes(s.id)) req.user.servers.push(s.id);
  save();
  io.to(`server:${s.id}`).emit('server:update', s);
  res.json({ serverId: s.id });
});

app.post('/api/admin/login', (req, res) => {
  if (req.body.password !== db.admin.password) return res.status(401).json({ error: 'bad password' });
  const token = gid(24);
  db.sessions[token] = { token, userId: 'admin', ip: ipOf(req), createdAt: now(), admin: true };
  save();
  res.json({ token });
});

function adminAuth(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const s = token && db.sessions[token];
  if (!s || !s.admin) return res.status(401).json({ error: 'admin unauthorized' });
  next();
}

app.post('/api/admin/ban/server/:id', adminAuth, (req, res) => {
  const srv = db.servers[req.params.id];
  if (!srv) return res.status(404).json({ error: 'not found' });
  const reason = req.body.reason || '';
  srv.status = 'banned';
  srv.members.forEach((uid) => {
    Object.values(db.sessions).forEach((sess) => {
      if (sess.userId === uid && sess.ip) db.bans.byIp[sess.ip] = { reason, at: now(), serverId: srv.id };
    });
  });
  save();
  io.emit('ban:update');
  res.json({ ok: true });
});



app.post('/api/admin/unban/server/:id', adminAuth, (req, res) => {
  const srv = db.servers[req.params.id];
  if (!srv) return res.status(404).json({ error: 'not found' });
  srv.status = 'active';
  Object.keys(db.bans.byIp).forEach((ip) => {
    const b = db.bans.byIp[ip];
    if (b && b.serverId === srv.id) delete db.bans.byIp[ip];
  });
  save();
  io.emit('ban:update');
  io.to(`server:${srv.id}`).emit('server:update', serializeServer(srv));
  res.json({ ok: true });
});

app.get('/api/admin/servers', adminAuth, (_req, res) => {
  const servers = Object.values(db.servers).map(serializeServer);
  res.json({ servers });
});

app.post('/api/admin/servers', adminAuth, (req, res) => {
  const id = makeServerId();
  const type = String(req.body.type || 'FO').toUpperCase();
  const name = String(req.body.name || `server-${id}`);
  const sections = Array.isArray(req.body.sections) ? req.body.sections : [];
  const channels = {};
  sections.forEach((sec) => {
    (sec.channels || []).forEach((ch) => {
      const cid = gid(10);
      channels[cid] = { id: cid, name: ch.name || 'channel', type: ch.type === 'голос' ? 'voice' : 'text', messages: [] };
    });
  });
  const serverObj = {
    id,
    ownerId: 'admin',
    type,
    org: String(req.body.org || ''),
    name,
    sections,
    channels,
    members: [],
    createdAt: now(),
    status: 'active',
  };
  const inv = freshInvite(id);
  serverObj.invite = inv;
  db.servers[id] = serverObj;
  db.invites[inv.code] = inv;
  save();
  res.json({ server: serializeServer(serverObj) });
});


app.post('/api/admin/servers/:id/update', adminAuth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s) return res.status(404).json({ error: 'not found' });
  if (typeof req.body.name === 'string' && req.body.name.trim()) s.name = req.body.name.trim();
  if (Array.isArray(req.body.sections)) s.sections = req.body.sections;
  if (typeof req.body.org === 'string') s.org = req.body.org;
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ server: serializeServer(s) });
});

app.post('/api/admin/servers/:id/delete', adminAuth, (req, res) => {
  if (!deleteServerEverywhere(req.params.id)) return res.status(404).json({ error: 'not found' });
  save();
  res.json({ ok: true });
});

io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  const sess = token && db.sessions[token];
  if (!sess) return next(new Error('unauthorized'));
  socket.session = sess;
  socket.user = db.users[sess.userId] || { id: sess.userId, name: 'unknown' };
  next();
});

io.on('connection', (socket) => {
  socket.on('server:join', ({ serverId }) => {
    const s = db.servers[serverId];
    if (!s || !s.members.includes(socket.user.id)) return;
    socket.join(`server:${serverId}`);
    socket.emit('server:init', s);
  });

  socket.on('message:send', ({ serverId, channelId, ciphertext, iv, keyId }) => {
    const s = db.servers[serverId];
    if (!s || !s.members.includes(socket.user.id)) return;
    const ch = s.channels[channelId];
    if (!ch) return;
    const msg = { id: gid(12), authorId: socket.user.id, ts: now(), ciphertext, iv, keyId, reactions: {} };
    ch.messages.push(msg);
    save();
    io.to(`server:${serverId}`).emit('message:new', { serverId, channelId, msg });
  });

  socket.on('reaction:set', ({ serverId, channelId, messageId, emoji }) => {
    const s = db.servers[serverId];
    const ch = s?.channels?.[channelId];
    const m = ch?.messages?.find((x) => x.id === messageId);
    if (!m) return;
    m.reactions[emoji] = m.reactions[emoji] || [];
    if (!m.reactions[emoji].includes(socket.user.id)) m.reactions[emoji].push(socket.user.id);
    save();
    io.to(`server:${serverId}`).emit('reaction:update', { serverId, channelId, messageId, reactions: m.reactions });
  });
});

server.listen(PORT, HOST, () => {
  console.log(`Morv server running on http://${HOST}:${PORT}`);
  console.log(`DATA_FILE=${DATA_FILE}`);
});
