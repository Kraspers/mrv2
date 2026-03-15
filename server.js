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
function ensureServerIntegrity(s) {
  if (!s) return;
  s.members = Array.isArray(s.members) ? s.members : [];
  if (s.ownerId && !s.members.includes(s.ownerId)) s.members.push(s.ownerId);
  s.memberPerms = s.memberPerms || {};
  if (s.ownerId && s.memberPerms[s.ownerId]) delete s.memberPerms[s.ownerId];
  s.prefixes = s.prefixes || {};
}
Object.values(db.servers || {}).forEach(ensureServerIntegrity);
function save() { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); }

function isServerAdmin(userId, srv) {
  return Boolean(srv) && (srv.ownerId === userId || userId === 'admin');
}

function canManage(userId, srv, perm) {
  if (isServerAdmin(userId, srv)) return true;
  const p = srv?.memberPerms?.[userId];
  return Boolean(p && p[perm]);
}


function serializeServer(s) {
  const memberProfiles = (s.members || []).map((id) => ({
    id,
    name: db.users[id]?.name || `user-${String(id).slice(0, 6)}`,
  }));
  return {
    id: s.id,
    ownerId: s.ownerId,
    type: s.type || 'NORMAL',
    name: s.name,
    avatar: s.avatar || null,
    org: s.org || '',
    sections: s.sections || [],
    channels: s.channels || {},
    members: s.members || [],
    memberProfiles,
    createdAt: s.createdAt,
    status: s.status || 'active',
    bots: s.bots || [],
    memberPerms: s.memberPerms || {},
    prefixes: s.prefixes || {},
    invite: s.invite || null,
  };
}


function pushSystemMessage(srv, text, opts = {}) {
  const channels = Object.values(srv.channels || {});
  let ch = null;
  if (opts.channelId) ch = srv.channels?.[opts.channelId] || null;
  if (!ch) ch = channels.find((c) => c.type === 'text' && c.botId) || null;
  if (!ch) ch = channels.find((c) => c.type === 'text') || null;
  if (!ch) return null;
  const msg = {
    id: gid(12),
    authorId: opts.authorId || 'system',
    ts: now(),
    ciphertext: String(text || ''),
    iv: '',
    keyId: 'local',
    reactions: {},
    pinned: false,
  };
  ch.messages = Array.isArray(ch.messages) ? ch.messages : [];
  ch.messages.push(msg);
  return { channelId: ch.id, msg };
}

function deleteServerEverywhere(serverId) {
  const srv = db.servers[serverId];
  if (!srv) return false;
  if (srv.invite?.code) delete db.invites[srv.invite.code];
  Object.values(db.users).forEach((u) => {
    u.servers = (u.servers || []).filter((id) => id !== serverId);
  });
  if (srv.channels) {
    Object.values(srv.channels).forEach((ch) => {
      (ch.messages || []).forEach((m) => {
        if (m.replyTo) m.replyTo.deleted = true;
      });
    });
  }
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
const voiceState = {}; // key: serverId:channelId -> { userId: { mute, deaf } }

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
  res.json({ token, deviceCode: user.deviceCode || deviceCode, user: { id: user.id, name: user.name } });
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
    avatar: req.body.avatar || null,
    sections: Array.isArray(req.body.sections) ? req.body.sections : [],
    channels: {},
    members: [req.user.id],
    memberPerms: {},
    prefixes: {},
    bots: [],
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
  if (!canManage(req.user.id, s, 'manageChannels')) return res.status(403).json({ error: 'forbidden' });
  if (s.type === 'FO') return res.status(403).json({ error: 'forbidden for FO server' });
  const name = String(req.body.name || '').trim().toUpperCase();
  if (!name) return res.status(400).json({ error: 'bad section name' });
  s.sections = Array.isArray(s.sections) ? s.sections : [];
  s.sections.push({ name, channels: [] });
  const activity = pushSystemMessage(s, `📁 Раздел ${name} создан`);
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  io.to(`server:${s.id}`).emit('server:activity', { type: 'section:created', name });
  if (activity) io.to(`server:${s.id}`).emit('message:new', { serverId: s.id, channelId: activity.channelId, msg: activity.msg });
  res.json({ server: serializeServer(s) });
});

app.post('/api/servers/:id/channels', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!canManage(req.user.id, s, 'manageChannels')) return res.status(403).json({ error: 'forbidden' });
  if (s.type === 'FO') return res.status(403).json({ error: 'forbidden for FO server' });
  const name = String(req.body.name || 'new-channel').trim().toLowerCase().replace(/\s+/g, '-');
  const type = req.body.type === 'voice' ? 'voice' : 'text';
  const secIndex = Number.isInteger(req.body.sectionIndex) ? req.body.sectionIndex : -1;
  if (!Array.isArray(s.sections) || secIndex < 0 || secIndex >= s.sections.length) return res.status(400).json({ error: 'bad section index' });
  const cid = gid(10);
  s.channels[cid] = { id: cid, name, type, messages: [] };
  s.sections[secIndex].channels = Array.isArray(s.sections[secIndex].channels) ? s.sections[secIndex].channels : [];
  s.sections[secIndex].channels.push({ id: cid, name, type: type === 'voice' ? 'голос' : 'текст' });
  const activity = pushSystemMessage(s, `${type === 'voice' ? '🔊' : '#'} ${name} создан`, { channelId: type === 'text' ? cid : undefined });
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  io.to(`server:${s.id}`).emit('server:activity', { type: 'channel:created', name, channelType: type });
  if (activity) io.to(`server:${s.id}`).emit('message:new', { serverId: s.id, channelId: activity.channelId, msg: activity.msg });
  res.json({ server: serializeServer(s), channel: s.channels[cid] });
});

app.post('/api/servers/:id/channels/:channelId/messages', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (s.status === 'banned') return res.status(403).json({ error: 'banned', reason: 'Доступ к Morv был ограничен' });
  if (s.status === 'archived') return res.status(403).json({ error: 'readonly', reason: 'Сервер в архиве (только чтение)' });
  const ch = s.channels?.[req.params.channelId];
  if (!ch || ch.type !== 'text') return res.status(404).json({ error: 'channel not found' });
  const text = String(req.body.text || '').trim();
  if (!text) return res.status(400).json({ error: 'empty message' });
  const replyTo = req.body.replyTo && typeof req.body.replyTo === 'object'
    ? {
        id: String(req.body.replyTo.id || ''),
        author: String(req.body.replyTo.author || ''),
        text: String(req.body.replyTo.text || ''),
      }
    : null;
  const msg = {
    id: gid(12),
    authorId: req.user.id,
    ts: now(),
    ciphertext: text,
    iv: '',
    keyId: 'local',
    reactions: {},
    replyTo,
    pinned: false,
  };
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

app.post('/api/servers/:id/update', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!canManage(req.user.id, s, 'manageServer')) return res.status(403).json({ error: 'forbidden' });
  if (typeof req.body.name === 'string' && req.body.name.trim()) s.name = req.body.name.trim();
  if (typeof req.body.avatar === 'string' || req.body.avatar === null) s.avatar = req.body.avatar || null;
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ server: serializeServer(s) });
});

app.post('/api/servers/:id/channels/:channelId/update', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!canManage(req.user.id, s, 'manageChannels')) return res.status(403).json({ error: 'forbidden' });
  const ch = s.channels?.[req.params.channelId];
  if (!ch) return res.status(404).json({ error: 'channel not found' });
  if (typeof req.body.name === 'string' && req.body.name.trim()) ch.name = req.body.name.trim();
  if (typeof req.body.desc === 'string') ch.desc = req.body.desc;
  (s.sections || []).forEach((sec) => {
    (sec.channels || []).forEach((c) => { if (c.id === ch.id) { c.name = ch.name; } });
  });
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ server: serializeServer(s) });
});

app.post('/api/servers/:id/channels/:channelId/delete', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!canManage(req.user.id, s, 'manageChannels')) return res.status(403).json({ error: 'forbidden' });
  const ch = s.channels?.[req.params.channelId];
  if (!ch) return res.status(404).json({ error: 'channel not found' });
  delete s.channels[ch.id];
  (s.sections || []).forEach((sec) => {
    sec.channels = (sec.channels || []).filter((c) => c.id !== ch.id);
  });
  if (ch.botId) s.bots = (s.bots || []).filter((b) => b.id !== ch.botId);
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ server: serializeServer(s) });
});

app.post('/api/servers/:id/sections/:sectionIndex/update', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!canManage(req.user.id, s, 'manageChannels')) return res.status(403).json({ error: 'forbidden' });
  const i = Number(req.params.sectionIndex);
  if (!Number.isInteger(i) || !s.sections || i < 0 || i >= s.sections.length) return res.status(404).json({ error: 'section not found' });
  const nm = String(req.body.name || '').trim();
  if (!nm) return res.status(400).json({ error: 'bad section name' });
  s.sections[i].name = nm;
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ server: serializeServer(s) });
});

app.post('/api/servers/:id/sections/:sectionIndex/delete', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!canManage(req.user.id, s, 'manageChannels')) return res.status(403).json({ error: 'forbidden' });
  const i = Number(req.params.sectionIndex);
  if (!Number.isInteger(i) || !s.sections || i < 0 || i >= s.sections.length) return res.status(404).json({ error: 'section not found' });
  const sec = s.sections[i];
  (sec.channels || []).forEach((ch) => {
    delete s.channels[ch.id];
  });
  s.sections.splice(i, 1);
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ server: serializeServer(s) });
});

app.post('/api/servers/:id/channels/:channelId/messages/:messageId/update', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  const ch = s.channels?.[req.params.channelId];
  if (!ch) return res.status(404).json({ error: 'channel not found' });
  const m = (ch.messages || []).find((x) => x.id === req.params.messageId);
  if (!m) return res.status(404).json({ error: 'message not found' });
  if (m.authorId !== req.user.id && !canManage(req.user.id, s, 'manageMessages')) return res.status(403).json({ error: 'forbidden' });
  const text = String(req.body.text || '').trim();
  if (!text) return res.status(400).json({ error: 'empty message' });
  m.ciphertext = text;
  m.edited = true;
  save();
  io.to(`server:${s.id}`).emit('message:update', { serverId: s.id, channelId: ch.id, messageId: m.id, text: m.ciphertext, edited: true });
  res.json({ ok: true });
});

app.post('/api/servers/:id/channels/:channelId/messages/:messageId/delete', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  const ch = s.channels?.[req.params.channelId];
  if (!ch) return res.status(404).json({ error: 'channel not found' });
  const m = (ch.messages || []).find((x) => x.id === req.params.messageId);
  if (!m) return res.status(404).json({ error: 'message not found' });
  if (m.authorId !== req.user.id && !canManage(req.user.id, s, 'manageMessages')) return res.status(403).json({ error: 'forbidden' });
  ch.messages = (ch.messages || []).filter((x) => x.id !== m.id);
  Object.values(s.channels || {}).forEach((c) => {
    (c.messages || []).forEach((msg) => {
      if (msg.replyTo && msg.replyTo.id === m.id) {
        msg.replyTo.deleted = true;
        msg.replyTo.text = 'Сообщение удалено';
      }
    });
  });
  save();
  io.to(`server:${s.id}`).emit('message:delete', { serverId: s.id, channelId: ch.id, messageId: m.id });
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ ok: true });
});

app.post('/api/servers/:id/members/:userId/remove', auth, (req, res) => {
  const s = db.servers[req.params.id];
  const uid = req.params.userId;
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!canManage(req.user.id, s, 'manageMembers')) return res.status(403).json({ error: 'forbidden' });
  if (uid === s.ownerId) return res.status(400).json({ error: 'cannot remove owner' });
  s.members = (s.members || []).filter((id) => id !== uid);
  if (s.memberPerms) delete s.memberPerms[uid];
  if (db.users[uid]) db.users[uid].servers = (db.users[uid].servers || []).filter((id) => id !== s.id);
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ ok: true });
});

app.post('/api/servers/:id/members/:userId/permissions', auth, (req, res) => {
  const s = db.servers[req.params.id];
  const uid = req.params.userId;
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!canManage(req.user.id, s, 'manageMembers')) return res.status(403).json({ error: 'forbidden' });
  if (uid === s.ownerId) return res.status(400).json({ error: 'owner always admin' });
  s.memberPerms = s.memberPerms || {};
  s.memberPerms[uid] = {
    manageChannels: !!req.body.manageChannels,
    manageServer: !!req.body.manageServer,
    manageMembers: !!req.body.manageMembers,
    manageMessages: !!req.body.manageMessages,
    manageBots: !!req.body.manageBots,
  };
  save();
  io.to(`server:${s.id}`).emit('member:permissions', { serverId: s.id, userId: uid, permissions: s.memberPerms[uid] });
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ ok: true, permissions: s.memberPerms[uid] });
});

app.post('/api/servers/:id/prefixes/:userId', auth, (req, res) => {
  const s = db.servers[req.params.id];
  const uid = req.params.userId;
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!s.members.includes(uid)) return res.status(404).json({ error: 'member not found' });
  if (!(req.user.id === uid || canManage(req.user.id, s, 'manageMembers'))) return res.status(403).json({ error: 'forbidden' });
  const value = String(req.body.prefix || '').trim();
  s.prefixes = s.prefixes || {};
  if (value) s.prefixes[uid] = value.slice(0, 24);
  else delete s.prefixes[uid];
  save();
  io.to(`server:${s.id}`).emit('prefix:update', { serverId: s.id, userId: uid, prefix: s.prefixes[uid] || '' });
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ ok: true, prefix: s.prefixes[uid] || '' });
});

app.post('/api/servers/:id/bots/add', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!canManage(req.user.id, s, 'manageBots')) return res.status(403).json({ error: 'forbidden' });
  const code = String(req.body.code || '');
  const name = String(req.body.name || 'bot');
  if (!code) return res.status(400).json({ error: 'bad code' });
  s.bots = s.bots || [];
  if (s.bots.some((b) => b.code === code)) return res.status(409).json({ error: 'bot already added' });
  const botId = gid(10);
  const bot = { id: botId, code, name, emoji: String(req.body.emoji || '🤖'), desc: String(req.body.desc || ''), coreApp: !!req.body.coreApp };
  s.bots.push(bot);
  let botChannelId = null;
  if (req.body.channelName) {
    const cid = `bot-ch-${botId}`;
    botChannelId = cid;
    s.channels[cid] = { id: cid, name: String(req.body.channelName), type: 'text', readonly: true, coreApp: !!req.body.coreApp, botId, messages: [] };
    s.sections = Array.isArray(s.sections) ? s.sections : [];
    let sec = null;
    if (typeof req.body.sectionName === 'string' && req.body.sectionName.trim()) {
      const secName = req.body.sectionName.trim().toUpperCase();
      sec = s.sections.find((x) => String(x.name || '').toUpperCase() === secName);
      if (!sec) {
        sec = { name: secName, channels: [] };
        s.sections.push(sec);
      }
    }
    if (!sec) {
      sec = { name: 'БОТЫ', channels: [] };
      s.sections.push(sec);
    }
    sec.channels = Array.isArray(sec.channels) ? sec.channels : [];
    sec.channels.push({ id: cid, name: s.channels[cid].name, type: 'текст' });
    pushSystemMessage(s, code === '111111'
      ? '👋 Канал приветствия готов. Здесь бот будет отправлять системные приветствия.'
      : `🤖 Бот ${name} активирован.`, { channelId: cid, authorId: `bot-${botId}` });
  }
  const activity = pushSystemMessage(s, `🤖 Добавлен бот ${name}`);
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  if (activity) io.to(`server:${s.id}`).emit('message:new', { serverId: s.id, channelId: activity.channelId, msg: activity.msg });
  io.to(`server:${s.id}`).emit('server:activity', { type: 'bot:added', name, channelId: botChannelId });
  res.json({ server: serializeServer(s), bot });
});

app.post('/api/servers/:id/bots/:botId/remove', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!canManage(req.user.id, s, 'manageBots')) return res.status(403).json({ error: 'forbidden' });
  const bid = req.params.botId;
  s.bots = (s.bots || []).filter((b) => b.id !== bid);
  Object.values(s.channels || {}).forEach((ch) => {
    if (ch.botId === bid) delete s.channels[ch.id];
  });
  (s.sections || []).forEach((sec) => {
    sec.channels = (sec.channels || []).filter((ch) => (s.channels || {})[ch.id]);
  });
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  res.json({ ok: true });
});

app.post('/api/servers/:id/channels/:channelId/pin', auth, (req, res) => {
  const s = db.servers[req.params.id];
  if (!s || !s.members.includes(req.user.id)) return res.status(404).json({ error: 'server not found' });
  if (!isServerAdmin(req.user.id, s)) return res.status(403).json({ error: 'forbidden' });
  const ch = s.channels?.[req.params.channelId];
  if (!ch) return res.status(404).json({ error: 'channel not found' });
  const messageId = String(req.body.messageId || '');
  const m = (ch.messages || []).find((x) => x.id === messageId);
  if (!m) return res.status(404).json({ error: 'message not found' });
  m.pinned = !m.pinned;
  save();
  io.to(`server:${s.id}`).emit('message:pin', { serverId: s.id, channelId: ch.id, messageId: m.id, pinned: m.pinned });
  res.json({ pinned: m.pinned });
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
  let welcomeEvent = null;
  const welcomeBot = (s.bots || []).find((b) => b.code === '111111');
  if (welcomeBot) {
    const wch = Object.values(s.channels || {}).find((ch) => ch.botId === welcomeBot.id);
    if (wch) welcomeEvent = pushSystemMessage(s, `👋 ${req.user.name} присоединился к серверу`, { channelId: wch.id, authorId: `bot-${welcomeBot.id}` });
  }
  save();
  io.to(`server:${s.id}`).emit('server:update', serializeServer(s));
  if (welcomeEvent) io.to(`server:${s.id}`).emit('message:new', { serverId: s.id, channelId: welcomeEvent.channelId, msg: welcomeEvent.msg });
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
  io.emit('ban:update', { serverId: srv.id, status: 'banned', reason });
  io.to(`server:${srv.id}`).emit('ban:update', { serverId: srv.id, status: 'banned', reason });
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
  io.emit('ban:update', { serverId: srv.id, status: 'active', reason: '' });
  io.to(`server:${srv.id}`).emit('ban:update', { serverId: srv.id, status: 'active', reason: '' });
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
    avatar: req.body.avatar || null,
    sections,
    channels,
    members: [],
    memberPerms: {},
    prefixes: {},
    bots: [],
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
  const sid = req.params.id;
  if (!deleteServerEverywhere(sid)) return res.status(404).json({ error: 'not found' });
  save();
  io.to(`server:${sid}`).emit('server:deleted', { serverId: sid });
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
    socket.emit('server:init', serializeServer(s));
  });


  socket.on('voice:join', ({ serverId, channelId }) => {
    const s = db.servers[serverId];
    if (!s || !s.members.includes(socket.user.id)) return;
    const ch = s.channels?.[channelId];
    if (!ch || ch.type !== 'voice') return;
    const key = `${serverId}:${channelId}`;
    voiceState[key] = voiceState[key] || {};
    voiceState[key][socket.user.id] = voiceState[key][socket.user.id] || { mute: false, deaf: false };
    socket.join(`voice:${key}`);
    io.to(`voice:${key}`).emit('voice:presence', {
      serverId,
      channelId,
      participants: Object.entries(voiceState[key]).map(([userId, st]) => ({ userId, mute: !!st.mute, deaf: !!st.deaf })),
    });
  });

  socket.on('voice:state', ({ serverId, channelId, mute, deaf }) => {
    const key = `${serverId}:${channelId}`;
    if (!voiceState[key] || !voiceState[key][socket.user.id]) return;
    voiceState[key][socket.user.id] = { mute: !!mute, deaf: !!deaf };
    io.to(`voice:${key}`).emit('voice:presence', {
      serverId,
      channelId,
      participants: Object.entries(voiceState[key]).map(([userId, st]) => ({ userId, mute: !!st.mute, deaf: !!st.deaf })),
    });
  });

  socket.on('voice:leave', ({ serverId, channelId }) => {
    const key = `${serverId}:${channelId}`;
    if (!voiceState[key]) return;
    delete voiceState[key][socket.user.id];
    socket.leave(`voice:${key}`);
    io.to(`voice:${key}`).emit('voice:presence', {
      serverId,
      channelId,
      participants: Object.entries(voiceState[key]).map(([userId, st]) => ({ userId, mute: !!st.mute, deaf: !!st.deaf })),
    });
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

  socket.on('disconnect', () => {
    Object.entries(voiceState).forEach(([key, users]) => {
      if (!users[socket.user.id]) return;
      delete users[socket.user.id];
      const [serverId, channelId] = key.split(':');
      io.to(`voice:${key}`).emit('voice:presence', {
        serverId,
        channelId,
        participants: Object.entries(users).map(([userId, st]) => ({ userId, mute: !!st.mute, deaf: !!st.deaf })),
      });
    });
  });
});

server.listen(PORT, HOST, () => {
  console.log(`Morv server running on http://${HOST}:${PORT}`);
  console.log(`DATA_FILE=${DATA_FILE}`);
});
