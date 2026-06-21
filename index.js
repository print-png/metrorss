const express = require('express');
const path = require('path');
const helmet = require('helmet');
const net = require('net');
const { kv } = require('@vercel/kv');

const app = express();
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

// CSP headers
app.use((req, res, next) => {
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self' https://metrorss.vercel.app; frame-ancestors 'none'");
    next();
});

// Serve static files from public/
app.use(express.static(path.join(__dirname, 'public')));

// CORS
app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (origin === 'https://metrorss.vercel.app') {
        res.header("Access-Control-Allow-Origin", origin);
    }
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.header("Access-Control-Allow-Headers", "Content-Type");
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// --- HEADER/LIMITS GATE ---

app.use((req, res, next) => {
    const did = req.headers['x-device-id'];
    if (did && did.length > 128) {
        return res.status(400).json({ error: 'Invalid device ID' });
    }
    const ua = req.headers['user-agent'];
    if (ua && ua.length > 256) {
        return res.status(400).json({ error: 'Invalid user-agent' });
    }
    next();
});

function getClientIP(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

// --- HELPERS ---

const banWords = ['crypto', 'sparkwtf', '@sparkwtf', 'casino', 'slots', 'azino', 'азино', 'виннер', 't.me', 'telegram.me', '@xukuvu'];

async function containsBanWords(text) {
    const lowerText = text.toLowerCase();
    const builtin = banWords.some(word => lowerText.includes(word));
    if (builtin) return true;
    try {
        const adminWords = (await kv.get('adminBanWords')) || [];
        return adminWords.some(word => lowerText.includes(word));
    } catch(e) { return false; }
}

function sanitize(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;')
        .replace(/&lt;b&gt;/gi, '<b>')
        .replace(/&lt;\/b&gt;/gi, '</b>')
        .replace(/&lt;i&gt;/gi, '<i>')
        .replace(/&lt;\/i&gt;/gi, '</i>')
        .replace(/&lt;p&gt;/gi, '<p>')
        .replace(/&lt;\/p&gt;/gi, '</p>')
        .replace(/&lt;br\s*\/?&gt;/gi, '<br>');
}

function escapeXml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/'/g, '&apos;').replace(/"/g, '&quot;');
}

const postCache = { data: null, at: 0, ttl: 8000 };

async function getPosts() {
    const now = Date.now();
    if (postCache.data && now - postCache.at < postCache.ttl) return postCache.data;
    try {
        const posts = await kv.get('posts');
        postCache.data = Array.isArray(posts) ? posts : [];
        postCache.at = now;
        return postCache.data;
    } catch (e) {
        console.error('KV GET error:', e);
        return [];
    }
}

const banCache = { ips: null, devices: null, at: 0, ttl: 5000 };

async function getBlockedIPs() {
    const now = Date.now();
    if (banCache.ips && now - banCache.at < banCache.ttl) return banCache.ips;
    const data = (await kv.get('blockedIPs')) || {};
    banCache.ips = data;
    banCache.at = now;
    return data;
}

async function getBlockedDevices() {
    const now = Date.now();
    if (banCache.devices && now - banCache.at < banCache.ttl) return banCache.devices;
    const data = (await kv.get('blockedDevices')) || {};
    banCache.devices = data;
    banCache.at = now;
    return data;
}

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
    console.error('ADMIN_PASSWORD not set — admin login disabled');
}

// --- RATE LIMITER (in-memory) ---

const loginAttempts = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [key, val] of loginAttempts) {
        if (now > val.resetAt) loginAttempts.delete(key);
    }
}, 60000);

function checkRateLimit(ip) {
    const now = Date.now();
    let entry = loginAttempts.get(ip);
    if (!entry || now > entry.resetAt) {
        entry = { count: 0, resetAt: now + 900000 };
        loginAttempts.set(ip, entry);
    }
    entry.count++;
    return entry.count <= 10;
}

// --- ACTION RATE LIMITER (likes, comments) ---

const actionLimits = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [key, val] of actionLimits) {
        if (now > val.resetAt) actionLimits.delete(key);
    }
}, 30000);

function checkActionLimit(ip, action, max, windowMs) {
    const now = Date.now();
    const k = action + ':' + ip;
    let entry = actionLimits.get(k);
    if (!entry || now > entry.resetAt) {
        entry = { count: 0, resetAt: now + windowMs };
        actionLimits.set(k, entry);
    }
    entry.count++;
    return entry.count <= max;
}

// --- SESSION HELPERS ---

function randomToken() {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const bytes = require('crypto').randomBytes(32);
    let r = '';
    for (let i = 0; i < 32; i++) r += chars[bytes[i] % chars.length];
    return r;
}

async function adminAuth(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Требуется авторизация' });
    }
    const token = auth.slice(7);
    try {
        const session = await kv.get('session:' + token);
        if (!session) return res.status(401).json({ error: 'Сессия истекла' });
        req.adminIP = session.ip;
        next();
    } catch (e) {
        res.status(500).json({ error: 'Auth check failed' });
    }
}

// --- DEVICE ID HELPER ---

const crypto2 = require('crypto');

function hashStr(s) {
    let h = 0;
    for (let i = 0; i < s.length; i++) { h = ((h << 5) - h) + s.charCodeAt(i); h |= 0; }
    return Math.abs(h).toString(36);
}

function sha256(s) {
    const buf = crypto2.createHash('sha256').update(s).digest();
    return Array.from(buf).map(b => b.toString(36).padStart(2, '0')).join('').slice(0, 60);
}

function getDeviceID(req) {
    const id = req.headers['x-device-id'] || '';
    if (id && !id.startsWith('d_') && !id.startsWith('d2_') && !id.startsWith('d3_')) return '';
    if (id && id.length < 6) return '';
    return id;
}

// Validate device signals: compute hash and compare with device ID
function validateDeviceSignals(req) {
    const signals = req.headers['x-device-signals'];
    if (!signals || signals.length < 10) return { valid: false, reason: 'signals missing' };
    const id = req.headers['x-device-id'] || '';
    if (!id) return { valid: false, reason: 'no id' };

    const prefix = id.slice(0, 3);
    const claimedHash = id.slice(3);

    if (prefix === 'd3_') {
        const computedHash = sha256(signals);
        if (computedHash !== claimedHash) return { valid: false, reason: 'hash mismatch' };
        return { valid: true, reason: '' };
    }

    if (prefix === 'd2_') {
        const computedHash = hashStr(signals);
        if (computedHash !== claimedHash) return { valid: false, reason: 'hash mismatch (d2)' };
        return { valid: true, reason: '' };
    }

    if (prefix === 'd_') {
        const computedHash = hashStr(signals.slice(0, 500));
        if (computedHash !== claimedHash) return { valid: false, reason: 'hash mismatch (d)' };
        return { valid: true, reason: '' };
    }

    return { valid: false, reason: 'unknown prefix' };
}

// --- VPS/VDS BLOCK ---

const vpsCache = new Map();

async function isVPSIP(ip) {
    if (!ip || !net.isIP(ip)) return false;
    if (vpsCache.has(ip)) return vpsCache.get(ip);
    try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 3000);
        const res = await fetch('http://ip-api.com/json/' + ip + '?fields=hosting', { signal: ctrl.signal });
        clearTimeout(timer);
        if (!res.ok) return false;
        const data = await res.json();
        const r = data.hosting === true;
        vpsCache.set(ip, r);
        setTimeout(() => vpsCache.delete(ip), 86400000);
        return r;
    } catch (e) { return false; }
}

// --- IP + DEVICE BAN MIDDLEWARE ---

app.use(async (req, res, next) => {
    if (req.path.startsWith('/api/admin')) return next();
    try {
        const blockedIPs = await getBlockedIPs();
        const ip = getClientIP(req);
        const ban = blockedIPs[ip];
        if (ban && ban.until > Date.now()) {
            return res.status(403).json({ error: 'вы забанены', reason: ban.reason || 'без причины', deviceId: getDeviceID(req) });
        }

        const deviceId = getDeviceID(req);
        if (deviceId) {
            const blockedDevices = await getBlockedDevices();
            const dban = blockedDevices[deviceId];
            if (dban && dban.until > Date.now()) {
                return res.status(403).json({ error: 'вы забанены', reason: dban.reason || 'без причины', deviceId });
            }

            // signal validation: catch forged device IDs
            const sv = validateDeviceSignals(req);
            if (!sv.valid && deviceId.startsWith('d3_')) {
                const strikes = (await kv.get('signalStrike:' + ip)) || 0;
                const newStrikes = strikes + 1;
                await kv.set('signalStrike:' + ip, newStrikes, { ex: 86400 });
                if (newStrikes >= 3) {
                    const banned = await getBlockedIPs();
                    banned[ip] = { until: Date.now() + 86400000, reason: 'автобан: подделка deviceID' };
                    await kv.set('blockedIPs', banned);
                    banCache.at = 0;
                    return res.status(403).json({ error: 'вы забанены', reason: 'Обнаружена подделка deviceID', deviceId });
                }
            }

            const devicesPerIP = (await kv.get('devicesPerIP:' + ip)) || {};
            if (!devicesPerIP[deviceId]) {
                devicesPerIP[deviceId] = Date.now();
                if (Object.keys(devicesPerIP).length > 2) {
                    const banned = await getBlockedIPs();
                    banned[ip] = { until: Date.now() + 86400000, reason: 'автобан: смена deviceID' };
                    await kv.set('blockedIPs', banned);
                    banCache.at = 0;
                    return res.status(403).json({ error: 'вы забанены', reason: 'Слишком много устройств с одного IP', deviceId });
                }
                await kv.set('devicesPerIP:' + ip, devicesPerIP, { ex: 86400 });
            }
        }
    } catch (e) {}
    next();
});

// --- BLOCK CURL ---

app.use((req, res, next) => {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    if (ua.includes('curl') || ua.includes('wget') || ua.includes('httpie') || ua.includes('python-requests') || ua.includes('go-http-client') || ua.includes('okhttp') || ua.includes('nsis') || ua.includes('powershell') || ua.includes('.net')) {
        return res.status(403).json({ error: 'Браузеры и приложения только' });
    }
    next();
});

// --- RATE LIMITER (all requests) ---

const reqCounts = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [k, v] of reqCounts) {
        if (now > v.resetAt) reqCounts.delete(k);
    }
}, 10000);

function rateLimit(req, res, next) {
    if (req.path.startsWith('/api/admin')) return next();
    const ip = getClientIP(req);
    const now = Date.now();
    let entry = reqCounts.get(ip);
    if (!entry || now > entry.resetAt) {
        entry = { count: 0, strike: 0, resetAt: now + 10000 };
        reqCounts.set(ip, entry);
    }
    entry.count++;
    if (entry.count > 60) {
        entry.strike = (entry.strike || 0) + 1;
        if (entry.strike >= 3) {
            entry.strike = 0;
            const until = Date.now() + 1800000;
            try {
                getBlockedIPs().then(b => {
                    b[ip] = { until, reason: 'автобан: DoS' };
                    kv.set('blockedIPs', b);
                    banCache.at = 0;
                });
            } catch(e) {}
        }
        return res.status(429).json({ error: 'Слишком много запросов, подожди' });
    }
    next();
}
app.use(rateLimit);

// --- CONCURRENT REQUEST LIMITER ---

const activeConns = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [ip, val] of activeConns) {
        if (now > val.resetAt) activeConns.delete(ip);
    }
}, 30000);

app.use((req, res, next) => {
    if (req.path.startsWith('/api/admin')) return next();
    const ip = getClientIP(req);
    const now = Date.now();
    let entry = activeConns.get(ip);
    if (!entry || now > entry.resetAt) {
        entry = { count: 0, resetAt: now + 30000 };
        activeConns.set(ip, entry);
    }
    entry.count++;
    if (entry.count > 10) {
        entry.count--;
        try {
            kv.get('blockedIPs').then(b => {
                const bans = b || {};
                if (!bans[ip]) {
                    bans[ip] = { until: Date.now() + 3600000, reason: 'автобан: флуд соединениями' };
                    kv.set('blockedIPs', bans);
                    banCache.at = 0;
                }
            });
        } catch(e) {}
        return res.status(429).json({ error: 'Слишком много одновременных запросов' });
    }
    res.on('finish', () => {
        const c = activeConns.get(ip);
        if (c && c.count > 1) c.count--;
        else activeConns.delete(ip);
    });
    next();
});

// --- REQUEST TIMEOUT ---

app.use((req, res, next) => {
    res.setTimeout(10000, () => {
        if (!res.headersSent) res.status(503).json({ error: 'Timeout' });
        try { req.destroy(); } catch(e) {}
    });
    next();
});

// --- ADMIN AUTH ROUTES (no session required) ---

app.post('/api/admin/login', async (req, res) => {
    try {
        const ip = getClientIP(req);
        if (!checkRateLimit(ip)) return res.status(429).json({ error: 'Слишком много попыток, подождите' });

        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Введите пароль' });
        if (password !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Неверный пароль' });

        const token = randomToken();
        await kv.set('session:' + token, { ip, at: Date.now() }, { ex: 86400 });

        res.json({ token });
    } catch (e) {
        res.status(500).json({ error: 'Login failed' });
    }
});

// --- ADMIN ROUTES (session required) ---

app.get('/api/admin/stats', adminAuth, async (req, res) => {
    try {
        const posts = await getPosts();
        const blockedIPs = (await kv.get('blockedIPs')) || {};
        res.json({
            postsCount: posts.length,
            bannedIPsCount: Object.keys(blockedIPs).length,
            totalLikes: posts.reduce((sum, p) => sum + (p.likes || 0), 0),
            totalComments: posts.reduce((sum, p) => sum + (p.comments?.length || 0), 0)
        });
    } catch (e) {
        res.status(500).json({ error: 'Stats failed' });
    }
});

app.get('/api/admin/posts', adminAuth, async (req, res) => {
    try {
        const posts = await getPosts();
        res.json(posts.map(p => ({
            id: p.id,
            title: p.title,
            text: p.text.substring(0, 100),
            date: p.date,
            likes: p.likes || 0,
            commentsCount: p.comments?.length || 0,
            image: p.image ? 'yes' : 'no',
            ip: p.ip || '',
            deviceId: p.deviceId || ''
        })));
    } catch (e) {
        res.status(500).json({ error: 'Failed to load posts' });
    }
});

app.delete('/api/admin/posts/:id', adminAuth, async (req, res) => {
    try {
        const posts = await getPosts();
        const idx = posts.findIndex(p => p.id === req.params.id);
        if (idx === -1) return res.status(404).json({ error: 'Post not found' });
        posts.splice(idx, 1);
        await kv.set('posts', posts);
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Delete failed' });
    }
});

app.delete('/api/admin/posts', adminAuth, async (req, res) => {
    try {
        await kv.set('posts', []);
        res.json({ ok: true, cleared: true });
    } catch (e) {
        res.status(500).json({ error: 'Clear failed' });
    }
});

app.delete('/api/admin/bans', adminAuth, async (req, res) => {
    try {
        await kv.set('blockedIPs', {});
        res.json({ ok: true, cleared: true });
    } catch (e) {
        res.status(500).json({ error: 'Clear failed' });
    }
});

app.delete('/api/admin/banned-devices', adminAuth, async (req, res) => {
    try {
        await kv.set('blockedDevices', {});
        res.json({ ok: true, cleared: true });
    } catch (e) {
        res.status(500).json({ error: 'Clear failed' });
    }
});

app.get('/api/admin/banned', adminAuth, async (req, res) => {
    try {
        const blockedIPs = (await kv.get('blockedIPs')) || {};
        res.json(blockedIPs);
    } catch (e) {
        res.status(500).json({ error: 'Failed to load bans' });
    }
});

app.post('/api/admin/ban', adminAuth, async (req, res) => {
    try {
        const { ip, reason, until } = req.body;
        if (!ip || !net.isIP(ip)) return res.status(400).json({ error: 'Valid IP required' });
        const blockedIPs = (await kv.get('blockedIPs')) || {};
        const banUntil = (!until || until > Date.now() + 864000000) ? Date.now() + 86400000 : until;
        blockedIPs[ip] = { reason: reason || 'Manual ban', until: banUntil, at: Date.now() };
        await kv.set('blockedIPs', blockedIPs);
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Ban failed' });
    }
});

app.delete('/api/admin/ban/:ip', adminAuth, async (req, res) => {
    try {
        const blockedIPs = (await kv.get('blockedIPs')) || {};
        delete blockedIPs[req.params.ip];
        await kv.set('blockedIPs', blockedIPs);
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Unban failed' });
    }
});

// --- DEVICE BAN ADMIN ROUTES ---

app.get('/api/admin/banned-devices', adminAuth, async (req, res) => {
    try {
        const blockedDevices = (await kv.get('blockedDevices')) || {};
        res.json(blockedDevices);
    } catch (e) {
        res.status(500).json({ error: 'Failed to load device bans' });
    }
});

app.post('/api/admin/ban-device', adminAuth, async (req, res) => {
    try {
        const { deviceId, reason, until } = req.body;
        if (!deviceId || typeof deviceId !== 'string') return res.status(400).json({ error: 'deviceId required' });
        const blockedDevices = (await kv.get('blockedDevices')) || {};
        const banUntil = (!until || until > Date.now() + 864000000) ? Date.now() + 86400000 : until;
        blockedDevices[deviceId] = { reason: reason || 'Manual ban', until: banUntil, at: Date.now() };
        await kv.set('blockedDevices', blockedDevices);
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Ban failed' });
    }
});

app.delete('/api/admin/ban-device/:deviceId', adminAuth, async (req, res) => {
    try {
        const blockedDevices = (await kv.get('blockedDevices')) || {};
        delete blockedDevices[req.params.deviceId];
        await kv.set('blockedDevices', blockedDevices);
        res.json({ ok: true });
    } catch (e) {
        res.status(500).json({ error: 'Unban failed' });
    }
});

// --- ADMIN EMERGENCY ---

app.get('/api/admin/emergency', adminAuth, async (req, res) => {
    try {
        const msg = (await kv.get('emergency')) || { text: '', active: false };
        res.json(msg);
    } catch (e) { res.status(500).json({ error: 'Failed to load' }); }
});

app.post('/api/admin/emergency', adminAuth, async (req, res) => {
    try {
        const { text } = req.body;
        if (!text || text.length > 2000) return res.status(400).json({ error: 'Text required (max 2000)' });
        await kv.set('emergency', { text, active: true, at: Date.now() });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: 'Failed to save' }); }
});

app.delete('/api/admin/emergency', adminAuth, async (req, res) => {
    try {
        await kv.set('emergency', { text: '', active: false });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: 'Failed to clear' }); }
});

// --- PUBLIC EMERGENCY ---

app.get('/api/emergency', async (req, res) => {
    try {
        const msg = (await kv.get('emergency')) || { text: '', active: false };
        res.json(msg);
    } catch (e) { res.json({ text: '', active: false }); }
});

// --- ADMIN BANWORDS ---

app.get('/api/admin/banwords', adminAuth, async (req, res) => {
    try {
        const words = (await kv.get('adminBanWords')) || [];
        res.json(words);
    } catch (e) { res.json([]); }
});

app.post('/api/admin/banwords', adminAuth, async (req, res) => {
    try {
        const { words } = req.body;
        if (!Array.isArray(words)) return res.status(400).json({ error: 'Array expected' });
        await kv.set('adminBanWords', words.map(w => w.toLowerCase().trim()).filter(Boolean));
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// --- ADMIN ALL COMMENTS ---

app.get('/api/admin/comments', adminAuth, async (req, res) => {
    try {
        const posts = await getPosts();
        const all = [];
        posts.forEach(p => {
            (p.comments || []).forEach((c, ci) => {
                all.push({
                    postId: p.id,
                    postTitle: p.title || 'без заголовка',
                    ci,
                    text: c.text,
                    date: c.date
                });
            });
        });
        all.sort((a, b) => new Date(b.date) - new Date(a.date));
        res.json(all);
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/comments/:postId/:ci', adminAuth, async (req, res) => {
    try {
        const posts = await getPosts();
        const post = posts.find(p => p.id === req.params.postId);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        const ci = parseInt(req.params.ci);
        if (!post.comments || !post.comments[ci]) return res.status(404).json({ error: 'Comment not found' });
        post.comments.splice(ci, 1);
        await kv.set('posts', posts);
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// --- ADMIN SEARCH POSTS ---

app.get('/api/admin/search', adminAuth, async (req, res) => {
    try {
        const q = (req.query.q || '').toLowerCase().trim();
        if (!q) return res.json([]);
        const posts = await getPosts();
        const result = posts.filter(p =>
            (p.title || '').toLowerCase().includes(q) ||
            (p.text || '').toLowerCase().includes(q)
        );
        res.json(result.slice(0, 50));
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// --- ROUTES ---

app.get('/api/health', async (req, res) => {
    let kvOk = false;
    try {
        await kv.get('health');
        kvOk = true;
    } catch (e) {}
    res.json({ ok: true, kv: kvOk });
});

app.get('/api/posts', async (req, res) => {
    try {
        const posts = await getPosts();
        res.json(posts.slice(0, 30));
    } catch (e) {
        console.error('/api/posts GET error:', e);
        res.status(500).json({ error: 'Internal error' });
    }
});

app.get('/api/liked-by-device', async (req, res) => {
    try {
        const did = getDeviceID(req);
        if (!did) return res.json([]);
        const likedIds = (await kv.get('likedByDevice:' + did)) || [];
        const posts = await getPosts();
        res.json(likedIds.map(id => posts.find(p => p.id === id)).filter(Boolean).reverse());
    } catch (e) {
        res.status(500).json({ error: 'Failed' });
    }
});

app.post('/api/posts', async (req, res) => {
    try {
        const ip = getClientIP(req);
        if (!checkActionLimit(ip, 'post', 2, 120000)) {
            return res.status(429).json({ error: 'Слишком много постов, подожди 2 минуты' });
        }

        const { title, text } = req.body;
        if (typeof title !== 'string' || typeof text !== 'string') {
            return res.status(400).json({ error: 'Invalid input' });
        }

        const cleanTitle = title.trim();
        const cleanText = text.trim();

        if (cleanTitle.length < 2 || cleanText.length < 2) {
            return res.status(400).json({ error: 'Слишком короткий пост' });
        }

        if (await containsBanWords(cleanTitle) || await containsBanWords(cleanText)) {
            return res.status(403).json({ error: 'Forbidden words detected' });
        }

        if (await isVPSIP(ip)) {
            return res.status(403).json({ error: 'С VDS/VPS постить нельзя' });
        }

        const spamTokens = cleanTitle.split(/\s+/).filter(t => t.length >= 3 && /^@?[a-zA-Z0-9]+$/.test(t));
        if (spamTokens.length >= 3) {
            const spamStrikes = (await kv.get('spamStrike:' + ip)) || 0;
            await kv.set('spamStrike:' + ip, spamStrikes + 1, { ex: 86400 });
            if (spamStrikes + 1 >= 3) {
                const banned = await getBlockedIPs();
                banned[ip] = { until: Date.now() + 86400000, reason: 'автобан: спам заголовками' };
                await kv.set('blockedIPs', banned);
                banCache.at = 0;
            }
            return res.status(403).json({ error: 'Спам-детект' });
        }

        const posts = await getPosts();

        const isDuplicate = posts.some(p => p.text === cleanText);
        if (isDuplicate) {
            return res.status(403).json({ error: 'Duplicate content' });
        }

        const recent = posts.slice(0, 20).some(p =>
            p.ip === ip && Date.now() - new Date(p.date).getTime() < 30000
        );
        if (recent) {
            return res.status(429).json({ error: 'Подожди 30 секунд между постами' });
        }

        const ipCount = (await kv.get('postCount:' + ip)) || 0;
        if (ipCount >= 30) {
            return res.status(403).json({ error: 'Лимит постов исчерпан' });
        }
        await kv.set('postCount:' + ip, ipCount + 1);

        const newPost = {
            id: Date.now().toString(),
            title: sanitize(cleanTitle.substring(0, 100)),
            text: sanitize(cleanText.substring(0, 2000)),
            date: new Date().toUTCString(),
            likes: 0,
            comments: [],
            ip,
            deviceId: getDeviceID(req)
        };

        posts.unshift(newPost);
        
        await kv.set('posts', posts.slice(0, 500));
        res.status(201).json(newPost);
    } catch (e) {
        console.error('/api/posts POST error:', e);
        res.status(500).json({ error: 'Save failed' });
    }
});

app.post('/api/posts/:id/like', async (req, res) => {
    try {
        const did = getDeviceID(req);
        if (!did) return res.status(400).json({ error: 'Device ID required' });
        const ip = getClientIP(req);
        if (!checkActionLimit(ip, 'like', 30, 60000)) {
            return res.status(429).json({ error: 'Слишком много лайков, подожди' });
        }

        const posts = await getPosts();
        const post = posts.find(p => p.id === req.params.id);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        
        if (!post.likedBy) post.likedBy = [];
        
        if (post.likedBy.includes(did)) {
            return res.status(409).json({ error: 'Already liked', likes: post.likes });
        }
        
        post.likedBy.push(did);
        post.likes = (post.likes || 0) + 1;
        await kv.set('posts', posts.slice(0, 500));

        const likedByDevice = (await kv.get('likedByDevice:' + did)) || [];
        if (!likedByDevice.includes(post.id)) {
            likedByDevice.push(post.id);
            await kv.set('likedByDevice:' + did, likedByDevice.slice(-500));
        }

        res.json({ likes: post.likes });
    } catch (e) {
        res.status(500).json({ error: 'Like failed' });
    }
});

app.post('/api/posts/:id/comments', async (req, res) => {
    try {
        const ip = getClientIP(req);
        if (!checkActionLimit(ip, 'comment', 5, 60000)) {
            return res.status(429).json({ error: 'Слишком много комментариев, подожди' });
        }

        const { text } = req.body;
        if (typeof text !== 'string' || !text.trim()) {
            return res.status(400).json({ error: 'Invalid comment' });
        }
        const commentText = text.trim().substring(0, 500);
        if (commentText.length < 1) {
            return res.status(400).json({ error: 'Слишком короткий комментарий' });
        }
        if (await containsBanWords(commentText)) {
            return res.status(403).json({ error: 'Forbidden words' });
        }
        const posts = await getPosts();
        const post = posts.find(p => p.id === req.params.id);
        if (!post) return res.status(404).json({ error: 'Post not found' });

        const recent = (post.comments || []).filter(c =>
            c.ip === ip && Date.now() - new Date(c.date).getTime() < 15000
        );
        if (recent.length >= 2) {
            return res.status(429).json({ error: 'Подожди 15 секунд между комментариями' });
        }

        const ipCommentCount = (await kv.get('commentCount:' + ip)) || 0;
        if (ipCommentCount >= 100) {
            return res.status(403).json({ error: 'Лимит комментариев исчерпан' });
        }
        await kv.set('commentCount:' + ip, ipCommentCount + 1);

        if (!post.comments) post.comments = [];
        post.comments.push({
            id: Date.now().toString(),
            text: sanitize(commentText),
            date: new Date().toUTCString(),
            ip
        });
        await kv.set('posts', posts.slice(0, 500));
        res.status(201).json(post.comments);
    } catch (e) {
        res.status(500).json({ error: 'Comment failed' });
    }
});

app.get('/rss', async (req, res) => {
    try {
        const posts = await getPosts();
        res.set('Content-Type', 'application/rss+xml; charset=utf-8');
        const siteLink = "https://metrorss.vercel.app";
        let rss = '<?xml version="1.0" encoding="UTF-8" ?>\n<rss version="2.0">\n<channel>\n';
        rss += '<title>MetroRSS Feed</title>\n';
        rss += '<link>' + siteLink + '</link>\n';
        rss += '<description>Глобальный RSS поток пользователей MetroRSS</description>\n';
        rss += '<language>ru</language>\n';
        for (const post of posts) {
            rss += '<item>\n';
            rss += '  <title>' + escapeXml(post.title) + '</title>\n';
            rss += '  <link>' + siteLink + '</link>\n';
            rss += '  <description>' + escapeXml(post.text) + '</description>\n';
            rss += '  <pubDate>' + post.date + '</pubDate>\n';
            rss += '  <guid isPermaLink="false">' + post.id + '</guid>\n';
            rss += '</item>\n';
        }
        rss += '</channel>\n</rss>';
        res.send(rss);
    } catch (e) {
        console.error('/rss error:', e);
        res.status(500).send('RSS error');
    }
});

// --- GLOBAL ERROR HANDLER ---
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal error' });
});

module.exports = app;