const express = require('express');
const path = require('path');
const helmet = require('helmet');
const { kv } = require('@vercel/kv');

const app = express();
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

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

function getClientIP(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

// --- HELPERS ---

const banWords = ['crypto', 'sparkwtf', '@sparkwtf', 'casino', 'slots', 'azino', 'азино', 'виннер', 't.me', 'telegram.me'];

function containsBanWords(text) {
    const lowerText = text.toLowerCase();
    return banWords.some(word => lowerText.includes(word));
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

async function getPosts() {
    try {
        const posts = await kv.get('posts');
        return Array.isArray(posts) ? posts : [];
    } catch (e) {
        console.error('KV GET error:', e);
        return [];
    }
}

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'mR55_2026!Admin#Secure';

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
    let r = '';
    for (let i = 0; i < 32; i++) r += chars[Math.floor(Math.random() * chars.length)];
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

function getDeviceID(req) {
    return req.headers['x-device-id'] || '';
}

// --- IP + DEVICE BAN MIDDLEWARE ---

app.use(async (req, res, next) => {
    if (req.path.startsWith('/api/admin')) return next();
    try {
        const blockedIPs = (await kv.get('blockedIPs')) || {};
        const ip = getClientIP(req);
        const ban = blockedIPs[ip];
        if (ban && ban.until > Date.now()) {
            return res.status(403).json({ error: 'вы забанены', reason: ban.reason || 'без причины', deviceId: getDeviceID(req) });
        }

        const deviceId = getDeviceID(req);
        if (deviceId) {
            const blockedDevices = (await kv.get('blockedDevices')) || {};
            const dban = blockedDevices[deviceId];
            if (dban && dban.until > Date.now()) {
                return res.status(403).json({ error: 'вы забанены', reason: dban.reason || 'без причины', deviceId });
            }
        }
    } catch (e) {}
    next();
});

// --- ADMIN AUTH ROUTES (no session required) ---

app.post('/api/admin/login', async (req, res) => {
    try {
        const { password } = req.body;
        if (!password) return res.status(400).json({ error: 'Введите пароль' });
        if (password !== ADMIN_PASSWORD) return res.status(403).json({ error: 'Неверный пароль' });

        const ip = getClientIP(req);
        if (!checkRateLimit(ip)) return res.status(429).json({ error: 'Слишком много попыток, подождите' });

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
        if (!ip) return res.status(400).json({ error: 'IP required' });
        const blockedIPs = (await kv.get('blockedIPs')) || {};
        blockedIPs[ip] = { reason: reason || 'Manual ban', until: until || Date.now() + 86400000, at: Date.now() };
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
        if (!deviceId) return res.status(400).json({ error: 'deviceId required' });
        const blockedDevices = (await kv.get('blockedDevices')) || {};
        blockedDevices[deviceId] = { reason: reason || 'Manual ban', until: until || Date.now() + 86400000, at: Date.now() };
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
        res.json(posts);
    } catch (e) {
        console.error('/api/posts GET error:', e);
        res.status(500).json({ error: 'Internal error' });
    }
});

app.post('/api/posts', async (req, res) => {
    try {
        const ip = getClientIP(req);
        if (!checkActionLimit(ip, 'post', 5, 60000)) {
            return res.status(429).json({ error: 'Слишком много постов, подожди' });
        }

        const { title, text } = req.body;
        if (typeof title !== 'string' || typeof text !== 'string') {
            return res.status(400).json({ error: 'Invalid input' });
        }

        const cleanTitle = title.trim();
        const cleanText = text.trim();

        if (containsBanWords(cleanTitle) || containsBanWords(cleanText)) {
            return res.status(403).json({ error: 'Forbidden words detected' });
        }

        const posts = await getPosts();

        const isDuplicate = posts.some(p => p.text === cleanText);
        if (isDuplicate) {
            return res.status(403).json({ error: 'Duplicate content' });
        }

        const newPost = {
            id: Date.now().toString(),
            title: sanitize(cleanTitle.substring(0, 100)),
            text: sanitize(cleanText.substring(0, 2000)),
            date: new Date().toUTCString(),
            likes: 0,
            comments: [],
            ip: getClientIP(req),
            deviceId: getDeviceID(req)
        };

        posts.unshift(newPost);
        
        await kv.set('posts', posts.slice(0, 500));
        res.status(201).json(newPost);
    } catch (e) {
        console.error('/api/posts POST error:', e);
        res.status(500).json({ error: 'Save failed: ' + e.message });
    }
});

app.post('/api/posts/:id/like', async (req, res) => {
    try {
        const ip = getClientIP(req);
        if (!checkActionLimit(ip, 'like', 30, 60000)) {
            return res.status(429).json({ error: 'Слишком много лайков, подожди' });
        }

        const posts = await getPosts();
        const post = posts.find(p => p.id === req.params.id);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        
        if (!post.likedBy) post.likedBy = [];
        
        if (post.likedBy.includes(ip)) {
            return res.status(409).json({ error: 'Already liked', likes: post.likes });
        }
        
        post.likedBy.push(ip);
        post.likes = (post.likes || 0) + 1;
        await kv.set('posts', posts.slice(0, 500));
        res.json({ likes: post.likes });
    } catch (e) {
        res.status(500).json({ error: 'Like failed' });
    }
});

app.post('/api/posts/:id/comments', async (req, res) => {
    try {
        const ip = getClientIP(req);
        if (!checkActionLimit(ip, 'comment', 10, 60000)) {
            return res.status(429).json({ error: 'Слишком много комментариев, подожди' });
        }

        const { text } = req.body;
        if (typeof text !== 'string' || !text.trim()) {
            return res.status(400).json({ error: 'Invalid comment' });
        }
        const commentText = text.trim().substring(0, 500);
        if (containsBanWords(commentText)) {
            return res.status(403).json({ error: 'Forbidden words' });
        }
        const posts = await getPosts();
        const post = posts.find(p => p.id === req.params.id);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        if (!post.comments) post.comments = [];
        post.comments.push({
            id: Date.now().toString(),
            text: sanitize(commentText),
            date: new Date().toUTCString()
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

module.exports = app;