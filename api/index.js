const express = require('express');
const path = require('path');
const helmet = require('helmet');
const { kv } = require('@vercel/kv');
const app = express();

app.use(helmet());

const botAgents = ['python-requests','python-urllib','curl/','wget','go-http-client','axios/','httpunit','java/','node-fetch','php/','ruby','semrushbot','ahrefsbot','mj12bot'];
app.use((req, res, next) => {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    if (!ua || ua.length < 10) return res.status(403).send('Forbidden');
    if (botAgents.some(b => ua.includes(b))) return res.status(403).send('Forbidden');
    next();
});

app.use((req, res, next) => {
    const xff = req.headers['x-forwarded-for'];
    if (xff && xff.split(',').length > 3) return res.status(403).send('Forbidden');
    next();
});

app.use((req, res, next) => {
    if (req.originalUrl.length > 200) return res.status(414).send('URI Too Long');
    next();
});

app.use(express.json({ limit: '10kb' }));

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

// === RATE LIMITING ===

const blockedIPs = new Map();

function getClientIP(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

function addViolation(ip) {
    const entry = blockedIPs.get(ip) || { violations: 0, until: 0 };
    entry.violations++;
    if (entry.violations >= 3) {
        entry.until = Date.now() + 600000;
        entry.violations = 0;
    }
    blockedIPs.set(ip, entry);
    cleanupMap(blockedIPs, 600000, 5000);
}

function cleanupMap(map, maxAge, maxEntries) {
    const now = Date.now();
    if (map.size <= maxEntries) return;
    for (const [key, val] of map) {
        if (Array.isArray(val) && val.length > 0 && now - val[val.length - 1] > maxAge) map.delete(key);
        else if (!Array.isArray(val) && val.until && now > val.until + 600000) map.delete(key);
    }
}

app.use((req, res, next) => {
    const ip = getClientIP(req);
    const blocked = blockedIPs.get(ip);
    if (blocked && Date.now() < blocked.until) return res.status(403).send('Forbidden');
    if (blocked && Date.now() >= blocked.until) blockedIPs.delete(ip);
    req.clientIP = ip;
    next();
});

const globalLimits = new Map();
app.use((req, res, next) => {
    const ip = req.clientIP;
    const now = Date.now();
    const timestamps = globalLimits.get(ip) || [];
    const recent = timestamps.filter(t => now - t < 10000);
    if (recent.length >= 30) {
        addViolation(ip);
        return res.status(429).set('Retry-After', '10').json({ error: "\u0421\u043b\u0438\u0448\u043a\u043e\u043c \u043c\u043d\u043e\u0433\u043e \u0437\u0430\u043f\u0440\u043e\u0441\u043e\u0432" });
    }
    recent.push(now);
    globalLimits.set(ip, recent);
    cleanupMap(globalLimits, 10000, 5000);
    next();
});

const perEndpointLimits = new Map();
function antiSpam(maxRequests, windowMs) {
    return function(req, res, next) {
        const ip = req.clientIP;
        const now = Date.now();
        const key = ip + ':' + req.path;
        const timestamps = perEndpointLimits.get(key) || [];
        const recent = timestamps.filter(t => now - t < windowMs);
        if (recent.length >= maxRequests) {
            addViolation(ip);
            return res.status(429).set('Retry-After', String(Math.ceil(windowMs / 1000))).json({ error: "\u041f\u0440\u0438\u0442\u043e\u0440\u043c\u043e\u0437\u0438!" });
        }
        recent.push(now);
        perEndpointLimits.set(key, recent);
        cleanupMap(perEndpointLimits, windowMs, 10000);
        next();
    };
}

// --- \u0424\u0418\u041b\u042c\u0422\u0420\u0410\u0426\u0418\u042f ---

const banWords = ['crypto', 'sparkwtf', '@sparkwtf', 'casino', 'slots', 'azino', '\u0430\u0437\u0438\u043d\u043e', '\u0432\u0438\u043d\u043d\u0435\u0440', 't.me', 'telegram.me'];

function containsBanWords(text) {
    const lowerText = text.toLowerCase();
    return banWords.some(word => lowerText.includes(word));
}

function getSimilarity(s1, s2) {
    let longer = s1; let shorter = s2;
    if (s1.length < s2.length) { longer = s2; shorter = s1; }
    let longerLength = longer.length;
    if (longerLength === 0) return 1.0;
    const costs = new Array();
    for (let i = 0; i <= longer.length; i++) {
        let lastValue = i;
        for (let j = 0; j <= shorter.length; j++) {
            if (i == 0) costs[j] = j;
            else {
                if (j > 0) {
                    let newValue = costs[j - 1];
                    if (longer.charAt(i - 1) != shorter.charAt(j - 1))
                        newValue = Math.min(Math.min(newValue, lastValue), costs[j]) + 1;
                    costs[j - 1] = lastValue;
                    lastValue = newValue;
                }
            }
        }
        if (i > 0) costs[shorter.length] = lastValue;
    }
    return (longerLength - costs[shorter.length]) / parseFloat(longerLength);
}

function isSpam(newText, existingPosts) {
    const checkCount = Math.min(existingPosts.length, 10);
    for (let i = 0; i < checkCount; i++) {
        if (getSimilarity(newText, existingPosts[i].text) > 0.85) return true;
    }
    return false;
}

function sanitize(str) {
    if (typeof str !== 'string') return '';
    return str
        .replace(/&/g, '\x26amp;')
        .replace(/</g, '\x26lt;')
        .replace(/>/g, '\x26gt;')
        .replace(/"/g, '\x26quot;')
        .replace(/'/g, '\x26#039;')
        .replace(/\x26lt;b\x26gt;/gi, '<b>')
        .replace(/\x26lt;\/b\x26gt;/gi, '</b>')
        .replace(/\x26lt;i\x26gt;/gi, '<i>')
        .replace(/\x26lt;\/i\x26gt;/gi, '</i>')
        .replace(/\x26lt;p\x26gt;/gi, '<p>')
        .replace(/\x26lt;\/p\x26gt;/gi, '</p>')
        .replace(/\x26lt;br\s*\/?\x26gt;/gi, '<br>');
}

function escapeXml(str) {
    if (!str) return '';
    return str.replace(/\x26/g, '\x26amp;').replace(/</g, '\x26lt;').replace(/>/g, '\x26gt;').replace(/'/g, '\x26apos;').replace(/"/g, '\x26quot;');
}

async function getPosts() {
    try {
        const posts = await kv.get('posts');
        return Array.isArray(posts) ? posts : [];
    } catch (e) { return []; }
}

// --- РОУТЫ ---

app.get('/posts', antiSpam(60, 60000), async (req, res) => {
    res.json(await getPosts());
});

app.post('/posts', antiSpam(15, 60000), async (req, res) => {
    const { title, text } = req.body;
    if (typeof title !== 'string' || typeof text !== 'string') return res.sendStatus(400);

    const cleanTitle = title.trim();
    const cleanText = text.trim();

    if (containsBanWords(cleanTitle) || containsBanWords(cleanText)) {
        return res.status(403).json({ error: "\u0412 \u043f\u043e\u0441\u0442\u0435 \u043e\u0431\u043d\u0430\u0440\u0443\u0436\u0435\u043d\u044b \u0437\u0430\u043f\u0440\u0435\u0449\u0435\u043d\u043d\u044b\u0435 \u0441\u043b\u043e\u0432\u0430 (\u0438\u043b\u0438 \u0441\u043f\u0430\u043c-\u0441\u0441\u044b\u043b\u043a\u0438)." });
    }

    const posts = await getPosts();

    if (isSpam(cleanText, posts)) {
        return res.status(403).json({ error: "\u041f\u043e\u0445\u043e\u0436\u0435 \u043d\u0430 \u0441\u043f\u0430\u043c, \u043d\u0430\u043f\u0438\u0448\u0438 \u0447\u0442\u043e-\u043d\u0438\u0431\u0443\u0434\u044c \u0434\u0440\u0443\u0433\u043e\u0435." });
    }

    const newPost = {
        id: Date.now().toString(),
        title: sanitize(cleanTitle.substring(0, 100)),
        text: sanitize(cleanText.substring(0, 2000)),
        date: new Date().toUTCString()
    };

    posts.unshift(newPost);
    try {
        await kv.set('posts', posts.slice(0, 500));
        res.status(201).json(newPost);
    } catch (e) {
        res.status(500).send("\u041e\u0448\u0438\u0431\u043a\u0430 \u0441\u043e\u0445\u0440\u0430\u043d\u0435\u043d\u0438\u044f");
    }
});

module.exports = app;
