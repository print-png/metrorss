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

function getClientIP(req) {
    return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
}

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

function adminAuth(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith('Basic ')) {
        res.set('WWW-Authenticate', 'Basic realm="Admin"');
        return res.status(401).json({ error: 'Authentication required' });
    }
    const decoded = Buffer.from(auth.slice(6), 'base64').toString();
    const [, password] = decoded.split(':');
    if (password !== ADMIN_PASSWORD) {
        res.set('WWW-Authenticate', 'Basic realm="Admin"');
        return res.status(401).json({ error: 'Invalid password' });
    }
    next();
}

// --- ADMIN ROUTES ---

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
            image: p.image ? 'yes' : 'no'
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
            comments: []
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
        const posts = await getPosts();
        const post = posts.find(p => p.id === req.params.id);
        if (!post) return res.status(404).json({ error: 'Post not found' });
        
        const ip = getClientIP(req);
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