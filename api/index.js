const express = require('express');
const helmet = require('helmet');
const { kv } = require('@vercel/kv');

const app = express();
app.use(helmet());
app.use(express.json({ limit: '10kb' }));

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

// --- ФИЛЬТРАЦИЯ ---

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
    } catch (e) { return []; }
}

// --- РОУТЫ ---

app.get('/posts', async (req, res) => {
    res.json(await getPosts());
});

app.post('/posts', async (req, res) => {
    const { title, text } = req.body;
    if (typeof title !== 'string' || typeof text !== 'string') return res.sendStatus(400);

    const cleanTitle = title.trim();
    const cleanText = text.trim();

    if (containsBanWords(cleanTitle) || containsBanWords(cleanText)) {
        return res.status(403).json({ error: "В посте обнаружены запрещённые слова (или спам-ссылки)." });
    }

    const posts = await getPosts();

    // простая проверка дублей по тексту
    const isDuplicate = posts.some(p => p.text === cleanText);
    if (isDuplicate) {
        return res.status(403).json({ error: "Похоже на спам, напиши что-то другое." });
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
        res.status(500).send("Ошибка сохранения");
    }
});

module.exports = app;