const API = "/api/posts";

function hashStr(s) {
    let h = 0;
    for (let i = 0; i < s.length; i++) { h = ((h << 5) - h) + s.charCodeAt(i); h |= 0; }
    return Math.abs(h).toString(36);
}

async function sha256(s) {
    try {
        const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
        return Array.from(new Uint8Array(buf)).map(b => b.toString(36).padStart(2, '0')).join('').slice(0, 60);
    } catch(e) { return null; }
}

function getCanvasFP() {
    try {
        const c = document.createElement('canvas');
        c.width = 256; c.height = 128;
        const ctx = c.getContext('2d');
        ctx.textBaseline = 'alphabetic';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(10, 10, 60, 60);
        ctx.fillStyle = '#069';
        ctx.fillText('C=π·d', 5, 40);
        ctx.fillStyle = '#444';
        ctx.font = '12px monospace';
        ctx.fillText(navigator.userAgent.slice(-8), 5, 70);
        ctx.font = 'bold 20px Georgia';
        ctx.fillStyle = '#2a9';
        ctx.fillText('g@', 120, 50);
        ctx.strokeStyle = '#e3a87e';
        ctx.lineWidth = 2.5;
        ctx.beginPath();
        ctx.arc(200, 60, 28, 0, Math.PI * 2);
        ctx.stroke();
        ctx.fillStyle = 'rgba(200,40,80,0.25)';
        ctx.beginPath();
        ctx.ellipse(35, 100, 42, 18, 0.3, 0, Math.PI * 2);
        ctx.fill();
        const grad = ctx.createLinearGradient(120, 0, 220, 0);
        grad.addColorStop(0, '#a0f');
        grad.addColorStop(1, '#0af');
        ctx.fillStyle = grad;
        ctx.fillRect(140, 90, 60, 25);
        return hashStr(c.toDataURL());
    } catch(e) { return ''; }
}



function getSignalString() {
    const parts = [
        navigator.userAgent,
        screen.width + 'x' + screen.height + 'x' + screen.colorDepth,
        navigator.language,
        Intl.DateTimeFormat().resolvedOptions().timeZone,
        navigator.platform,
        navigator.hardwareConcurrency || '',
        navigator.deviceMemory || '',
        navigator.maxTouchPoints,
        getCanvasFP(),
        navigator.webdriver || '',
        navigator.vendor || '',
        window.devicePixelRatio || '',
        screen.availWidth + 'x' + screen.availHeight,
        screen.pixelDepth || '',
        (screen.orientation ? screen.orientation.type : '') || '',
        (navigator.plugins ? navigator.plugins.length : '') || '',
                navigator.productSub || '',
                (navigator.userAgent.match(/Android\s[\d.]+/)?.[0]) || '',
                navigator.userAgentData?.platform || ''
    ];
    return parts.join('|');
}

let _cachedDID = null;

async function generateDeviceID() {
    const signals = getSignalString();
    let h = await sha256(signals);
    if (!h || h.length < 16) h = hashStr(signals);
    const id = 'd3_' + h;
    saveDeviceID(id);
    _cachedDID = id;
    return id;
}

function getDeviceID() {
    if (_cachedDID) return _cachedDID;
    let id = localStorage.getItem('_did') || sessionStorage.getItem('_did') || getCookie('_did');
    if (!id) {
        const signals = getSignalString();
        const h = hashStr(signals);
        id = 'd2_' + h;
        saveDeviceID(id);
    }
    _cachedDID = id;
    generateDeviceID().catch(() => {});
    return id;
}

function saveDeviceID(id) {
    try { localStorage.setItem('_did', id); } catch(e) {}
    try { sessionStorage.setItem('_did', id); } catch(e) {}
    try { setCookie('_did', id, 365); } catch(e) {}
    try {
        const req = indexedDB.open('_did_db', 1);
        req.onupgradeneeded = () => req.result.createObjectStore('d', { keyPath: 'k' });
        req.onsuccess = () => {
            const tx = req.result.transaction('d', 'readwrite');
            const store = tx.objectStore('d');
            store.get('id').onsuccess = (e) => {
                if (!e.target.result) store.put({ k: 'id', v: id });
            };
        };
    } catch(e) {}
}

function getCookie(n) {
    const m = document.cookie.match('(^|;)\\s*' + n + '\\s*=\\s*([^;]+)');
    return m ? m.pop() : '';
}

function setCookie(n, v, days) {
    const d = new Date();
    d.setTime(d.getTime() + days * 864e5);
    document.cookie = n + '=' + v + '; expires=' + d.toUTCString() + '; path=/; SameSite=Lax';
}

const origFetch = window.fetch;
window.fetch = function(url, opts = {}) {
    opts = opts || {};
    opts.headers = opts.headers || {};
    opts.headers['X-Device-ID'] = getDeviceID();
    opts.headers['X-Device-Signals'] = getSignalString().slice(0, 2000);
    return origFetch.call(window, url, opts);
};

async function likePost(id, btn, countEl) {
    try {
        const res = await fetch(API + '/' + id + '/like', { method: 'POST' });
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            if (res.status === 403 && errData.error) {
                alert(errData.error + (errData.reason ? ' (' + errData.reason + ')' : ''));
            }
            return;
        }
        const data = await res.json();
        countEl.textContent = data.likes;
        btn.classList.add('liked');
        setTimeout(() => btn.classList.remove('liked'), 300);
    } catch (e) {}
}

async function addComment(id, inputEl, listEl) {
    const text = inputEl.value.trim();
    if (!text) return;
    inputEl.value = '';
    inputEl.disabled = true;
    try {
        const res = await fetch(API + '/' + id + '/comments', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ text: text })
        });
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            if (res.status === 403 && errData.error) {
                alert(errData.error + (errData.reason ? ' (' + errData.reason + ')' : ''));
            }
            inputEl.disabled = false;
            return;
        }
        const comments = await res.json();
        renderComments(comments, listEl);
    } catch (e) {}
    inputEl.disabled = false;
}

function renderComments(comments, listEl) {
    if (!comments || comments.length === 0) {
        listEl.innerHTML = '';
        return;
    }
    listEl.innerHTML = comments.map(c =>
        '<div class="c"><span class="cd">' + new Date(c.date).toLocaleDateString('ru') + '</span>' + esc(c.text) + '</div>'
    ).join('');
}

function toggleComments(commentsEl) {
    commentsEl.classList.toggle('open');
}

function esc(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

async function loadNews(silent) {
    const feed = document.getElementById('feed');
    if (!silent) feed.innerHTML = '<img class="loader-gif" src="/loader.gif">';
    try {
        const res = await fetch(API);
        if (!res.ok) {
            const errData = await res.json().catch(() => ({}));
            if (res.status === 403 && errData.error) {
                feed.innerHTML = '<div class="post" style="border-color:#e51400;"><p style="color:#e51400;font-weight:300;"><b>вы забанены</b>' + (errData.reason ? '<br><span style="color:#999;font-size:13px;">причина: ' + esc(errData.reason) + '</span>' : '') + (errData.deviceId ? '<br><span style="color:#555;font-size:11px;">device: ' + esc(errData.deviceId) + '</span>' : '') + '</p></div>';
                return;
            }
            throw new Error('Ошибка сервера (' + res.status + ')');
        }
        const data = await res.json();
        if (!Array.isArray(data) || data.length === 0) { 
            feed.innerHTML = '<p style="color:#666;font-style:italic;font-weight:300;">лента новостей пуста.</p>'; 
            return; 
        }
        feed.innerHTML = data.map((p, i) => {
            const id = p && p.id ? p.id : '';
            const title = p && p.title ? String(p.title).toLowerCase() : 'без заголовка';
            const text = p && p.text ? String(p.text) : '';
            const likes = p && typeof p.likes === 'number' ? p.likes : 0;
            const comments = p && Array.isArray(p.comments) ? p.comments : [];
            return '<div class="post' + (silent ? ' no-anim' : '') + '" style="' + (silent ? '' : 'animation-delay:' + (i*0.05) + 's') + '" data-id="' + id + '">' +
                '<h2>' + title + '</h2><p>' + text + '</p>' +
                '<div class="bar">' +
                    '<button class="like-btn" data-id="' + id + '">' +
                        '<i class="material-icons">favorite_border</i>' +
                        '<span class="lc">' + likes + '</span>' +
                    '</button>' +
                    '<button class="cmt-btn" data-id="' + id + '">' +
                        '<i class="material-icons">chat_bubble_outline</i>' +
                        '<span>' + comments.length + '</span>' +
                    '</button>' +
                '</div>' +
                '<div class="comments">' +
                    '<div class="cmt-list">' + comments.map(c =>
                        '<div class="c"><span class="cd">' + new Date(c.date).toLocaleDateString('ru') + '</span>' + esc(c.text) + '</div>'
                    ).join('') + '</div>' +
                    '<div class="cmt-form"><input class="cmt-input" placeholder="комментарий..."><button class="cmt-send"><i class="material-icons">send</i></button></div>' +
                '</div>' +
            '</div>';
        }).join('');
        attachListeners();
    } catch (e) {
        if (!silent) feed.innerHTML = '<p style="color:#e51400;font-weight:300;">не удалось загрузить ленту: ' + esc(e.message) + '</p>';
    }
}

function attachListeners() {
    document.querySelectorAll('.like-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = this.dataset.id;
            const countEl = this.querySelector('.lc');
            likePost(id, this, countEl);
        });
    });
    
    document.querySelectorAll('.cmt-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const id = this.dataset.id;
            const postEl = document.querySelector('.post[data-id="' + id + '"]');
            const commentsEl = postEl.querySelector('.comments');
            toggleComments(commentsEl);
        });
    });
    
    document.querySelectorAll('.cmt-send').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const postEl = this.closest('.post');
            const id = postEl.dataset.id;
            const inputEl = postEl.querySelector('.cmt-input');
            const listEl = postEl.querySelector('.cmt-list');
            addComment(id, inputEl, listEl);
            const cmtBtn = postEl.querySelector('.cmt-btn span');
            cmtBtn.textContent = postEl.querySelectorAll('.c').length;
        });
    });
    
    document.querySelectorAll('.cmt-input').forEach(input => {
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                const postEl = this.closest('.post');
                const id = postEl.dataset.id;
                const listEl = postEl.querySelector('.cmt-list');
                addComment(id, this, listEl);
                const cmtBtn = postEl.querySelector('.cmt-btn span');
                const count = postEl.querySelectorAll('.c').length;
                cmtBtn.textContent = count;
            }
        });
        input.addEventListener('click', function(e) { e.stopPropagation(); });
    });
}

async function postNews() {
    const titleEl = document.getElementById('t');
    const textEl = document.getElementById('d');
    const btn = document.getElementById('submit-btn');
    
    if (!titleEl.value.trim() || !textEl.value.trim()) {
        return alert('Заполните все поля!');
    }
    
    btn.disabled = true;
    btn.innerHTML = 'публикация...';
    
    try {
        const res = await fetch(API, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ title: titleEl.value, text: textEl.value })
        });
        const data = await res.json();
        
        if (!res.ok) {
            const msg = data.reason ? data.error + ' (' + data.reason + ')' : data.error;
            throw new Error(msg || 'Сервер ответил ошибкой: ' + res.status);
        }
        
        titleEl.value = '';
        textEl.value = '';
        await loadNews();
    } catch (e) {
        alert(e.message);
    } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="material-icons" style="font-size:18px;">send</i> опубликовать';
    }
}

document.getElementById('submit-btn').addEventListener('click', postNews);

document.addEventListener('pointerdown', (e) => {
    const target = e.target.closest('.wp-btn, .post, .wp-box');
    if (!target) return;
    if (e.target.closest('.bar, .comments, .like-btn, .cmt-btn, .cmt-form, .cmt-input, .cmt-send')) return;
    const rect = target.getBoundingClientRect();
    const rotateY = ((e.clientX - rect.left - rect.width / 2) / (rect.width / 2)) * 8;
    const rotateX = -((e.clientY - rect.top - rect.height / 2) / (rect.height / 2)) * 8;
    target.style.transform = 'perspective(600px) scale(0.97) rotateX(' + rotateX + 'deg) rotateY(' + rotateY + 'deg)';
    target.style.transition = 'transform 0.05s ease-out';
    const reset = () => { target.style.transform = ''; target.style.transition = 'transform 0.3s cubic-bezier(0.1, 0.9, 0.2, 1)'; document.removeEventListener('pointerup', reset); target.removeEventListener('pointerleave', reset); };
    document.addEventListener('pointerup', reset);
    target.addEventListener('pointerleave', reset);
});

loadNews();

let autoRefresh = setInterval(() => {
    if (currentFeed === 'all') loadNews(true);
}, 30000);

async function loadEmergency() {
    try {
        const res = await fetch('/api/emergency');
        const data = await res.json();
        const banner = document.getElementById('emergency-banner');
        const textEl = document.getElementById('emergency-text');
        if (data.active && data.text) {
            textEl.textContent = data.text;
            banner.style.display = 'block';
        } else {
            banner.style.display = 'none';
        }
    } catch(e) {}
}
loadEmergency();

let currentFeed = 'all';

document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', async function() {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        this.classList.add('active');
        currentFeed = this.dataset.feed;
        if (currentFeed === 'all') {
            await loadNews(true);
        } else if (currentFeed === 'liked') {
            await loadLiked();
        }
    });
});

async function loadLiked() {
    const feed = document.getElementById('feed');
    feed.innerHTML = '<img class="loader-gif" src="/loader.gif">';
    try {
        const res = await fetch('/api/liked-by-device');
        const data = await res.json();
        if (!Array.isArray(data) || data.length === 0) {
            feed.innerHTML = '<p style="color:#666;font-style:italic;font-weight:300;">вы ещё не лайкали посты.</p>';
            return;
        }
        feed.innerHTML = data.map((p, i) => {
            const id = p && p.id ? p.id : '';
            const title = p && p.title ? String(p.title).toLowerCase() : 'без заголовка';
            const text = p && p.text ? String(p.text) : '';
            const likes = p && typeof p.likes === 'number' ? p.likes : 0;
            const comments = p && Array.isArray(p.comments) ? p.comments : [];
            return '<div class="post" style="animation-delay:' + (i*0.05) + 's" data-id="' + id + '">' +
                '<h2>' + title + '</h2><p>' + text + '</p>' +
                '<div class="bar">' +
                    '<button class="like-btn" data-id="' + id + '">' +
                        '<i class="material-icons">favorite_border</i>' +
                        '<span class="lc">' + likes + '</span>' +
                    '</button>' +
                    '<button class="cmt-btn" data-id="' + id + '">' +
                        '<i class="material-icons">chat_bubble_outline</i>' +
                        '<span>' + comments.length + '</span>' +
                    '</button>' +
                '</div>' +
                '<div class="comments">' +
                    '<div class="cmt-list">' + comments.map(c =>
                        '<div class="c"><span class="cd">' + new Date(c.date).toLocaleDateString('ru') + '</span>' + esc(c.text) + '</div>'
                    ).join('') + '</div>' +
                    '<div class="cmt-form"><input class="cmt-input" placeholder="комментарий..."><button class="cmt-send"><i class="material-icons">send</i></button></div>' +
                '</div>' +
            '</div>';
        }).join('');
        attachListeners();
    } catch (e) {
        feed.innerHTML = '<p style="color:#e51400;font-weight:300;">ошибка загрузки.</p>';
    }
}