const API = "/api/posts";

async function likePost(id, btn, countEl) {
    try {
        const res = await fetch(API + '/' + id + '/like', { method: 'POST' });
        if (!res.ok) throw new Error('err');
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
        if (!res.ok) { inputEl.disabled = false; return; }
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
        '<div class="c"><span class="cd">' + new Date(c.date).toLocaleDateString('ru') + '</span>' + c.text + '</div>'
    ).join('');
}

function toggleComments(commentsEl) {
    commentsEl.classList.toggle('open');
}

async function loadNews() {
    const feed = document.getElementById('feed');
    feed.innerHTML = '<img class="loader-gif" src="https://media.tenor.com/ptkoPmx8XAkAAAAi/windows-loading.gif">';
    try {
        const res = await fetch(API);
        if (!res.ok) throw new Error('Ошибка сервера (' + res.status + ')');
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
                        '<div class="c"><span class="cd">' + new Date(c.date).toLocaleDateString('ru') + '</span>' + c.text + '</div>'
                    ).join('') + '</div>' +
                    '<div class="cmt-form"><input class="cmt-input" placeholder="комментарий..."><button class="cmt-send"><i class="material-icons">send</i></button></div>' +
                '</div>' +
            '</div>';
        }).join('');
        attachListeners();
    } catch (e) {
        feed.innerHTML = '<p style="color:#e51400;font-weight:300;">не удалось загрузить ленту: ' + e.message + '</p>';
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
            throw new Error(data.error || 'Сервер ответил ошибкой: ' + res.status);
        }
        
        titleEl.value = '';
        textEl.value = '';
        await loadNews();
    } catch (e) {
        alert('Ошибка при публикации: ' + e.message);
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

document.getElementById('about-btn').addEventListener('click', () => {
    document.getElementById('about-modal').classList.add('open');
});
document.getElementById('about-close').addEventListener('click', () => {
    document.getElementById('about-modal').classList.remove('open');
});
document.getElementById('about-modal').addEventListener('click', (e) => {
    if (e.target === document.getElementById('about-modal')) {
        document.getElementById('about-modal').classList.remove('open');
    }
});