const { kv } = require('@vercel/kv');

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

module.exports = async (req, res) => {
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
};