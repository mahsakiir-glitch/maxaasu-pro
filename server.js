require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || JWT_SECRET + '_admin';
const STREAM_SECRET = process.env.STREAM_SECRET || JWT_SECRET + '_stream';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

let supabase;
try {
  supabase = createClient(SUPABASE_URL || 'https://placeholder.supabase.co', SUPABASE_KEY || 'placeholder');
} catch (e) {
  supabase = null;
  console.error('Supabase client failed to initialize');
}

/* ═══ View Dedup - prevents counting same token twice ═══ */
const viewedTokens = new Set();
setInterval(() => viewedTokens.clear(), 300000);

/* ═══ Middleware ═══ */
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

const globalLimiter = rateLimit({ windowMs: 60000, max: 300, trustProxy: true, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({ windowMs: 900000, max: 10, trustProxy: true, message: { error: 'Too many login attempts' } });
const streamLimiter = rateLimit({ windowMs: 60000, max: 100, trustProxy: true });
const contactLimiter = rateLimit({ windowMs: 3600000, max: 5, trustProxy: true });

app.use(globalLimiter);
app.use(express.static(path.join(__dirname, 'public')));

/* ═══ Auth Middleware ═══ */
function auth(req, res, next) {
  const t = req.cookies?.token;
  if (!t) return res.status(401).json({ error: 'Authentication required' });
  try { req.admin = jwt.verify(t, ADMIN_JWT_SECRET); next(); }
  catch { res.clearCookie('token'); return res.status(403).json({ error: 'Invalid or expired session' }); }
}

/* ═══ Helper Functions ═══ */
function resolveUrl(url, type) {
  let u = url || '';
  if (type === 'archive') {
    var m = u.match(/archive\.org\/details\/([^/?\s]+)/);
    if (m) u = 'https://archive.org/download/' + m[1] + '/' + m[1] + '.mp4';
  }
  if (type === 'ipfs' && u.startsWith('ipfs://')) {
    u = u.replace('ipfs://', 'https://gateway.pinata.cloud/ipfs/');
  }
  return u;
}

function extractYoutubeId(url) {
  if (!url) return null;
  var m = url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
  return m ? m[1] : null;
}

function isYoutubeUrl(url) {
  if (!url) return false;
  return /(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)/i.test(url);
}

/* ═══ Admin Setup ═══ */
async function setupAdmin() {
  if (!supabase) return;
  try {
    var { data } = await supabase.from('admin_users').select('id').limit(1);
    if (!data?.length) {
      var h = await bcrypt.hash('Admin@2024', 12);
      await supabase.from('admin_users').insert({ username: 'admin', password_hash: h, pin: '12345678' });
      console.log('Admin created: admin / Admin@2024 / PIN: 12345678');
    }
  } catch (e) { console.error('Admin setup error:', e.message); }
}
setupAdmin();

/* ═══════════════════════════════════════
   AUTH ROUTES
   ═══════════════════════════════════════ */
app.post('/api/v1/auth/check-pin', async (req, res) => {
  try {
    var { username, pin } = req.body;
    if (!username || !pin) return res.json({ valid: false });
    var { data } = await supabase.from('admin_users').select('pin').eq('username', username).single();
    res.json({ valid: data?.pin === pin && pin.length === 8 });
  } catch { res.json({ valid: false }); }
});

app.post('/api/v1/auth/login', authLimiter, async (req, res) => {
  try {
    var { username, password, pin } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Missing fields' });
    var { data: admin, error } = await supabase.from('admin_users').select('*').eq('username', username).single();
    if (error || !admin || !(await bcrypt.compare(password, admin.password_hash))) return res.status(401).json({ error: 'Invalid credentials' });
    if (!pin || pin.length !== 8 || admin.pin !== pin) return res.status(401).json({ error: 'Invalid PIN' });
    const token = jwt.sign({ id: admin.id, username: admin.username }, ADMIN_JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 24 * 60 * 60 * 1000
    }).json({ username: admin.username, success: true });
  } catch { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/v1/auth/logout', (req, res) => {
  res.clearCookie('token').json({ success: true });
});

/* ═══════════════════════════════════════
   STREAM TOKEN REQUEST - VIDEO
   ═══════════════════════════════════════ */
app.post('/api/v1/videos/request-stream/:videoId', streamLimiter, async (req, res) => {
  try {
    const { videoId } = req.params;
    const { data: v, error } = await supabase.from('videos').select('*').eq('id', videoId).single();
    if (error || !v) return res.status(404).json({ error: 'Video not found' });
    if (!v.is_published) return res.status(403).json({ error: 'Video not available' });

    /* Check YouTube by BOTH video_type AND URL pattern */
    const yid = extractYoutubeId(v.url);
    if (v.video_type === 'youtube' || yid) {
      if (yid) {
        return res.json({
          streamToken: null,
          youtubeUrl: 'https://www.youtube-nocookie.com/embed/' + yid + '?autoplay=1&rel=0&modestbranding=1&playsinline=1',
          type: 'youtube'
        });
      }
    }

    const streamToken = jwt.sign(
      { videoId: v.id, type: v.video_type || 'mp4', media: 'video' },
      STREAM_SECRET,
      { expiresIn: '300s' }
    );
    res.json({ streamToken, type: v.video_type || 'mp4' });
  } catch (e) {
    console.error('Video token error:', e.message);
    res.status(500).json({ error: 'Failed to generate stream token' });
  }
});

/* ═══════════════════════════════════════
   STREAM TOKEN REQUEST - AUDIO
   ═══════════════════════════════════════ */
app.post('/api/v1/audio/request-stream/:audioId', streamLimiter, async (req, res) => {
  try {
    const { audioId } = req.params;
    const { data: a, error } = await supabase.from('audio_tracks').select('*').eq('id', audioId).single();
    if (error || !a) return res.status(404).json({ error: 'Audio not found' });
    if (!a.is_published) return res.status(403).json({ error: 'Audio not available' });

    const streamToken = jwt.sign(
      { audioId: a.id, type: a.audio_type || 'mp3', media: 'audio' },
      STREAM_SECRET,
      { expiresIn: '300s' }
    );
    res.json({ streamToken, type: a.audio_type || 'mp3' });
  } catch (e) {
    console.error('Audio token error:', e.message);
    res.status(500).json({ error: 'Failed to generate stream token' });
  }
});

/* ═══════════════════════════════════════
   STREAM ENDPOINT — REDIRECT APPROACH
   Token verify → count view → 302 redirect to actual URL
   Browser video/audio element follows redirect automatically
   ═══════════════════════════════════════ */
app.get('/api/v1/stream/:token', streamLimiter, async (req, res) => {
  try {
    const { token } = req.params;

    /* Verify the JWT stream token */
    let decoded;
    try {
      decoded = jwt.verify(token, STREAM_SECRET);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({ error: 'Stream token expired. Please refresh the page.' });
      }
      return res.status(403).json({ error: 'Invalid stream token' });
    }

    const isVideo = decoded.media === 'video';
    const id = isVideo ? decoded.videoId : decoded.audioId;
    const table = isVideo ? 'videos' : 'audio_tracks';

    /* Look up the media record */
    const { data: v } = await supabase.from(table).select('*').eq('id', id).single();
    if (!v) return res.status(404).json({ error: 'Media not found' });

    /* Count view (dedup by token so same token = 1 view) */
    const vk = 'v_' + token;
    if (!viewedTokens.has(vk)) {
      viewedTokens.add(vk);
      supabase.from(table).update({ views: (v.views || 0) + 1 }).eq('id', id).then(() => {}).catch(() => {});
    }

    /* Resolve the actual URL */
    let realUrl = resolveUrl(v.url, decoded.type);
    if (!realUrl) return res.status(404).json({ error: 'No source URL' });

    /* REDIRECT to the actual media URL
       - Browser video/audio elements follow 302 redirects natively
       - HLS.js follows redirects for m3u8 manifests
       - The actual URL is only revealed after valid token verification
       - Tokens expire in 5 minutes, preventing permanent hotlinking
    */
    res.redirect(302, realUrl);

  } catch (err) {
    console.error('Stream error:', err.message);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Stream failed' });
    }
  }
});

/* ═══════════════════════════════════════
   PUBLIC ROUTES
   ═══════════════════════════════════════ */
app.get('/api/v1/videos', async (req, res) => {
  try {
    var q = supabase.from('videos').select('id, title, description, thumbnail, video_type, category_id, is_featured, duration, order_index, views, created_at').eq('is_published', true).order('order_index');
    if (req.query.category_id) q = q.eq('category_id', req.query.category_id);
    var { data } = await q; res.json(data || []);
  } catch { res.json([]); }
});

app.get('/api/v1/categories', async (req, res) => {
  try { var { data } = await supabase.from('categories').select('*').eq('is_active', true).order('order_index'); res.json(data || []); } catch { res.json([]); }
});

app.get('/api/v1/posts', async (req, res) => {
  try { var { data } = await supabase.from('posts').select('*').eq('is_published', true).order('created_at', { ascending: false }); res.json(data || []); } catch { res.json([]); }
});

app.post('/api/v1/posts/:id/view', async (req, res) => {
  try { var { data: p } = await supabase.from('posts').select('views').eq('id', req.params.id).single(); if (!p) return res.status(404); await supabase.from('posts').update({ views: (p.views || 0) + 1 }).eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); }
});

app.get('/api/v1/audio', async (req, res) => {
  try { var { data } = await supabase.from('audio_tracks').select('*').eq('is_published', true).order('created_at', { ascending: false }); res.json(data || []); } catch { res.json([]); }
});

app.get('/api/v1/settings', async (req, res) => {
  try { var { data } = await supabase.from('settings').select('*'); var s = {}; (data || []).forEach(i => s[i.key] = i.value); res.json(s); } catch { res.json({}); }
});

app.post('/api/v1/contacts', contactLimiter, async (req, res) => {
  try {
    var { alias_name, contact_method, message_type, message } = req.body;
    if (!alias_name || !message) return res.status(400).json({ error: 'Missing fields' });
    var { data, error } = await supabase.from('contacts').insert({ alias_name, contact_method: contact_method || '', message_type, message }).select().single();
    if (error) throw error;
    res.json({ success: true, id: data.id });
  } catch { res.status(500).json({ error: 'Failed' }); }
});

/* ═══════════════════════════════════════
   ADMIN ROUTES
   ═══════════════════════════════════════ */
app.get('/api/v1/admin/videos', auth, async (req, res) => {
  try { var { data } = await supabase.from('videos').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch { res.json([]); }
});
app.post('/api/v1/admin/videos', auth, async (req, res) => {
  try {
    var d = req.body; if (!d.title || !d.url) return res.status(400).json({ error: 'Title and URL required' });
    var { data, error } = await supabase.from('videos').insert({
      title: d.title, description: d.description || '', url: d.url, video_type: d.video_type || 'mp4',
      thumbnail: d.thumbnail || '', category_id: d.category_id || null, is_featured: d.is_featured || false,
      is_published: d.is_published !== false, duration: d.duration || '0:00', order_index: d.order_index || 0
    }).select().single();
    if (error) throw error; res.json(data);
  } catch (e) { res.status(500).json({ error: e.message || 'Failed' }); }
});
app.put('/api/v1/admin/videos/:id', auth, async (req, res) => {
  try { var { data, error } = await supabase.from('videos').update(req.body).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
});
app.delete('/api/v1/admin/videos/:id', auth, async (req, res) => {
  try { await supabase.from('videos').delete().eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); }
});

app.get('/api/v1/admin/categories', auth, async (req, res) => {
  try { var { data } = await supabase.from('categories').select('*').order('order_index'); res.json(data || []); } catch { res.json([]); }
});
app.post('/api/v1/admin/categories', auth, async (req, res) => {
  try { var d = req.body; if (!d.name) return res.status(400); var { data, error } = await supabase.from('categories').insert({ name: d.name, description: d.description || '', icon: d.icon || 'fa-folder', order_index: d.order_index || 0 }).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
});
app.put('/api/v1/admin/categories/:id', auth, async (req, res) => {
  try { var { data, error } = await supabase.from('categories').update(req.body).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
});
app.delete('/api/v1/admin/categories/:id', auth, async (req, res) => {
  try { await supabase.from('categories').delete().eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); }
});

app.get('/api/v1/admin/posts', auth, async (req, res) => {
  try { var { data } = await supabase.from('posts').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch { res.json([]); }
});
app.post('/api/v1/admin/posts', auth, async (req, res) => {
  try { var d = req.body; if (!d.title || !d.content) return res.status(400); var { data, error } = await supabase.from('posts').insert({ title: d.title, content: d.content, author: d.author || 'Maxaas.u', image_url: d.image_url || '', is_published: d.is_published !== false }).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
});
app.put('/api/v1/admin/posts/:id', auth, async (req, res) => {
  try { var { data, error } = await supabase.from('posts').update(req.body).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
});
app.delete('/api/v1/admin/posts/:id', auth, async (req, res) => {
  try { await supabase.from('posts').delete().eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); }
});

app.get('/api/v1/admin/audio', auth, async (req, res) => {
  try { var { data } = await supabase.from('audio_tracks').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch { res.json([]); }
});
app.post('/api/v1/admin/audio', auth, async (req, res) => {
  try { var d = req.body; if (!d.title || !d.url) return res.status(400); var { data, error } = await supabase.from('audio_tracks').insert({ title: d.title, artist: d.artist || 'Unknown', url: d.url, audio_type: d.audio_type || 'mp3', cover_url: d.cover_url || '', duration: d.duration || '0:00', category: d.category || 'General', website_url: d.website_url || '', is_published: d.is_published !== false }).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
});
app.put('/api/v1/admin/audio/:id', auth, async (req, res) => {
  try { var d = req.body; if (d.website_url === undefined) d.website_url = ''; var { data, error } = await supabase.from('audio_tracks').update(d).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
});
app.delete('/api/v1/admin/audio/:id', auth, async (req, res) => {
  try { await supabase.from('audio_tracks').delete().eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); }
});

app.get('/api/v1/admin/contacts', auth, async (req, res) => {
  try { var { data } = await supabase.from('contacts').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch { res.json([]); }
});
app.put('/api/v1/admin/contacts/:id', auth, async (req, res) => {
  try { var u = {}; if (req.body.is_read !== undefined) u.is_read = req.body.is_read; if (req.body.admin_response !== undefined) u.admin_response = req.body.admin_response; var { data, error } = await supabase.from('contacts').update(u).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
});
app.delete('/api/v1/admin/contacts/:id', auth, async (req, res) => {
  try { await supabase.from('contacts').delete().eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); }
});

app.put('/api/v1/admin/settings', auth, async (req, res) => {
  try { for (var [k, v] of Object.entries(req.body)) { await supabase.from('settings').upsert({ key: k, value: typeof v === 'object' ? JSON.stringify(v) : String(v), updated_at: new Date().toISOString() }); } res.json({ success: true }); } catch { res.status(500); }
});

app.put('/api/v1/admin/credentials', auth, async (req, res) => {
  try {
    var { pin, new_username, new_password, new_pin } = req.body;
    if (!pin) return res.status(400).json({ error: 'Current PIN required' });
    var { data: admin } = await supabase.from('admin_users').select('*').eq('id', req.admin.id).single();
    if (!admin || admin.pin !== pin) return res.status(401).json({ error: 'Invalid PIN' });
    var u = {};
    if (new_username) u.username = new_username;
    if (new_password) u.password_hash = await bcrypt.hash(new_password, 12);
    if (new_pin) { if (new_pin.length !== 8) return res.status(400).json({ error: 'PIN must be 8 digits' }); u.pin = new_pin; }
    if (!Object.keys(u).length) return res.status(400).json({ error: 'No changes' });
    await supabase.from('admin_users').update(u).eq('id', req.admin.id);
    const newToken = jwt.sign({ id: req.admin.id, username: new_username || req.admin.username }, ADMIN_JWT_SECRET, { expiresIn: '24h' });
    res.cookie('token', newToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 }).json({ success: true });
  } catch { res.status(500); }
});

app.get('/api/v1/admin/analytics', auth, async (req, res) => {
  try {
    var { data: videos } = await supabase.from('videos').select('id,title,views,created_at').order('views', { ascending: false });
    var { data: contacts } = await supabase.from('contacts').select('id,is_read,created_at');
    var totalViews = 0; for (var v of (videos || [])) totalViews += (v.views || 0);
    var unread = 0; for (var c of (contacts || [])) if (!c.is_read) unread++;
    var thisWeek = 0; var weekAgo = new Date(); weekAgo.setDate(weekAgo.getDate() - 7);
    for (var v2 of (videos || [])) { if (new Date(v2.created_at) >= weekAgo) thisWeek++; }
    res.json({ totalViews, topVideos: (videos || []).slice(0, 5), totalVideos: (videos || []).length, unread, thisWeek });
  } catch { res.json({ totalViews: 0, topVideos: [], totalVideos: 0, unread: 0, thisWeek: 0 }); }
});

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.listen(PORT, () => console.log('Maxaas.u Server on port ' + PORT));