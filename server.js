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

// ═══ SECRETS ═══
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || JWT_SECRET + '_admin';
const STREAM_SECRET = process.env.STREAM_SECRET || JWT_SECRET + '_stream'; // Secret for video tokens
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY; // SERVICE KEY BACKEND ONLY!
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://maxaas.u';

let supabase;
try {
  supabase = createClient(SUPABASE_URL || 'https://placeholder.supabase.co', SUPABASE_KEY || 'placeholder');
} catch (e) {
  supabase = null;
  console.error('Supabase client failed to initialize');
}

// ═══ IN-MEMORY STORE FOR ONE-TIME STREAM TOKENS ═══
const usedStreamTokens = new Set();
setInterval(() => usedStreamTokens.clear(), 120000); // Clear used tokens every 2 mins

// ═══ MIDDLEWARE ═══
app.use(helmet({ 
  contentSecurityPolicy: false, 
  crossOriginEmbedderPolicy: false,
  xFrameOptions: { action: 'deny' } // Prevent iframe embedding (Clickjacking)
}));
app.use(cors({ origin: FRONTEND_URL, credentials: true })); // LOCKED TO maxaas.u
app.use(express.json({ limit: '10mb' }));
app.use(cookieParser());

// ═══ RATE LIMITERS ═══
const globalLimiter = rateLimit({ windowMs: 60000, max: 300, trustProxy: true });
const authLimiter = rateLimit({ windowMs: 900000, max: 10, trustProxy: true }); // 10 login attempts per 15 mins
const streamLimiter = rateLimit({ windowMs: 60000, max: 30, trustProxy: true }); // 30 stream requests per min

app.use(globalLimiter);
app.use(express.static(path.join(__dirname, 'public')));

// ═══ AUTH MIDDLEWARE (HTTPONLY COOKIE) ═══
function auth(req, res, next) {
  const t = req.cookies?.token; 
  if (!t) return res.status(401).json({ error: 'Authentication required' });
  try {
    const decoded = jwt.verify(t, ADMIN_JWT_SECRET);
    // Session Fingerprinting (IP + User-Agent)
    const currentFingerprint = crypto.createHash('sha256').update(req.ip + req.headers['user-agent']).digest('hex');
    if (decoded.fp !== currentFingerprint) {
      res.clearCookie('token');
      return res.status(403).json({ error: 'Session changed. Re-login required.' });
    }
    req.admin = decoded;
    next();
  } catch {
    res.clearCookie('token');
    return res.status(403).json({ error: 'Invalid or expired session' });
  }
}

// ═══ HELPERS ═══
function resolveUrl(v) {
  let u = v.url || '';
  if (v.video_type === 'archive') {
    var m = u.match(/archive\.org\/details\/([^/?\s]+)/);
    if (m) u = 'https://archive.org/download/' + m[1] + '/' + m[1] + '.mp4';
  }
  if (v.video_type === 'ipfs' && u.startsWith('ipfs://')) {
    u = u.replace('ipfs://', 'https://gateway.pinata.cloud/ipfs/');
  }
  return u;
}

// ═══ SETUP DEFAULT ADMIN ═══
async function setupAdmin() {
  if (!supabase) return;
  try {
    var { data } = await supabase.from('admin_users').select('id').limit(1);
    if (!data?.length) {
      var h = await bcrypt.hash('Admin@2024', 12);
      await supabase.from('admin_users').insert({ username: 'admin', password_hash: h, pin: '12345678' });
      console.log('✅ Admin created: admin / Admin@2024 / PIN: 12345678');
    }
  } catch (e) { console.error('Admin setup error:', e.message); }
}
setupAdmin();

/* ══════════════════════════════════════
   AUTH ROUTES (HTTPONLY COOKIES ONLY)
   ══════════════════════════════════════ */
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
    if (error || !admin || !(await bcrypt.compare(password, admin.password_hash))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    if (!pin || pin.length !== 8 || admin.pin !== pin) {
      return res.status(401).json({ error: 'Invalid PIN' });
    }
    
    // Create Session Fingerprint (IP + User-Agent)
    const fingerprint = crypto.createHash('sha256').update(req.ip + req.headers['user-agent']).digest('hex');
    const token = jwt.sign({ id: admin.id, username: admin.username, fp: fingerprint }, ADMIN_JWT_SECRET, { expiresIn: '24h' });
    
    // SET HTTPONLY COOKIE
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

/* ══════════════════════════════════════
   SECURE VIDEO STREAMING PROXY
   ══════════════════════════════════════ */

// Step 1: Request a temporary stream token (Requires Admin Auth Cookie)
app.post('/api/v1/videos/request-stream/:videoId', auth, streamLimiter, async (req, res) => {
  try {
    const { videoId } = req.params;
    const { data: v } = await supabase.from('videos').select('*').eq('id', videoId).single();
    if (!v) return res.status(404).json({ error: 'Video not found' });

    // Generate 60-second Signed Stream Token bound to IP and User-Agent
    const streamToken = jwt.sign({
      videoId: v.id,
      ip: req.ip,
      ua: req.headers['user-agent'],
      type: v.video_type
    }, STREAM_SECRET, { expiresIn: '60s' }); // EXPIRES IN 60 SECONDS!

    res.json({ streamToken });
  } catch { res.status(500).json({ error: 'Failed to generate stream token' }); }
});

// Step 2: Stream the video using the token (No Auth Cookie needed so <video> tag can play it)
app.get('/api/v1/stream/:token', streamLimiter, async (req, res) => {
  try {
    const { token } = req.params;

    // One-Time Use Validation
    if (usedStreamTokens.has(token)) {
      return res.status(403).json({ error: 'Token already used or expired' });
    }
    usedStreamTokens.add(token);

    // Verify & Decode Token
    const decoded = jwt.verify(token, STREAM_SECRET);

    // Replay Attack & Fingerprint Validation
    if (decoded.ip !== req.ip || decoded.ua !== req.headers['user-agent']) {
      return res.status(403).json({ error: 'Invalid session fingerprint' });
    }

    const { videoId, type } = decoded;
    const { data: v } = await supabase.from('videos').select('*').eq('id', videoId).single();
    if (!v) return res.status(404).json({ error: 'Video not found' });

    // Increment View Count
    await supabase.from('videos').update({ views: (v.views || 0) + 1 }).eq('id', videoId);

    let realUrl = resolveUrl(v);

    // YouTube redirect (Proxy cannot proxy YouTube Iframes easily, redirect to nocookie)
    if (type === 'youtube') {
      const yid = v.url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/)?.[1];
      return res.redirect(`https://www.youtube-nocookie.com/embed/${yid}?autoplay=1`);
    }

    if (!realUrl) return res.status(404).json({ error: 'No source URL' });

    // Fetch the real video and Proxy the stream back to the frontend
    const response = await fetch(realUrl, {
      headers: { Range: req.headers.range || '' }
    });

    res.setHeader('Content-Type', response.headers.get('content-type') || 'video/mp4');
    if (response.headers.has('content-length')) res.setHeader('Content-Length', response.headers.get('content-length'));
    if (response.headers.has('content-range')) res.setHeader('Content-Range', response.headers.get('content-range'));
    if (response.status === 206) res.status(206);
    
    response.body.pipe(res);

  } catch (err) {
    console.error('Stream proxy error:', err);
    res.status(403).json({ error: 'Stream failed or token invalid' });
  }
});

/* ══════════════════════════════════════
   PUBLIC ROUTES (STRIP URL FIELDS!)
   ══════════════════════════════════════ */
app.get('/api/v1/videos', async (req, res) => {
  try {
    var q = supabase.from('videos').select('id, title, description, thumbnail, video_type, category_id, is_featured, duration, order_index, views, created_at').eq('is_published', true).order('order_index');
    if (req.query.category_id) q = q.eq('category_id', req.query.category_id);
    var { data } = await q;
    res.json(data || []);
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

app.post('/api/v1/audio/:id/view', async (req, res) => {
  try { var { data: a } = await supabase.from('audio_tracks').select('views').eq('id', req.params.id).single(); if (!a) return res.status(404); await supabase.from('audio_tracks').update({ views: (a.views || 0) + 1 }).eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); }
});

app.get('/api/v1/settings', async (req, res) => {
  try { var { data } = await supabase.from('settings').select('*'); var s = {}; (data || []).forEach(i => s[i.key] = i.value); res.json(s); } catch { res.json({}); }
});

app.post('/api/v1/contacts', async (req, res) => {
  try { var { alias_name, contact_method, message_type, message } = req.body; if (!alias_name || !message) return res.status(400); var { data, error } = await supabase.from('contacts').insert({ alias_name, contact_method: contact_method || '', message_type, message }).select().single(); if (error) throw error; res.json({ success: true, id: data.id }); } catch { res.status(500); }
});

/* ══════════════════════════════════════
   ADMIN ROUTES (PROTECTED BY HTTPONLY COOKIE)
   ══════════════════════════════════════ */
app.get('/api/v1/admin/videos', auth, async (req, res) => { try { var { data } = await supabase.from('videos').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch { res.json([]); } });
app.post('/api/v1/admin/videos', auth, async (req, res) => { try { var d = req.body; if (!d.title || !d.url) return res.status(400); var { data, error } = await supabase.from('videos').insert({ title: d.title, description: d.description || '', url: d.url, video_type: d.video_type || 'mp4', thumbnail: d.thumbnail || '', category_id: d.category_id || null, is_featured: d.is_featured || false, is_published: d.is_published !== false, duration: d.duration || '0:00', order_index: d.order_index || 0 }).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); } });
app.put('/api/v1/admin/videos/:id', auth, async (req, res) => { try { var { data, error } = await supabase.from('videos').update(req.body).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); } });
app.delete('/api/v1/admin/videos/:id', auth, async (req, res) => { try { await supabase.from('videos').delete().eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); } });

app.get('/api/v1/admin/categories', auth, async (req, res) => { try { var { data } = await supabase.from('categories').select('*').order('order_index'); res.json(data || []); } catch { res.json([]); } });
app.post('/api/v1/admin/categories', auth, async (req, res) => { try { var d = req.body; if (!d.name) return res.status(400); var { data, error } = await supabase.from('categories').insert({ name: d.name, description: d.description || '', icon: d.icon || 'fa-folder', order_index: d.order_index || 0 }).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); } });
app.put('/api/v1/admin/categories/:id', auth, async (req, res) => { try { var { data, error } = await supabase.from('categories').update(req.body).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); } });
app.delete('/api/v1/admin/categories/:id', auth, async (req, res) => { try { await supabase.from('categories').delete().eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); } });

app.get('/api/v1/admin/posts', auth, async (req, res) => { try { var { data } = await supabase.from('posts').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch { res.json([]); } });
app.post('/api/v1/admin/posts', auth, async (req, res) => { try { var d = req.body; if (!d.title || !d.content) return res.status(400); var { data, error } = await supabase.from('posts').insert({ title: d.title, content: d.content, author: d.author || 'Maxaas.u', image_url: d.image_url || '', is_published: d.is_published !== false }).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); } });
app.put('/api/v1/admin/posts/:id', auth, async (req, res) => { try { var { data, error } = await supabase.from('posts').update(req.body).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); } });
app.delete('/api/v1/admin/posts/:id', auth, async (req, res) => { try { await supabase.from('posts').delete().eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); } });

app.get('/api/v1/admin/audio', auth, async (req, res) => { try { var { data } = await supabase.from('audio_tracks').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch { res.json([]); } });
app.post('/api/v1/admin/audio', auth, async (req, res) => { try { var d = req.body; if (!d.title || !d.url) return res.status(400); var { data, error } = await supabase.from('audio_tracks').insert({ title: d.title, artist: d.artist || 'Unknown', url: d.url, cover_url: d.cover_url || '', duration: d.duration || '0:00', category: d.category || 'General', website_url: d.website_url || '', is_published: d.is_published !== false }).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); } });
app.put('/api/v1/admin/audio/:id', auth, async (req, res) => { try { var d = req.body; if (d.website_url === undefined) d.website_url = ''; var { data, error } = await supabase.from('audio_tracks').update(d).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); } });
app.delete('/api/v1/admin/audio/:id', auth, async (req, res) => { try { await supabase.from('audio_tracks').delete().eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); } });

app.get('/api/v1/admin/contacts', auth, async (req, res) => { try { var { data } = await supabase.from('contacts').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch { res.json([]); } });
app.put('/api/v1/admin/contacts/:id', auth, async (req, res) => { try { var u = {}; if (req.body.is_read !== undefined) u.is_read = req.body.is_read; if (req.body.admin_response !== undefined) u.admin_response = req.body.admin_response; var { data, error } = await supabase.from('contacts').update(u).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); } });
app.delete('/api/v1/admin/contacts/:id', auth, async (req, res) => { try { await supabase.from('contacts').delete().eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); } });

app.put('/api/v1/admin/settings', auth, async (req, res) => { try { for (var [k, v] of Object.entries(req.body)) { await supabase.from('settings').upsert({ key: k, value: v, updated_at: new Date().toISOString() }); } res.json({ success: true }); } catch { res.status(500); } });

app.put('/api/v1/admin/credentials', auth, async (req, res) => {
  try {
    var { pin, new_username, new_password, new_pin } = req.body; if (!pin) return res.status(400);
    var { data: admin } = await supabase.from('admin_users').select('*').eq('id', req.admin.id).single();
    if (!admin || admin.pin !== pin) return res.status(401).json({ error: 'Invalid PIN' });
    var u = {}; if (new_username) u.username = new_username; if (new_password) u.password_hash = await bcrypt.hash(new_password, 12);
    if (new_pin) { if (new_pin.length !== 8) return res.status(400); u.pin = new_pin; }
    if (!Object.keys(u).length) return res.status(400);
    await supabase.from('admin_users').update(u).eq('id', req.admin.id);
    
    const fingerprint = crypto.createHash('sha256').update(req.ip + req.headers['user-agent']).digest('hex');
    const newToken = jwt.sign({ id: req.admin.id, username: new_username || req.admin.username, fp: fingerprint }, ADMIN_JWT_SECRET, { expiresIn: '24h' });
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
app.listen(PORT, () => console.log(`🚀 Maxaas.u Enterprise Security Server running on port ${PORT}`));