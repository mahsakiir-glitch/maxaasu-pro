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
const httpsReq = require('https');
const httpReq = require('http');
const { URL } = require('url');

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
}

const viewedTokens = new Set();
setInterval(() => viewedTokens.clear(), 300000);

/* ═══ PRODUCTION GRADE SECURITY HEADERS ═══ */
app.use(helmet({
  contentSecurityPolicy: false, 
  crossOriginEmbedderPolicy: false,
  hsts: { maxAge: 31536000, includeSubDomains: true, preload: true }, // Force HTTPS
  referrerPolicy: { policy: 'no-referrer' } // Hide referrer to prevent URL leakage
}));

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

/* ═══ ADVANCED RATE LIMITING (Replaces express-brute) ═══ */
const globalLimiter = rateLimit({ windowMs: 60000, max: 300, trustProxy: true });
const authLimiter = rateLimit({ windowMs: 900000, max: 8, trustProxy: true, skipSuccessfulRequests: true });
const streamLimiter = rateLimit({ windowMs: 60000, max: 80, trustProxy: true });
const contactLimiter = rateLimit({ windowMs: 3600000, max: 3, trustProxy: true });
const pinLimiter = rateLimit({ windowMs: 300000, max: 15, trustProxy: true });

// Strict brute-force protection for login
const loginBruteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per IP per 15 minutes
  trustProxy: true,
  skipSuccessfulRequests: true,
  message: { error: 'Too many login attempts. Please try again later.' }
});

app.use(globalLimiter);
app.use(express.static(path.join(__dirname, 'public')));

function auth(req, res, next) {
  const t = req.cookies?.token;
  if (!t) return res.status(401).json({ error: 'Authentication required' });
  try {
    req.admin = jwt.verify(t, ADMIN_JWT_SECRET);
    next();
  } catch {
    res.clearCookie('token');
    return res.status(403).json({ error: 'Invalid session' });
  }
}

function resolveUrl(url, type) {
  let u = url || '';
  if (type === 'archive') {
    var m = u.match(/archive\.org\/details\/([^/?\s]+)/);
    if (m) u = 'https://archive.org/download/' + m[1] + '/' + m[1] + '.mp4';
  }
  if (type === 'ipfs' && u.startsWith('ipfs://')) u = u.replace('ipfs://', 'https://gateway.pinata.cloud/ipfs/');
  return u;
}

function extractYoutubeId(url) {
  if (!url) return null;
  var m = url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]{11})/);
  return m ? m[1] : null;
}

function sanitize(s) {
  if (!s) return '';
  return String(s).replace(/[<>'";&]/g, '').substring(0, 1000);
}

async function setupAdmin() {
  if (!supabase) return;
  try {
    var { data } = await supabase.from('admin_users').select('id').limit(1);
    if (!data?.length) {
      var h = await bcrypt.hash('Admin@2024', 14);
      var pin = crypto.randomBytes(4).toString('hex');
      await supabase.from('admin_users').insert({ username: 'admin', password_hash: h, pin: pin });
      console.log('Admin: admin / Admin@2024 / PIN: ' + pin);
    }
  } catch (e) {
    console.error('Admin setup:', e.message);
  }
}
setupAdmin();

/* ═══ STREAM PROXY FUNCTION ═══ */
function proxyUrl(urlStr, req, res, maxRedirects) {
  if (maxRedirects === undefined) maxRedirects = 8;
  return new Promise((resolve, reject) => {
    if (maxRedirects <= 0) return reject(new Error('Too many redirects'));

    let parsedUrl;
    try {
      parsedUrl = new URL(urlStr);
    } catch (e) {
      return reject(new Error('Invalid URL: ' + urlStr));
    }

    const isHttps = parsedUrl.protocol === 'https:';
    const mod = isHttps ? httpsReq : httpReq;

    const requestHeaders = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
      'Accept': '*/*',
      'Accept-Encoding': 'identity',
      'Connection': 'close'
    };

    if (req.headers.range) {
      requestHeaders['Range'] = req.headers.range;
    }

    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'GET',
      headers: requestHeaders
    };

    const upstreamReq = mod.request(options, (upstreamRes) => {
      if (upstreamRes.statusCode >= 300 && upstreamRes.statusCode < 400 && upstreamRes.headers.location) {
        let location = upstreamRes.headers.location;
        if (location.startsWith('/')) {
          location = parsedUrl.protocol + '//' + parsedUrl.host + location;
        } else if (!location.startsWith('http')) {
          location = new URL(location, urlStr).href;
        }
        upstreamRes.resume();
        return proxyUrl(location, req, res, maxRedirects - 1).then(resolve).catch(reject);
      }

      if (upstreamRes.statusCode >= 400) {
        upstreamRes.resume();
        if (!res.headersSent) {
          res.status(upstreamRes.statusCode);
          res.json({ error: 'Upstream error: ' + upstreamRes.statusCode });
        }
        return resolve();
      }

      if (!res.headersSent) {
        res.status(upstreamRes.statusCode);

        const forwardHeaders = [
          'content-type', 'content-length', 'content-range',
          'accept-ranges', 'content-disposition', 'cache-control',
          'content-encoding', 'transfer-encoding', 'duration'
        ];

        forwardHeaders.forEach(h => {
          const val = upstreamRes.headers[h];
          if (val !== undefined) {
            res.setHeader(h, val);
          }
        });

        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Headers', 'Range');
        res.setHeader('Access-Control-Expose-Headers', 'Content-Range, Content-Length, Content-Disposition');
        
        // Prevent mime sniffing & strict streaming
        res.setHeader('X-Content-Type-Options', 'nosniff');
      }

      upstreamRes.pipe(res);
      upstreamRes.on('end', resolve);
      upstreamRes.on('error', (err) => {
        upstreamRes.unpipe(res);
        if (!res.headersSent) reject(err);
        else { res.end(); resolve(); }
      });
    });

    upstreamReq.on('error', (err) => {
      if (!res.headersSent) reject(err);
      else { res.end(); resolve(); }
    });

    upstreamReq.setTimeout(30000, () => {
      upstreamReq.destroy();
      if (!res.headersSent) reject(new Error('Upstream timeout'));
      else { res.end(); resolve(); }
    });

    upstreamReq.end();
  });
}

/* ═══ AUTH ROUTES ═══ */
app.post('/api/v1/auth/check-pin', pinLimiter, async (req, res) => {
  try {
    var { username, pin } = req.body;
    if (!username || !pin || pin.length !== 8) return res.json({ valid: false });
    var { data } = await supabase.from('admin_users').select('pin').eq('username', sanitize(username)).single();
    res.json({ valid: data?.pin === pin });
  } catch {
    res.json({ valid: false });
  }
});

app.post('/api/v1/auth/login', authLimiter, loginBruteLimiter, async (req, res) => {
  try {
    var { username, password, pin } = req.body;
    if (!username || !password || !pin) return res.status(400).json({ error: 'Missing fields' });
    var { data: admin, error } = await supabase.from('admin_users').select('*').eq('username', sanitize(username)).single();
    if (error || !admin || !(await bcrypt.compare(password, admin.password_hash))) return res.status(401).json({ error: 'Invalid credentials' });
    if (admin.pin !== pin) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: admin.id, username: admin.username, ip: req.ip }, ADMIN_JWT_SECRET, { expiresIn: '8h' });
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 8 * 60 * 60 * 1000,
      path: '/'
    }).json({ username: admin.username, success: true });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/v1/auth/logout', (req, res) => {
  res.clearCookie('token', { path: '/' }).json({ success: true });
});

/* ═══ STREAM TOKEN — VIDEO ═══ */
app.post('/api/v1/videos/request-stream/:videoId', streamLimiter, async (req, res) => {
  try {
    const { videoId } = req.params;
    if (!videoId || videoId.length > 100) return res.status(400).json({ error: 'Invalid ID' });
    const { data: v, error } = await supabase.from('videos').select('*').eq('id', videoId).single();
    if (error || !v) return res.status(404).json({ error: 'Not found' });
    if (!v.is_published) return res.status(403).json({ error: 'Unavailable' });

    const yid = extractYoutubeId(v.url);

    if (v.video_type === 'youtube' || yid) {
      if (yid) {
        return res.json({
          streamToken: null,
          youtubeUrl: 'https://www.youtube-nocookie.com/embed/' + yid + '?autoplay=1&rel=0&modestbranding=1&playsinline=1&iv_load_policy=3',
          type: 'youtube',
          youtubeId: yid
        });
      }
    }

    // Fingerprint binding: Hash IP + User-Agent
    const userFingerprint = crypto.createHash('sha256').update(req.ip + (req.headers['user-agent'] || '')).digest('hex');

    const streamToken = jwt.sign(
      { videoId: v.id, type: v.video_type || 'mp4', media: 'video', fp: userFingerprint, uid: crypto.randomBytes(6).toString('hex') },
      STREAM_SECRET,
      { expiresIn: '300s' }
    );
    res.json({ streamToken, type: v.video_type || 'mp4' });
  } catch (e) {
    res.status(500).json({ error: 'Failed' });
  }
});

/* ═══ STREAM TOKEN — AUDIO ═══ */
app.post('/api/v1/audio/request-stream/:audioId', streamLimiter, async (req, res) => {
  try {
    const { audioId } = req.params;
    if (!audioId || audioId.length > 100) return res.status(400).json({ error: 'Invalid ID' });
    const { data: a, error } = await supabase.from('audio_tracks').select('*').eq('id', audioId).single();
    if (error || !a) return res.status(404).json({ error: 'Not found' });
    if (!a.is_published) return res.status(403).json({ error: 'Unavailable' });

    const userFingerprint = crypto.createHash('sha256').update(req.ip + (req.headers['user-agent'] || '')).digest('hex');

    const streamToken = jwt.sign(
      { audioId: a.id, type: a.audio_type || 'mp3', media: 'audio', fp: userFingerprint, uid: crypto.randomBytes(6).toString('hex') },
      STREAM_SECRET,
      { expiresIn: '300s' }
    );
    res.json({ streamToken, type: a.audio_type || 'mp3' });
  } catch (e) {
    res.status(500).json({ error: 'Failed' });
  }
});

/* ═══ STREAM ENDPOINT — PROXY ═══ */
app.get('/api/v1/stream/:token', streamLimiter, async (req, res) => {
  try {
    const { token } = req.params;

    let decoded;
    try {
      decoded = jwt.verify(token, STREAM_SECRET);
    } catch (err) {
      return res.status(403).json({
        error: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token'
      });
    }

    // Validate Fingerprint
    const currentFingerprint = crypto.createHash('sha256').update(req.ip + (req.headers['user-agent'] || '')).digest('hex');
    if (decoded.fp !== currentFingerprint) {
      return res.status(403).json({ error: 'Session mismatch' });
    }

    const isVideo = decoded.media === 'video';
    const id = isVideo ? decoded.videoId : decoded.audioId;
    const table = isVideo ? 'videos' : 'audio_tracks';

    const { data: v } = await supabase.from(table).select('*').eq('id', id).single();
    if (!v) return res.status(404).json({ error: 'Not found' });

    const vk = 'v_' + token;
    if (!viewedTokens.has(vk)) {
      viewedTokens.add(vk);
      supabase.from(table).update({ views: (v.views || 0) + 1 }).eq('id', id).then(() => {}).catch(() => {});
    }

    let realUrl = resolveUrl(v.url, decoded.type);
    if (!realUrl) return res.status(404).json({ error: 'No source' });

    await proxyUrl(realUrl, req, res);

  } catch (err) {
    if (!res.headersSent) {
      res.status(500).json({ error: 'Stream error' });
    }
  }
});

/* ═══ PUBLIC ROUTES ═══ */
app.get('/api/v1/videos', async (req, res) => {
  try {
    var q = supabase.from('videos').select('id,title,description,thumbnail,video_type,category_id,is_featured,duration,order_index,views,created_at').eq('is_published', true).order('order_index');
    if (req.query.category_id) q = q.eq('category_id', req.query.category_id);
    var { data } = await q;
    res.json(data || []);
  } catch { res.json([]); }
});

app.get('/api/v1/categories', async (req, res) => {
  try {
    var { data } = await supabase.from('categories').select('*').eq('is_active', true).order('order_index');
    res.json(data || []);
  } catch { res.json([]); }
});

app.get('/api/v1/posts', async (req, res) => {
  try {
    var { data } = await supabase.from('posts').select('*').eq('is_published', true).order('created_at', { ascending: false });
    res.json(data || []);
  } catch { res.json([]); }
});

app.post('/api/v1/posts/:id/view', streamLimiter, async (req, res) => {
  try {
    var { data: p } = await supabase.from('posts').select('views').eq('id', req.params.id).single();
    if (!p) return res.status(404);
    await supabase.from('posts').update({ views: (p.views || 0) + 1 }).eq('id', req.params.id);
    res.json({ success: true });
  } catch { res.status(500); }
});

app.get('/api/v1/audio', async (req, res) => {
  try {
    var { data } = await supabase.from('audio_tracks').select('id,title,artist,cover_url,duration,category,views,created_at').eq('is_published', true).order('created_at', { ascending: false });
    res.json(data || []);
  } catch { res.json([]); }
});

app.get('/api/v1/settings', async (req, res) => {
  try {
    var { data } = await supabase.from('settings').select('*');
    var s = {};
    (data || []).forEach(i => s[i.key] = i.value);
    res.json(s);
  } catch { res.json({}); }
});

app.post('/api/v1/contacts', contactLimiter, async (req, res) => {
  try {
    var { alias_name, contact_method, message_type, message } = req.body;
    if (!alias_name || !message) return res.status(400);
    var { data, error } = await supabase.from('contacts').insert({
      alias_name: sanitize(alias_name).substring(0, 50),
      contact_method: sanitize(contact_method || '').substring(0, 100),
      message_type,
      message: String(message).substring(0, 2000)
    }).select().single();
    if (error) throw error;
    res.json({ success: true, id: data.id });
  } catch { res.status(500); }
});

/* ═══ ADMIN ROUTES ═══ */
app.get('/api/v1/admin/videos', auth, async (req, res) => {
  try { var { data } = await supabase.from('videos').select('*').order('created_at', { ascending: false }); res.json(data || []); } catch { res.json([]); }
});
app.post('/api/v1/admin/videos', auth, async (req, res) => {
  try { var d = req.body; if (!d.title || !d.url) return res.status(400); var { data, error } = await supabase.from('videos').insert({ title: sanitize(d.title), description: d.description || '', url: d.url, video_type: d.video_type || 'mp4', thumbnail: d.thumbnail || '', category_id: d.category_id || null, is_featured: !!d.is_featured, is_published: d.is_published !== false, duration: d.duration || '0:00', order_index: d.order_index || 0 }).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
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
  try { var d = req.body; if (!d.name) return res.status(400); var { data, error } = await supabase.from('categories').insert({ name: sanitize(d.name), description: d.description || '', icon: d.icon || 'fa-folder', order_index: d.order_index || 0 }).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
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
  try { var d = req.body; if (!d.title || !d.content) return res.status(400); var { data, error } = await supabase.from('posts').insert({ title: sanitize(d.title), content: d.content, author: sanitize(d.author || 'Maxaas.u'), image_url: d.image_url || '', is_published: d.is_published !== false }).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
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
  try { var d = req.body; if (!d.title || !d.url) return res.status(400); var { data, error } = await supabase.from('audio_tracks').insert({ title: sanitize(d.title), artist: sanitize(d.artist || 'Unknown'), url: d.url, audio_type: d.audio_type || 'mp3', cover_url: d.cover_url || '', duration: d.duration || '0:00', category: d.category || 'General', website_url: d.website_url || '', is_published: d.is_published !== false }).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
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
  try { var u = {}; if (req.body.is_read !== undefined) u.is_read = !!req.body.is_read; if (req.body.admin_response !== undefined) u.admin_response = req.body.admin_response; var { data, error } = await supabase.from('contacts').update(u).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
});
app.delete('/api/v1/admin/contacts/:id', auth, async (req, res) => {
  try { await supabase.from('contacts').delete().eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); }
});

app.put('/api/v1/admin/settings', auth, async (req, res) => {
  try { for (var [k, v] of Object.entries(req.body)) { if (k.length > 50) continue; await supabase.from('settings').upsert({ key: k, value: typeof v === 'object' ? JSON.stringify(v) : String(v).substring(0, 5000), updated_at: new Date().toISOString() }); } res.json({ success: true }); } catch { res.status(500); }
});

app.put('/api/v1/admin/credentials', auth, async (req, res) => {
  try {
    var { pin, new_username, new_password, new_pin } = req.body;
    if (!pin || pin.length !== 8) return res.status(400).json({ error: 'PIN required' });
    var { data: admin } = await supabase.from('admin_users').select('*').eq('id', req.admin.id).single();
    if (!admin || admin.pin !== pin) return res.status(401).json({ error: 'Invalid PIN' });

    var u = {};
    if (new_username) u.username = sanitize(new_username).substring(0, 30);
    if (new_password) {
      if (new_password.length < 8) return res.status(400).json({ error: 'Password 8+ chars' });
      u.password_hash = await bcrypt.hash(new_password, 14);
    }
    if (new_pin) {
      if (new_pin.length !== 8) return res.status(400).json({ error: 'PIN 8 digits' });
      u.pin = new_pin;
    }
    if (!Object.keys(u).length) return res.status(400).json({ error: 'No changes' });

    await supabase.from('admin_users').update(u).eq('id', req.admin.id);

    const newToken = jwt.sign(
      { id: req.admin.id, username: new_username || req.admin.username, ip: req.ip },
      ADMIN_JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.cookie('token', newToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 8 * 60 * 60 * 1000,
      path: '/'
    }).json({ success: true });
  } catch { res.status(500); }
});

app.get('/api/v1/admin/analytics', auth, async (req, res) => {
  try {
    var { data: videos } = await supabase.from('videos').select('id,title,views,created_at').order('views', { ascending: false });
    var { data: contacts } = await supabase.from('contacts').select('id,is_read,created_at');

    var totalViews = 0;
    for (var v of (videos || [])) totalViews += (v.views || 0);

    var unread = 0;
    for (var c of (contacts || [])) if (!c.is_read) unread++;

    var thisWeek = 0;
    var wAgo = new Date();
    wAgo.setDate(wAgo.getDate() - 7);
    for (var v2 of (videos || [])) if (new Date(v2.created_at) >= wAgo) thisWeek++;

    res.json({ totalViews, topVideos: (videos || []).slice(0, 5), totalVideos: (videos || []).length, unread, thisWeek });
  } catch { res.json({ totalViews: 0, topVideos: [], totalVideos: 0, unread: 0, thisWeek: 0 }); }
});

/* ═══ SPA Catch-all ═══ */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

/* ═══ Start Server ═══ */
app.listen(PORT, () => {
  console.log('═══════════════════════════════════════');
  console.log('  Maxaas.u Server Running');
  console.log('  Port: ' + PORT);
  console.log('  Mode: ' + (process.env.NODE_ENV || 'development'));
  console.log('  Stream: Secure Proxy + Fingerprint Binding');
  console.log('═══════════════════════════════════════');
});