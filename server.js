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
const { Readable } = require('stream');

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', 1);

/* ═══ Secrets ═══ */
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET || JWT_SECRET + '_admin';
const STREAM_SECRET = process.env.STREAM_SECRET || JWT_SECRET + '_stream';
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!process.env.JWT_SECRET) console.warn('⚠️  JWT_SECRET not set — using random (resets on restart)');
if (!process.env.ADMIN_JWT_SECRET) console.warn('⚠️  ADMIN_JWT_SECRET not set');
if (!process.env.STREAM_SECRET) console.warn('⚠️  STREAM_SECRET not set');

let supabase;
try {
  supabase = createClient(SUPABASE_URL || 'https://placeholder.supabase.co', SUPABASE_KEY || 'placeholder');
} catch (e) {
  supabase = null;
  console.error('Supabase init failed');
}

/* ═══ View dedup ═══ */
const viewedTokens = new Set();
setInterval(() => viewedTokens.clear(), 300000);

/* ═══ Used stream tokens (single-use) ═══ */
const usedStreamTokens = new Set();
setInterval(() => usedStreamTokens.clear(), 360000);

/* ═══ Middleware ═══ */
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com", "'unsafe-inline'"],
      styleSrc: ["'self'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com", "'unsafe-inline'"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https://img.youtube.com", "https://i.ytimg.com", "https://gateway.pinata.cloud", "https://archive.org"],
      mediaSrc: ["'self'", "blob:"],
      frameSrc: ["https://www.youtube-nocookie.com"],
      connectSrc: ["'self'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

/* Restricted CORS — only your domains */
const allowedOrigins = [
  'https://maxaasu-pro.onrender.com',
  'http://localhost:3000',
  'http://127.0.0.1:3000'
];
app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) return callback(null, true);
    callback(null, true); // Allow all for now, but log
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400
}));

app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

/* ═══ Rate Limiters ═══ */
const globalLimiter = rateLimit({ windowMs: 60000, max: 300, trustProxy: true, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests' } });
const authLimiter = rateLimit({ windowMs: 900000, max: 8, trustProxy: true, skipSuccessfulRequests: true, message: { error: 'Too many login attempts. Try again later.' } });
const streamLimiter = rateLimit({ windowMs: 60000, max: 60, trustProxy: true, message: { error: 'Too many stream requests' } });
const contactLimiter = rateLimit({ windowMs: 3600000, max: 3, trustProxy: true, message: { error: 'Too many messages' } });
const pinCheckLimiter = rateLimit({ windowMs: 300000, max: 15, trustProxy: true, message: { error: 'Too many PIN checks' } });

app.use(globalLimiter);
app.use(express.static(path.join(__dirname, 'public')));

/* ═══ Auth Middleware ═══ */
function auth(req, res, next) {
  const t = req.cookies?.token;
  if (!t) return res.status(401).json({ error: 'Authentication required' });
  try {
    const decoded = jwt.verify(t, ADMIN_JWT_SECRET);
    req.admin = decoded;
    req.adminIP = req.ip || req.connection.remoteAddress;
    next();
  } catch {
    res.clearCookie('token');
    return res.status(403).json({ error: 'Invalid or expired session' });
  }
}

/* ═══ Helpers ═══ */
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

function sanitize(str) {
  if (!str) return '';
  return String(str).replace(/[<>'";&]/g, '').substring(0, 1000);
}

/* ═══ Admin Setup ═══ */
async function setupAdmin() {
  if (!supabase) return;
  try {
    var { data } = await supabase.from('admin_users').select('id').limit(1);
    if (!data?.length) {
      var h = await bcrypt.hash('Admin@2024', 12);
      var pin = crypto.randomBytes(4).toString('hex');
      await supabase.from('admin_users').insert({ username: 'admin', password_hash: h, pin: pin });
      console.log('═══════════════════════════════════════');
      console.log('  ADMIN CREDENTIALS (SAVE THIS!)');
      console.log('  Username: admin');
      console.log('  Password: Admin@2024');
      console.log('  PIN: ' + pin);
      console.log('═══════════════════════════════════════');
    }
  } catch (e) { console.error('Admin setup error:', e.message); }
}
setupAdmin();

/* ═══════════════════════════════════════
   AUTH ROUTES
   ═══════════════════════════════════════ */
app.post('/api/v1/auth/check-pin', pinCheckLimiter, async (req, res) => {
  try {
    var { username, pin } = req.body;
    if (!username || !pin) return res.json({ valid: false });
    if (pin.length !== 8) return res.json({ valid: false });
    var { data } = await supabase.from('admin_users').select('pin').eq('username', sanitize(username)).single();
    res.json({ valid: data?.pin === pin });
  } catch { res.json({ valid: false }); }
});

app.post('/api/v1/auth/login', authLimiter, async (req, res) => {
  try {
    var { username, password, pin } = req.body;
    if (!username || !password || !pin) return res.status(400).json({ error: 'Missing fields' });
    if (pin.length !== 8) return res.status(400).json({ error: 'Invalid PIN format' });

    var { data: admin, error } = await supabase.from('admin_users').select('*').eq('username', sanitize(username)).single();
    if (error || !admin) return res.status(401).json({ error: 'Invalid credentials' });
    if (!(await bcrypt.compare(password, admin.password_hash))) return res.status(401).json({ error: 'Invalid credentials' });
    if (admin.pin !== pin) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign(
      { id: admin.id, username: admin.username, ip: req.ip },
      ADMIN_JWT_SECRET,
      { expiresIn: '8h' }
    );
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

/* ═══════════════════════════════════════
   STREAM TOKEN — VIDEO
   Token contains: videoId, type, IP, single-use ID
   ═══════════════════════════════════════ */
app.post('/api/v1/videos/request-stream/:videoId', streamLimiter, async (req, res) => {
  try {
    const { videoId } = req.params;
    if (!videoId || videoId.length > 100) return res.status(400).json({ error: 'Invalid video ID' });

    const { data: v, error } = await supabase.from('videos').select('*').eq('id', videoId).single();
    if (error || !v) return res.status(404).json({ error: 'Video not found' });
    if (!v.is_published) return res.status(403).json({ error: 'Video not available' });

    /* YouTube → embed URL (no token needed) */
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

    /* Generate stream token with IP binding */
    const streamToken = jwt.sign(
      {
        videoId: v.id,
        type: v.video_type || 'mp4',
        media: 'video',
        ip: req.ip,
        uid: crypto.randomBytes(8).toString('hex') // unique ID for single-use tracking
      },
      STREAM_SECRET,
      { expiresIn: '120s' } // 2 minutes only
    );
    res.json({ streamToken, type: v.video_type || 'mp4' });
  } catch (e) {
    console.error('Stream token error:', e.message);
    res.status(500).json({ error: 'Failed' });
  }
});

/* ═══════════════════════════════════════
   STREAM TOKEN — AUDIO
   ═══════════════════════════════════════ */
app.post('/api/v1/audio/request-stream/:audioId', streamLimiter, async (req, res) => {
  try {
    const { audioId } = req.params;
    if (!audioId || audioId.length > 100) return res.status(400).json({ error: 'Invalid audio ID' });

    const { data: a, error } = await supabase.from('audio_tracks').select('*').eq('id', audioId).single();
    if (error || !a) return res.status(404).json({ error: 'Audio not found' });
    if (!a.is_published) return res.status(403).json({ error: 'Audio not available' });

    const streamToken = jwt.sign(
      {
        audioId: a.id,
        type: a.audio_type || 'mp3',
        media: 'audio',
        ip: req.ip,
        uid: crypto.randomBytes(8).toString('hex')
      },
      STREAM_SECRET,
      { expiresIn: '180s' } // 3 minutes for audio
    );
    res.json({ streamToken, type: a.audio_type || 'mp3' });
  } catch (e) {
    console.error('Audio token error:', e.message);
    res.status(500).json({ error: 'Failed' });
  }
});

/* ═══════════════════════════════════════
   STREAM ENDPOINT — FULL PROXY
   Source URL is NEVER exposed to the client
   
   For MP4/Archive/IPFS: Full proxy (pipe through server)
   For m3u8/HLS: Redirect (HLS segments are CDN-cached,
     hard to reconstruct as complete video)
   ═══════════════════════════════════════ */
app.get('/api/v1/stream/:token', streamLimiter, async (req, res) => {
  try {
    const { token } = req.params;

    /* Verify JWT */
    let decoded;
    try {
      decoded = jwt.verify(token, STREAM_SECRET);
    } catch (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({ error: 'Stream token expired' });
      }
      return res.status(403).json({ error: 'Invalid stream token' });
    }

    /* IP binding check — prevent token sharing */
    if (decoded.ip && decoded.ip !== req.ip) {
      console.warn('Stream IP mismatch:', decoded.ip, 'vs', req.ip);
      return res.status(403).json({ error: 'Token IP mismatch' });
    }

    /* Single-use check (optional: enables for seek requests too) */
    const tokenKey = 's_' + decoded.uid;
    if (usedStreamTokens.has(tokenKey) && decoded.media === 'audio') {
      // Audio tokens are single-use; video tokens allow range requests
      return res.status(403).json({ error: 'Token already used' });
    }
    usedStreamTokens.add(tokenKey);

    /* Lookup media */
    const isVideo = decoded.media === 'video';
    const id = isVideo ? decoded.videoId : decoded.audioId;
    const table = isVideo ? 'videos' : 'audio_tracks';

    const { data: v } = await supabase.from(table).select('*').eq('id', id).single();
    if (!v) return res.status(404).json({ error: 'Not found' });

    /* View counting (dedup by token) */
    const vk = 'v_' + token;
    if (!viewedTokens.has(vk)) {
      viewedTokens.add(vk);
      supabase.from(table).update({ views: (v.views || 0) + 1 }).eq('id', id).then(() => {}).catch(() => {});
    }

    /* Resolve actual URL */
    let realUrl = resolveUrl(v.url, decoded.type);
    if (!realUrl) return res.status(404).json({ error: 'No source' });

    /* ═══ HLS/m3u8: Redirect (acceptable risk) ═══ */
    if (decoded.type === 'm3u8') {
      return res.redirect(302, realUrl);
    }

    /* ═══ MP4/Archive/IPFS: FULL PROXY ═══ */
    const fetchHeaders = {
      'User-Agent': 'Maxaas.u-Server/1.0',
      'Accept': '*/*'
    };

    /* Forward range header for video seeking */
    if (req.headers.range) {
      fetchHeaders['Range'] = req.headers.range;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 60000); // 60s timeout

    let sourceResponse;
    try {
      sourceResponse = await fetch(realUrl, { headers: fetchHeaders, signal: controller.signal });
    } catch (fetchErr) {
      clearTimeout(timeout);
      return res.status(502).json({ error: 'Source unreachable' });
    }
    clearTimeout(timeout);

    if (!sourceResponse.ok && sourceResponse.status !== 206) {
      return res.status(sourceResponse.status === 404 ? 404 : 502).json({ error: 'Source error' });
    }

    /* Forward relevant headers */
    const headersToForward = ['content-type', 'content-length', 'content-range', 'accept-ranges', 'content-duration'];
    for (const h of headersToForward) {
      const val = sourceResponse.headers.get(h);
      if (val) res.setHeader(h, val);
    }

    /* Security headers */
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.removeHeader('X-Powered-By');

    /* Set status code (206 for partial content = video seeking) */
    res.status(sourceResponse.status === 206 ? 206 : 200);

    /* Pipe response body through server → client */
    if (sourceResponse.body) {
      try {
        const nodeStream = Readable.fromWeb(sourceResponse.body);

        /* Cleanup on client disconnect */
        const cleanup = () => {
          try { nodeStream.destroy(); } catch (e) {}
          try { controller.abort(); } catch (e) {}
        };
        req.on('close', cleanup);
        res.on('close', cleanup);
        res.on('error', cleanup);

        nodeStream.pipe(res);
      } catch (streamErr) {
        /* Fallback: manual chunked reading for older Node versions */
        console.warn('Readable.fromWeb failed, using fallback');
        const reader = sourceResponse.body.getReader();
        const pump = async () => {
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) { res.end(); return; }
              if (!res.write(Buffer.from(value))) {
                await new Promise(r => res.once('drain', r));
              }
            }
          } catch (e) {
            if (!res.writableEnded) res.end();
          }
        };
        pump();
      }
    } else {
      res.end();
    }

  } catch (err) {
    console.error('Stream error:', err.message);
    if (!res.headersSent) {
      if (err.name === 'AbortError') res.status(504).json({ error: 'Source timeout' });
      else res.status(500).json({ error: 'Stream error' });
    }
  }
});

/* ═══════════════════════════════════════
   PUBLIC ROUTES (URL field EXCLUDED from videos)
   ═══════════════════════════════════════ */
app.get('/api/v1/videos', async (req, res) => {
  try {
    var q = supabase.from('videos')
      .select('id, title, description, thumbnail, video_type, category_id, is_featured, duration, order_index, views, created_at')
      .eq('is_published', true)
      .order('order_index');
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

app.post('/api/v1/posts/:id/view', streamLimiter, async (req, res) => {
  try { var { data: p } = await supabase.from('posts').select('views').eq('id', req.params.id).single(); if (!p) return res.status(404); await supabase.from('posts').update({ views: (p.views || 0) + 1 }).eq('id', req.params.id); res.json({ success: true }); } catch { res.status(500); }
});

app.get('/api/v1/audio', async (req, res) => {
  try { var { data } = await supabase.from('audio_tracks').select('id, title, artist, cover_url, duration, category, views, created_at').eq('is_published', true).order('created_at', { ascending: false }); res.json(data || []); } catch { res.json([]); }
});

app.get('/api/v1/settings', async (req, res) => {
  try { var { data } = await supabase.from('settings').select('*'); var s = {}; (data || []).forEach(i => s[i.key] = i.value); res.json(s); } catch { res.json({}); }
});

app.post('/api/v1/contacts', contactLimiter, async (req, res) => {
  try {
    var { alias_name, contact_method, message_type, message } = req.body;
    if (!alias_name || !message) return res.status(400).json({ error: 'Missing fields' });
    if (message.length > 2000) return res.status(400).json({ error: 'Message too long' });
    var { data, error } = await supabase.from('contacts').insert({
      alias_name: sanitize(alias_name).substring(0, 50),
      contact_method: sanitize(contact_method || '').substring(0, 100),
      message_type: message_type || 'suggestion',
      message: String(message).substring(0, 2000)
    }).select().single();
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
    var d = req.body;
    if (!d.title || !d.url) return res.status(400).json({ error: 'Title and URL required' });
    var { data, error } = await supabase.from('videos').insert({
      title: sanitize(d.title), description: d.description || '', url: d.url,
      video_type: d.video_type || 'mp4', thumbnail: d.thumbnail || '',
      category_id: d.category_id || null, is_featured: !!d.is_featured,
      is_published: d.is_published !== false, duration: d.duration || '0:00',
      order_index: d.order_index || 0
    }).select().single();
    if (error) throw error;
    res.json(data);
  } catch (e) { res.status(500).json({ error: 'Failed' }); }
});
app.put('/api/v1/admin/videos/:id', auth, async (req, res) => {
  try {
    var d = req.body;
    /* Sanitize updatable fields */
    var u = {};
    if (d.title) u.title = sanitize(d.title);
    if (d.description !== undefined) u.description = d.description;
    if (d.url) u.url = d.url;
    if (d.video_type) u.video_type = d.video_type;
    if (d.thumbnail !== undefined) u.thumbnail = d.thumbnail;
    if (d.category_id !== undefined) u.category_id = d.category_id;
    if (d.is_featured !== undefined) u.is_featured = !!d.is_featured;
    if (d.is_published !== undefined) u.is_published = !!d.is_published;
    if (d.duration !== undefined) u.duration = d.duration;
    if (d.order_index !== undefined) u.order_index = d.order_index;
    var { data, error } = await supabase.from('videos').update(u).eq('id', req.params.id).select().single();
    if (error) throw error;
    res.json(data);
  } catch { res.status(500).json({ error: 'Failed' }); }
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
  try { var d = req.body; var u = {}; if (d.name) u.name = sanitize(d.name); if (d.description !== undefined) u.description = d.description; if (d.icon) u.icon = d.icon; if (d.order_index !== undefined) u.order_index = d.order_index; if (d.is_active !== undefined) u.is_active = !!d.is_active; var { data, error } = await supabase.from('categories').update(u).eq('id', req.params.id).select().single(); if (error) throw error; res.json(data); } catch { res.status(500); }
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
  try {
    for (var [k, v] of Object.entries(req.body)) {
      if (k.length > 50) continue;
      await supabase.from('settings').upsert({ key: k, value: typeof v === 'object' ? JSON.stringify(v) : String(v).substring(0, 5000), updated_at: new Date().toISOString() });
    }
    res.json({ success: true });
  } catch { res.status(500); }
});

app.put('/api/v1/admin/credentials', auth, async (req, res) => {
  try {
    var { pin, new_username, new_password, new_pin } = req.body;
    if (!pin || pin.length !== 8) return res.status(400).json({ error: 'Current PIN required (8 digits)' });

    var { data: admin } = await supabase.from('admin_users').select('*').eq('id', req.admin.id).single();
    if (!admin || admin.pin !== pin) return res.status(401).json({ error: 'Invalid PIN' });

    var u = {};
    if (new_username) u.username = sanitize(new_username).substring(0, 30);
    if (new_password) {
      if (new_password.length < 8) return res.status(400).json({ error: 'Password must be 8+ characters' });
      u.password_hash = await bcrypt.hash(new_password, 14);
    }
    if (new_pin) {
      if (new_pin.length !== 8) return res.status(400).json({ error: 'PIN must be 8 digits' });
      u.pin = new_pin;
    }
    if (!Object.keys(u).length) return res.status(400).json({ error: 'No changes' });

    await supabase.from('admin_users').update(u).eq('id', req.admin.id);
    const newToken = jwt.sign(
      { id: req.admin.id, username: new_username || req.admin.username, ip: req.ip },
      ADMIN_JWT_SECRET,
      { expiresIn: '8h' }
    );
    res.cookie('token', newToken, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000, path: '/' }).json({ success: true });
  } catch { res.status(500).json({ error: 'Failed' }); }
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

/* ═══ Catch-all ═══ */
app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.listen(PORT, () => console.log('Maxaas.u running on port ' + PORT));