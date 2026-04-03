const express = require('express');
const multer  = require('multer');
const axios   = require('axios');
const cors    = require('cors');
const path    = require('path');
const fs      = require('fs');
require('dotenv').config();

const app = express();
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── uploads dir
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/\s/g,'_')}`)
});
const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('video/')) cb(null, true);
    else cb(new Error('Fichier vidéo requis'));
  }
});
app.use('/uploads', express.static(uploadDir));

// ── In-memory stores
let videos  = [];
let members = {}; // { login: { login, avatar_url, joinedAt, role } }

// ── Owner config
const OWNER = 'Tetedecitron';

function getRole(login) {
  if (login === OWNER) return 'owner';
  return members[login]?.role || 'member';
}

function registerMember(login, avatar_url) {
  if (!members[login]) {
    members[login] = { login, avatar_url, joinedAt: new Date().toISOString(), role: login === OWNER ? 'owner' : 'member' };
  } else {
    members[login].avatar_url = avatar_url;
    if (login === OWNER) members[login].role = 'owner';
  }
}

// ── GitHub OAuth
app.get('/auth/github/url', (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID,
    redirect_uri: `${process.env.BACKEND_URL || 'http://localhost:3000'}/auth/callback`,
    scope: 'user:email',
    state: Math.random().toString(36).slice(2)
  });
  res.json({ url: `https://github.com/login/oauth/authorize?${params}` });
});

app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).json({ error: 'Code manquant' });
  try {
    const tokenRes = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: `${process.env.BACKEND_URL || 'http://localhost:3000'}/auth/callback`
    }, { headers: { Accept: 'application/json' } });

    const { access_token } = tokenRes.data;
    if (!access_token) throw new Error('Token vide');

    const userRes = await axios.get('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${access_token}`, 'User-Agent': 'GDVault' }
    });

    const { login, avatar_url, name, id } = userRes.data;
    registerMember(login, avatar_url);

    const user = { login, avatar_url, name: name || login, id, role: getRole(login) };
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.redirect(`${frontendUrl}?user=${encodeURIComponent(JSON.stringify(user))}`);
  } catch (err) {
    console.error('OAuth error:', err.message);
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}?error=auth_failed`);
  }
});

// ── Videos
app.get('/api/videos', (req, res) => {
  res.json(videos.sort((a, b) => new Date(b.date) - new Date(a.date)));
});

app.post('/api/videos', upload.single('video'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Aucun fichier reçu' });
  const { title, difficulty, description, author, authorAvatar } = req.body;
  if (author) registerMember(author, authorAvatar);
  const video = {
    id: Date.now(),
    title: title || req.file.originalname,
    difficulty: difficulty || 'insane',
    description: description || '',
    author: author || 'Anonyme',
    authorAvatar: authorAvatar || '',
    authorRole: getRole(author || ''),
    filename: req.file.filename,
    url: `/uploads/${req.file.filename}`,
    size: req.file.size,
    date: new Date().toISOString(),
    views: 0
  };
  videos.unshift(video);
  res.json({ success: true, video });
});

app.delete('/api/videos/:id', (req, res) => {
  const idx = videos.findIndex(v => v.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Vidéo introuvable' });
  const [v] = videos.splice(idx, 1);
  const fp = path.join(uploadDir, v.filename);
  if (fs.existsSync(fp)) fs.unlinkSync(fp);
  res.json({ success: true });
});

// ── Members / user search
app.get('/api/members', (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  let list = Object.values(members);
  if (q) list = list.filter(m => m.login.toLowerCase().includes(q));
  // attach video count
  list = list.map(m => ({
    ...m,
    videoCount: videos.filter(v => v.author === m.login).length
  }));
  // owner first, then alphabetical
  list.sort((a, b) => {
    if (a.role === 'owner') return -1;
    if (b.role === 'owner') return 1;
    return a.login.localeCompare(b.login);
  });
  res.json(list);
});

// videos by user
app.get('/api/members/:login/videos', (req, res) => {
  const userVideos = videos.filter(v => v.author === req.params.login)
    .sort((a, b) => new Date(b.date) - new Date(a.date));
  res.json(userVideos);
});

// ── Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Erreur serveur' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🎮 GDVault — http://localhost:${PORT}\n`);
});
