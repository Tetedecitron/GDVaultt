// ── GDVault Backend — GitHub OAuth + Video Upload
// Run: npm install && node server.js

const express = require('express');
const multer = require('multer');
const axios = require('axios');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json());

// ── Serve frontend
app.use(express.static(path.join(__dirname, 'public')));

// ── Video storage
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: uploadDir,
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname.replace(/\s/g, '_')}`)
});
const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 }, // 500 MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('video/')) cb(null, true);
    else cb(new Error('Fichier vidéo requis'));
  }
});
app.use('/uploads', express.static(uploadDir));

// ── In-memory video DB (remplace par MongoDB/SQLite pour la prod)
let videos = [];

// ── GitHub OAuth ──────────────────────────────────────
// GET /auth/github/url → Retourne l'URL d'auth GitHub
app.get('/auth/github/url', (req, res) => {
  const params = new URLSearchParams({
    client_id: process.env.GITHUB_CLIENT_ID,
    redirect_uri: `${process.env.BACKEND_URL || 'http://localhost:3000'}/auth/callback`,
    scope: 'user:email',
    state: Math.random().toString(36).slice(2)
  });
  res.json({ url: `https://github.com/login/oauth/authorize?${params}` });
});

// GET /auth/callback?code=... → Échange le code contre un token
app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.status(400).json({ error: 'Code manquant' });

  try {
    // Échange code → access_token
    const tokenRes = await axios.post('https://github.com/login/oauth/access_token', {
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
      redirect_uri: `${process.env.BACKEND_URL || 'http://localhost:3000'}/auth/callback`
    }, { headers: { Accept: 'application/json' } });

    const { access_token } = tokenRes.data;
    if (!access_token) throw new Error('Token vide');

    // Récupère le profil GitHub
    const userRes = await axios.get('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${access_token}`, 'User-Agent': 'GDVault' }
    });

    const user = {
      login: userRes.data.login,
      avatar_url: userRes.data.avatar_url,
      name: userRes.data.name || userRes.data.login,
      id: userRes.data.id
    };

    // Redirige vers le frontend avec les infos user en query param
    // (En prod, utilise un JWT ou une session cookie)
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.redirect(`${frontendUrl}?user=${encodeURIComponent(JSON.stringify(user))}`);

  } catch (err) {
    console.error('OAuth error:', err.message);
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}?error=auth_failed`);
  }
});

// ── API — Videos ──────────────────────────────────────

// GET /api/videos → Liste toutes les vidéos
app.get('/api/videos', (req, res) => {
  res.json(videos.sort((a, b) => new Date(b.date) - new Date(a.date)));
});

// POST /api/videos → Upload une vidéo
app.post('/api/videos', upload.single('video'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Aucun fichier reçu' });

  const { title, difficulty, description, author, authorAvatar } = req.body;

  const video = {
    id: Date.now(),
    title: title || req.file.originalname,
    difficulty: difficulty || 'insane',
    description: description || '',
    author: author || 'Anonyme',
    authorAvatar: authorAvatar || '',
    filename: req.file.filename,
    url: `/uploads/${req.file.filename}`,
    size: req.file.size,
    date: new Date().toISOString(),
    views: 0
  };

  videos.unshift(video);
  res.json({ success: true, video });
});

// DELETE /api/videos/:id
app.delete('/api/videos/:id', (req, res) => {
  const idx = videos.findIndex(v => v.id === parseInt(req.params.id));
  if (idx === -1) return res.status(404).json({ error: 'Vidéo introuvable' });
  const [v] = videos.splice(idx, 1);
  const filePath = path.join(uploadDir, v.filename);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  res.json({ success: true });
});

// ── Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Erreur serveur' });
});

// ── Start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`\n🎮 GDVault Backend — http://localhost:${PORT}`);
  console.log(`⚙️  Mets tes credentials GitHub dans .env\n`);
});
