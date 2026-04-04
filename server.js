const express     = require('express');
const multer      = require('multer');
const axios       = require('axios');
const cors        = require('cors');
const path        = require('path');
const fs          = require('fs');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const mongoose    = require('mongoose');
const cloudinary  = require('cloudinary').v2;
const streamifier = require('streamifier');
require('dotenv').config();

const app = express();
app.use(cors({ origin: process.env.FRONTEND_URL || 'http://localhost:3000', credentials: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Cloudinary ─────────────────────────────────────────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// ── MongoDB ────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ MongoDB connecté'))
  .catch(err => console.error('❌ MongoDB erreur:', err.message));

// ── Schemas ────────────────────────────────────────────────
const OWNER = 'Tetedecitron';

const userSchema = new mongoose.Schema({
  login:      { type: String, required: true, unique: true },
  email:      { type: String, sparse: true },
  password:   { type: String },
  avatar_url: { type: String, default: '' },
  role:       { type: String, default: 'member' },
  githubId:   { type: Number, sparse: true },
  joinedAt:   { type: Date, default: Date.now }
});

const videoSchema = new mongoose.Schema({
  title:        { type: String, required: true },
  difficulty:   { type: String, default: 'extremedemon' },
  description:  { type: String, default: '' },
  author:       { type: String, required: true },
  authorAvatar: { type: String, default: '' },
  authorRole:   { type: String, default: 'member' },
  cloudinaryId: { type: String },   // public_id sur Cloudinary
  url:          { type: String },   // URL de lecture
  size:         { type: Number, default: 0 },
  date:         { type: Date, default: Date.now },
  views:        { type: Number, default: 0 }
});

const User  = mongoose.model('User',  userSchema);
const Video = mongoose.model('Video', videoSchema);

// ── Multer (mémoire, pas disque) ───────────────────────────
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('video/')) cb(null, true);
    else cb(new Error('Fichier vidéo requis'));
  }
});

// ── JWT ────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'gdvault_secret';

function makeToken(user) {
  return jwt.sign({ id: user._id, login: user.login, role: user.role }, JWT_SECRET, { expiresIn: '30d' });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: 'Non authentifié' });
  try { req.user = jwt.verify(header.replace('Bearer ', ''), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token invalide' }); }
}

// ── Helper ─────────────────────────────────────────────────
async function ensureUser(login, avatar_url, githubId) {
  let u = await User.findOne({ login });
  if (!u) {
    u = await User.create({ login, avatar_url: avatar_url || '', githubId: githubId || null, role: login === OWNER ? 'owner' : 'member' });
  } else {
    if (avatar_url) u.avatar_url = avatar_url;
    if (login === OWNER) u.role = 'owner';
    await u.save();
  }
  return u;
}

// Upload buffer → Cloudinary
function uploadToCloudinary(buffer, filename) {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { resource_type: 'video', folder: 'gdvault', public_id: `${Date.now()}-${filename}`, chunk_size: 6000000 },
      (err, result) => { if (err) reject(err); else resolve(result); }
    );
    streamifier.createReadStream(buffer).pipe(stream);
  });
}

// ── AUTH — Email/Password ──────────────────────────────────
app.post('/auth/register', async (req, res) => {
  try {
    const { login, email, password } = req.body;
    if (!login || !email || !password) return res.status(400).json({ error: 'Champs manquants' });
    if (password.length < 6) return res.status(400).json({ error: 'Mot de passe trop court (6 min)' });
    const exists = await User.findOne({ $or: [{ login }, { email }] });
    if (exists) return res.status(409).json({ error: exists.login === login ? 'Pseudo déjà pris' : 'Email déjà utilisé' });
    const hashed = await bcrypt.hash(password, 10);
    const avatar_url = `https://api.dicebear.com/7.x/pixel-art/svg?seed=${login}`;
    const user = await User.create({ login, email, password: hashed, avatar_url, role: login === OWNER ? 'owner' : 'member' });
    res.json({ token: makeToken(user), user: { login: user.login, avatar_url: user.avatar_url, role: user.role } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { login, password } = req.body;
    if (!login || !password) return res.status(400).json({ error: 'Champs manquants' });
    const user = await User.findOne({ $or: [{ login }, { email: login }] });
    if (!user || !user.password) return res.status(401).json({ error: 'Compte introuvable ou connexion GitHub requise' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'Mot de passe incorrect' });
    res.json({ token: makeToken(user), user: { login: user.login, avatar_url: user.avatar_url, role: user.role } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── AUTH — GitHub OAuth ────────────────────────────────────
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
    const { login, avatar_url, id } = userRes.data;
    const user = await ensureUser(login, avatar_url, id);
    const token = makeToken(user);
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:3000';
    res.redirect(`${frontendUrl}?token=${encodeURIComponent(token)}&user=${encodeURIComponent(JSON.stringify({ login: user.login, avatar_url: user.avatar_url, role: user.role }))}`);
  } catch (err) {
    console.error('OAuth error:', err.message);
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:3000'}?error=auth_failed`);
  }
});

// ── VIDEOS ─────────────────────────────────────────────────
app.get('/api/videos', async (req, res) => {
  try {
    const { diff, q } = req.query;
    const filter = {};
    if (diff) filter.difficulty = diff;
    if (q) filter.title = { $regex: q, $options: 'i' };
    const vids = await Video.find(filter).sort({ date: -1 });
    res.json(vids);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/videos', authMiddleware, upload.single('video'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'Aucun fichier reçu' });
    const { title, difficulty, description } = req.body;
    const user = await User.findOne({ login: req.user.login });

    // Upload vers Cloudinary
    const result = await uploadToCloudinary(req.file.buffer, req.file.originalname.replace(/\s/g, '_'));

    const video = await Video.create({
      title: title || req.file.originalname,
      difficulty: difficulty || 'extremedemon',
      description: description || '',
      author: req.user.login,
      authorAvatar: user?.avatar_url || '',
      authorRole: req.user.role,
      cloudinaryId: result.public_id,
      url: result.secure_url,
      size: req.file.size
    });
    res.json({ success: true, video });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/videos/:id', authMiddleware, async (req, res) => {
  try {
    const video = await Video.findById(req.params.id);
    if (!video) return res.status(404).json({ error: 'Vidéo introuvable' });
    if (video.author !== req.user.login && req.user.role !== 'owner') return res.status(403).json({ error: 'Interdit' });
    if (video.cloudinaryId) {
      await cloudinary.uploader.destroy(video.cloudinaryId, { resource_type: 'video' });
    }
    await Video.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── MEMBERS ────────────────────────────────────────────────
app.get('/api/members', async (req, res) => {
  try {
    const { q } = req.query;
    const filter = q ? { login: { $regex: q, $options: 'i' } } : {};
    const users = await User.find(filter, '-password -email').sort({ role: -1, login: 1 });
    const logins = users.map(u => u.login);
    const counts = await Video.aggregate([
      { $match: { author: { $in: logins } } },
      { $group: { _id: '$author', count: { $sum: 1 } } }
    ]);
    const countMap = {};
    counts.forEach(c => countMap[c._id] = c.count);
    const result = users.map(u => ({
      login: u.login, avatar_url: u.avatar_url, role: u.role,
      joinedAt: u.joinedAt, videoCount: countMap[u.login] || 0
    }));
    result.sort((a, b) => { if (a.role === 'owner') return -1; if (b.role === 'owner') return 1; return a.login.localeCompare(b.login); });
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/members/:login/videos', async (req, res) => {
  try {
    const vids = await Video.find({ author: req.params.login }).sort({ date: -1 });
    res.json(vids);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/members/:login', authMiddleware, async (req, res) => {
  try {
    if (req.user.role !== 'owner') return res.status(403).json({ error: 'Réservé au Owner' });
    if (req.params.login === OWNER) return res.status(400).json({ error: 'Impossible de supprimer le Owner' });
    await User.findOneAndDelete({ login: req.params.login });
    const userVideos = await Video.find({ author: req.params.login });
    for (const v of userVideos) {
      if (v.cloudinaryId) await cloudinary.uploader.destroy(v.cloudinaryId, { resource_type: 'video' }).catch(() => {});
    }
    await Video.deleteMany({ author: req.params.login });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Error handler ──────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Erreur serveur' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`\n🎮 GDVault — http://localhost:${PORT}\n`));
