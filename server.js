// ═══════════════════════════════════════════════
//  AuthLab — Backend Server
//  Node.js + Express + MongoDB + JWT
//  ✅ Production-ready: serve frontend + API dalam 1 Railway deployment
// ═══════════════════════════════════════════════

// ── LOAD ENV (HARUS PALING ATAS, SEBELUM APAPUN) ─
require('dotenv').config();

const path = require('path');

// ── DEBUG: CEK ENV VARS SAAT STARTUP ────────────
console.log('🔍 ENV Check:');
console.log('   NODE_ENV       :', process.env.NODE_ENV       || '(tidak di-set)');
console.log('   PORT           :', process.env.PORT           || '(tidak di-set, default 3000)');
console.log('   MONGO_URI      :', process.env.MONGO_URI      ? '✅ terbaca' : '❌ TIDAK TERBACA');
console.log('   JWT_SECRET     :', process.env.JWT_SECRET     ? '✅ terbaca' : '❌ TIDAK TERBACA');
// 🔥 CONFIG: API KEY RESEND DI AMBIL DARI VARIABLE ENV DI SINI 🔥
// 👉 Isi RESEND_API_KEY di file .env lokal atau tab Variables di Railway
console.log('   RESEND_API_KEY :', process.env.RESEND_API_KEY ? '✅ terbaca' : '⚠️  BELUM DI-SET (magic link email tidak akan terkirim)');

// ── VALIDASI ENV WAJIB (FAIL FAST) ──────────────
const REQUIRED_ENV = ['MONGO_URI', 'JWT_SECRET', 'JWT_REFRESH_SECRET'];
const missingEnv = REQUIRED_ENV.filter((key) => !process.env[key]);

if (missingEnv.length > 0) {
  console.error('\n❌ Environment variable berikut belum di-set:');
  missingEnv.forEach((key) => console.error(`   - ${key}`));
  console.error('\n💡 Solusi:');
  console.error('   • Lokal  : pastikan file .env ada dan berisi variable di atas');
  console.error('   • Railway: buka Settings → Variables → tambahkan variable tersebut');
  console.error('   • Pastikan nama variable PERSIS sama (case-sensitive)\n');
  process.exit(1);
}

const express   = require('express');
const mongoose  = require('mongoose');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const crypto    = require('crypto');
const rateLimit = require('express-rate-limit');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── TRUST PROXY (wajib di Railway / behind reverse proxy) ─
app.set('trust proxy', 1);

// ── SERVE STATIC FILES (frontend) ───────────────
// Semua file di folder public/ akan di-serve secara otomatis
app.use(express.static(path.join(__dirname, 'public')));

// ── MIDDLEWARE ──────────────────────────────────
app.use(express.json());

// CORS: karena frontend & backend 1 domain di Railway,
// kita tetap izinkan localhost untuk development lokal
const allowedOrigins = [
  // Production Railway domain (Railway inject secara otomatis via env RAILWAY_PUBLIC_DOMAIN)
  process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : null,
  // Custom domain jika ada
  process.env.FRONTEND_URL || null,
  // Development lokal
  'http://localhost:3000',
  'http://localhost:5500',
  'http://127.0.0.1:5500',
].filter(Boolean); // buang null

app.use(cors({
  origin: function (origin, callback) {
    // Izinkan request tanpa origin (curl, Postman, server-to-server)
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true,
}));

// ── RATE LIMITER (brute force protection) ───────
const loginLimiter = rateLimit({
  windowMs      : 15 * 60 * 1000,
  max           : 5,
  message       : { success: false, message: 'Terlalu banyak percobaan. Coba lagi dalam 15 menit.' },
  standardHeaders: true,
  legacyHeaders  : false,
});

// ── MONGODB CONNECTION ──────────────────────────
console.log('\n🔌 Menghubungkan ke MongoDB...');

mongoose.connect(process.env.MONGO_URI, {
  serverSelectionTimeoutMS : 30000,
  socketTimeoutMS          : 45000,
  family                   : 4,
})
  .then(() => {
    console.log('✅ MongoDB terhubung:', mongoose.connection.host);
  })
  .catch((err) => {
    console.error('❌ MongoDB gagal konek:', err.message);
    console.error('\n💡 Kemungkinan penyebab:');
    console.error('   • MONGO_URI salah format');
    console.error('   • IP Railway belum di-whitelist di MongoDB Atlas (set 0.0.0.0/0)');
    console.error('   • Username/password salah\n');
    process.exit(1);
  });

mongoose.connection.on('disconnected', () => console.warn('⚠️  MongoDB terputus. Mencoba reconnect...'));
mongoose.connection.on('reconnected',  () => console.log('🔄 MongoDB berhasil reconnect'));

// ── SCHEMA & MODEL ─────────────────────────────
const userSchema = new mongoose.Schema({
  firstName : { type: String, trim: true },
  lastName  : { type: String, trim: true },
  username  : { type: String, unique: true, sparse: true, lowercase: true, trim: true },
  email     : { type: String, required: true, unique: true, lowercase: true, trim: true },
  password  : { type: String },
  provider  : { type: String, default: 'local' },
  isVerified: { type: Boolean, default: false },
  createdAt : { type: Date, default: Date.now },
});

userSchema.methods.toSafeJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.__v;
  return obj;
};

const User = mongoose.model('User', userSchema);

const tokenSchema = new mongoose.Schema({
  email    : String,
  token    : String,
  type     : String,
  expiresAt: Date,
  used     : { type: Boolean, default: false },
});
const TokenRecord = mongoose.model('TokenRecord', tokenSchema);

// ── HELPERS ─────────────────────────────────────
const signAccessToken  = (userId) =>
  jwt.sign({ uid: userId }, process.env.JWT_SECRET,         { expiresIn: '15m' });

const signRefreshToken = (userId) =>
  jwt.sign({ uid: userId }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });

const respond = (res, status, success, message, data = {}) =>
  res.status(status).json({ success, message, ...data });

// ── MIDDLEWARE: AUTH GUARD ──────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer '))
    return respond(res, 401, false, 'Token tidak ditemukan');
  try {
    req.user = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    next();
  } catch {
    return respond(res, 401, false, 'Token tidak valid atau sudah expired');
  }
}

// ════════════════════════════════════════════════
//  API ROUTES — semua diawali /api
// ════════════════════════════════════════════════

// ── HEALTH CHECK ────────────────────────────────
app.get('/api/health', (req, res) => {
  respond(res, 200, true, 'Server berjalan normal', {
    db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
  });
});

// ── REGISTER ────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { firstName, lastName, username, email, password } = req.body;

    if (!email || !password)
      return respond(res, 400, false, 'Email dan password wajib diisi');
    if (password.length < 8)
      return respond(res, 400, false, 'Password minimal 8 karakter');

    const existingEmail = await User.findOne({ email });
    if (existingEmail)
      return respond(res, 409, false, 'Email sudah terdaftar');

    if (username) {
      const existingUsername = await User.findOne({ username });
      if (existingUsername)
        return respond(res, 409, false, 'Username sudah dipakai');
    }

    const hash = await bcrypt.hash(password, 12);
    const user = await User.create({ firstName, lastName, username, email, password: hash, provider: 'local' });

    const accessToken  = signAccessToken(user._id);
    const refreshToken = signRefreshToken(user._id);

    respond(res, 201, true, 'Akun berhasil dibuat', {
      user: user.toSafeJSON(), accessToken, refreshToken,
    });

  } catch (err) {
    console.error('Register error:', err);
    respond(res, 500, false, 'Internal server error');
  }
});

// ── LOGIN ────────────────────────────────────────
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return respond(res, 400, false, 'Email dan password wajib diisi');

    const user = await User.findOne({ $or: [{ email }, { username: email }] });

    if (!user || !user.password)
      return respond(res, 401, false, 'Email atau password salah');

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return respond(res, 401, false, 'Email atau password salah');

    const accessToken  = signAccessToken(user._id);
    const refreshToken = signRefreshToken(user._id);

    respond(res, 200, true, 'Login berhasil', {
      user: user.toSafeJSON(), accessToken, refreshToken,
    });

  } catch (err) {
    console.error('Login error:', err);
    respond(res, 500, false, 'Internal server error');
  }
});

// ── REFRESH TOKEN ────────────────────────────────
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return respond(res, 400, false, 'Refresh token diperlukan');

    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user    = await User.findById(decoded.uid);

    if (!user) return respond(res, 404, false, 'User tidak ditemukan');

    const newAccessToken = signAccessToken(user._id);
    respond(res, 200, true, 'Token diperbarui', { accessToken: newAccessToken });

  } catch {
    respond(res, 401, false, 'Refresh token tidak valid atau expired');
  }
});

// ── CHECK USERNAME ───────────────────────────────
app.get('/api/auth/check-username', async (req, res) => {
  try {
    const { username } = req.query;
    if (!username || username.length < 3)
      return respond(res, 400, false, 'Username terlalu pendek');

    const exists = await User.findOne({ username: username.toLowerCase() });
    respond(res, 200, true, exists ? 'Username sudah dipakai' : 'Username tersedia', {
      available: !exists,
    });
  } catch {
    respond(res, 500, false, 'Internal server error');
  }
});

// ── SEND MAGIC LINK ──────────────────────────────
app.post('/api/auth/magic-link', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return respond(res, 400, false, 'Email diperlukan');

    // 🔥 CONFIG: API KEY RESEND DI AMBIL DARI VARIABLE ENV DI SINI 🔥
    // 👉 Tambahkan RESEND_API_KEY=re_xxxx di file .env lokal atau
    //    tab Variables di Railway agar email magic link bisa terkirim
    const RESEND_API_KEY = process.env.RESEND_API_KEY;
    if (!RESEND_API_KEY) {
      console.error('❌ RESEND_API_KEY belum di-set! Magic link tidak bisa dikirim.');
      console.error('   • Lokal  : tambahkan RESEND_API_KEY=re_xxxx di file .env');
      console.error('   • Railway: buka Settings → Variables → tambahkan RESEND_API_KEY');
      return respond(res, 500, false, 'Layanan email belum dikonfigurasi. Hubungi administrator.');
    }

    const token     = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await TokenRecord.deleteMany({ email, type: 'magic' });
    await TokenRecord.create({ email, token, type: 'magic', expiresAt });

    // Base URL: pakai Railway domain jika ada, fallback ke FRONTEND_URL
    const baseUrl = process.env.RAILWAY_PUBLIC_DOMAIN
      ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
      : (process.env.FRONTEND_URL || 'http://localhost:3000');

    // Link mengarah ke route backend verify-magic agar token langsung diproses & user ter-login
    const link = `${baseUrl}/api/auth/verify-magic?token=${token}`;

    // Kirim email via Resend API menggunakan fetch bawaan Node.js
    const resendRes = await fetch('https://api.resend.com/emails', {
      method : 'POST',
      headers: {
        'Content-Type' : 'application/json',
        'Authorization': `Bearer ${RESEND_API_KEY}`,
      },
      body: JSON.stringify({
        from   : process.env.RESEND_FROM_EMAIL || 'AuthLab <onboarding@resend.dev>',
        to     : [email],
        subject: 'Magic Link Login — AuthLab',
        html   : `
          <div style="font-family: Arial, sans-serif; max-width: 480px; margin: 0 auto; padding: 32px 24px; background: #f9fafb; border-radius: 12px;">
            <h2 style="margin: 0 0 8px; font-size: 22px; color: #111827;">Masuk ke AuthLab</h2>
            <p style="margin: 0 0 24px; font-size: 15px; color: #4b5563;">
              Klik tombol di bawah untuk login. Link ini hanya berlaku selama <strong>15 menit</strong> dan hanya bisa digunakan sekali.
            </p>
            <a href="${link}"
               style="display: inline-block; padding: 13px 28px; background: #4f46e5; color: #ffffff;
                      font-size: 15px; font-weight: 600; text-decoration: none; border-radius: 8px;
                      letter-spacing: 0.3px;">
              ✉️ &nbsp;Login Sekarang
            </a>
            <p style="margin: 24px 0 0; font-size: 13px; color: #9ca3af;">
              Jika kamu tidak meminta link ini, abaikan email ini. Link akan kadaluarsa otomatis.
            </p>
            <hr style="margin: 24px 0; border: none; border-top: 1px solid #e5e7eb;" />
            <p style="margin: 0; font-size: 12px; color: #d1d5db;">
              AuthLab · Magic Link Authentication
            </p>
          </div>
        `,
      }),
    });

    if (!resendRes.ok) {
      const errBody = await resendRes.json().catch(() => ({}));
      console.error('❌ Resend API gagal:', resendRes.status, errBody);
      return respond(res, 500, false, 'Gagal mengirim email. Coba beberapa saat lagi.');
    }

    console.log(`✅ Magic link terkirim ke ${email}`);
    respond(res, 200, true, 'Magic link berhasil dikirim! Cek inbox Gmail kamu.');

  } catch (err) {
    console.error('Magic link error:', err);
    respond(res, 500, false, 'Internal server error');
  }
});

// ── VERIFY MAGIC LINK ────────────────────────────
app.get('/api/auth/verify-magic', async (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return respond(res, 400, false, 'Token diperlukan');

    const record = await TokenRecord.findOne({ token, type: 'magic', used: false });
    if (!record)     return respond(res, 400, false, 'Token tidak valid');
    if (new Date() > record.expiresAt) return respond(res, 400, false, 'Token sudah expired');

    record.used = true;
    await record.save();

    let user = await User.findOne({ email: record.email });
    if (!user) {
      user = await User.create({ email: record.email, provider: 'magic', isVerified: true });
    }

    const accessToken  = signAccessToken(user._id);
    const refreshToken = signRefreshToken(user._id);

    respond(res, 200, true, 'Login via magic link berhasil', {
      user: user.toSafeJSON(), accessToken, refreshToken,
    });

  } catch (err) {
    console.error('Verify magic error:', err);
    respond(res, 500, false, 'Internal server error');
  }
});

// ── SEND OTP ─────────────────────────────────────
app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return respond(res, 400, false, 'Nomor HP diperlukan');

    const otp       = Math.floor(100000 + Math.random() * 900000).toString();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    await TokenRecord.deleteMany({ email: phone, type: 'otp' });
    await TokenRecord.create({ email: phone, token: otp, type: 'otp', expiresAt });

    // TODO: kirim via SMS (Twilio, Vonage, dll)
    console.log(`[DEV] OTP untuk ${phone}: ${otp}`);
    respond(res, 200, true, 'OTP berhasil dikirim (cek terminal di dev mode)', {
      devOtp: process.env.NODE_ENV !== 'production' ? otp : undefined,
    });

  } catch (err) {
    console.error('Send OTP error:', err);
    respond(res, 500, false, 'Internal server error');
  }
});

// ── VERIFY OTP ───────────────────────────────────
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp)
      return respond(res, 400, false, 'Nomor HP dan OTP diperlukan');

    const record = await TokenRecord.findOne({ email: phone, type: 'otp', used: false });
    if (!record || record.token !== otp) return respond(res, 400, false, 'OTP tidak valid');
    if (new Date() > record.expiresAt)   return respond(res, 400, false, 'OTP sudah expired');

    record.used = true;
    await record.save();

    respond(res, 200, true, 'OTP berhasil diverifikasi', { verified: true });

  } catch (err) {
    console.error('Verify OTP error:', err);
    respond(res, 500, false, 'Internal server error');
  }
});

// ── GET PROFILE (protected) ──────────────────────
app.get('/api/user/profile', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.uid);
    if (!user) return respond(res, 404, false, 'User tidak ditemukan');
    respond(res, 200, true, 'Profil berhasil diambil', { user: user.toSafeJSON() });
  } catch {
    respond(res, 500, false, 'Internal server error');
  }
});

// ════════════════════════════════════════════════
//  CATCH-ALL: Semua route selain /api → serve index.html
//  Ini yang membuat browser refresh tidak error (SPA behavior)
// ════════════════════════════════════════════════
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── GLOBAL ERROR HANDLER ─────────────────────────
app.use((err, req, res, next) => {
  console.error('🔥 Unhandled error:', err);
  respond(res, 500, false, 'Internal server error');
});

// ── START SERVER ─────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 AuthLab server berjalan di http://localhost:${PORT}`);
  console.log(`📋 Environment : ${process.env.NODE_ENV || 'development'}`);
  console.log(`📂 Static files: ${path.join(__dirname, 'public')}\n`);
});

// ── GRACEFUL SHUTDOWN ────────────────────────────
process.on('SIGTERM', async () => {
  console.log('⚠️  SIGTERM diterima. Menutup server...');
  await mongoose.connection.close();
  console.log('✅ MongoDB ditutup. Server berhenti.');
  process.exit(0);
});

process.on('uncaughtException',  (err)    => { console.error('💥 Uncaught Exception:', err);    process.exit(1); });
process.on('unhandledRejection', (reason) => { console.error('💥 Unhandled Rejection:', reason); process.exit(1); });
