const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const multer = require('multer');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIO(server);

const PORT = 3000;
const JWT_SECRET = 'secureshare_jwt_secret_2025';
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const KEYS_DIR = path.join(__dirname, 'keys');

// Create directories
[UPLOADS_DIR, KEYS_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// In-memory users DB (for demo — replace with real DB in production)
const users = {};

// Connected socket users: socketId -> { username, publicKey }
const connectedUsers = {};

// Pending file transfer requests: requestId -> { fromSocket, toSocket, filename, encryptedFile, encryptedKey, iv }
const pendingTransfers = {};

// ─── RSA Key Generation per user ───────────────────────────────────────────────
function generateRSAKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

// ─── AES Encryption ────────────────────────────────────────────────────────────
function encryptFileAES(fileBuffer) {
  const aesKey = crypto.randomBytes(32); // 256-bit AES key
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  const encryptedFile = Buffer.concat([cipher.update(fileBuffer), cipher.final()]);
  return { encryptedFile, aesKey, iv };
}

function decryptFileAES(encryptedBuffer, aesKey, iv) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
  return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
}

// ─── RSA Key Wrapping ──────────────────────────────────────────────────────────
function encryptAESKeyWithRSA(aesKey, publicKeyPem) {
  return crypto.publicEncrypt(
    { key: publicKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    aesKey
  );
}

function decryptAESKeyWithRSA(encryptedAESKey, privateKeyPem) {
  return crypto.privateDecrypt(
    { key: privateKeyPem, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    encryptedAESKey
  );
}

// ─── Middleware ────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.static(__dirname));

// Multer — memory storage so we can encrypt before saving
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// ─── Auth Routes ───────────────────────────────────────────────────────────────
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (users[username]) return res.status(409).json({ error: 'Username already exists' });

  const hashedPassword = await bcrypt.hash(password, 12);
  const { publicKey, privateKey } = generateRSAKeyPair();

  users[username] = { hashedPassword, publicKey, privateKey };

  // Save private key to keys dir (in real app, send to client securely)
  fs.writeFileSync(path.join(KEYS_DIR, `${username}_private.pem`), privateKey);
  fs.writeFileSync(path.join(KEYS_DIR, `${username}_public.pem`), publicKey);

  res.json({ success: true, message: 'Registered successfully' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users[username];
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const valid = await bcrypt.compare(password, user.hashedPassword);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ success: true, token, publicKey: user.publicKey });
});

// ─── File Upload + Encrypt + Transfer Request ──────────────────────────────────
app.post('/send-file', upload.single('file'), (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  let decoded;
  try { decoded = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }

  const { targetUsername } = req.body;
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'No file uploaded' });

  // Find target user's socket
  const targetEntry = Object.entries(connectedUsers).find(([, u]) => u.username === targetUsername);
  if (!targetEntry) return res.status(404).json({ error: 'Target user not online' });

  const [targetSocketId, targetUser] = targetEntry;
  const senderEntry = Object.entries(connectedUsers).find(([, u]) => u.username === decoded.username);
  const senderSocketId = senderEntry ? senderEntry[0] : null;

  // Encrypt file with AES
  const { encryptedFile, aesKey, iv } = encryptFileAES(file.buffer);

  // Wrap AES key with receiver's RSA public key
  const receiverPublicKey = users[targetUsername]?.publicKey;
  if (!receiverPublicKey) return res.status(404).json({ error: 'Receiver public key not found' });

  const encryptedAESKey = encryptAESKeyWithRSA(aesKey, receiverPublicKey);

  // Create transfer request
  const requestId = crypto.randomBytes(8).toString('hex');
  pendingTransfers[requestId] = {
    fromSocket: senderSocketId,
    toSocket: targetSocketId,
    fromUsername: decoded.username,
    filename: file.originalname,
    mimetype: file.mimetype,
    encryptedFile: encryptedFile.toString('base64'),
    encryptedAESKey: encryptedAESKey.toString('base64'),
    iv: iv.toString('hex'),
    fileSize: file.size
  };

  // Notify receiver via Socket.IO
  io.to(targetSocketId).emit('file-request', {
    requestId,
    fromUsername: decoded.username,
    filename: file.originalname,
    fileSize: file.size
  });

  res.json({ success: true, requestId, message: 'Transfer request sent' });
});

// ─── Download decrypted file ───────────────────────────────────────────────────
app.get('/download/:requestId', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });

  let decoded;
  try { decoded = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }

  const transfer = pendingTransfers[req.params.requestId];
  if (!transfer) return res.status(404).json({ error: 'Transfer not found' });

  const receiverPrivateKey = users[decoded.username]?.privateKey;
  if (!receiverPrivateKey) return res.status(404).json({ error: 'Private key not found' });

  try {
    const encryptedAESKey = Buffer.from(transfer.encryptedAESKey, 'base64');
    const encryptedFile = Buffer.from(transfer.encryptedFile, 'base64');
    const iv = Buffer.from(transfer.iv, 'hex');

    const aesKey = decryptAESKeyWithRSA(encryptedAESKey, receiverPrivateKey);
    const decryptedFile = decryptFileAES(encryptedFile, aesKey, iv);

    res.setHeader('Content-Disposition', `attachment; filename="${transfer.filename}"`);
    res.setHeader('Content-Type', transfer.mimetype || 'application/octet-stream');
    res.send(decryptedFile);

    // Clean up after download
    delete pendingTransfers[req.params.requestId];
  } catch (err) {
    res.status(500).json({ error: 'Decryption failed: ' + err.message });
  }
});

// ─── Socket.IO ────────────────────────────────────────────────────────────────
io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);

  // Register user to socket
  socket.on('register-socket', (data) => {
    const { token } = data;
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      connectedUsers[socket.id] = { username: decoded.username };
      console.log(`${decoded.username} registered socket ${socket.id}`);

      // Broadcast updated online users list
      broadcastOnlineUsers();
    } catch (e) {
      socket.emit('error', 'Invalid token');
    }
  });

  // Accept transfer
  socket.on('accept-transfer', ({ requestId }) => {
    const transfer = pendingTransfers[requestId];
    if (!transfer) return;
    if (transfer.fromSocket) {
      io.to(transfer.fromSocket).emit('transfer-accepted', { requestId, filename: transfer.filename });
    }
    socket.emit('start-download', { requestId, filename: transfer.filename });
  });

  // Reject transfer
  socket.on('reject-transfer', ({ requestId }) => {
    const transfer = pendingTransfers[requestId];
    if (!transfer) return;
    if (transfer.fromSocket) {
      io.to(transfer.fromSocket).emit('transfer-rejected', { requestId, filename: transfer.filename });
    }
    delete pendingTransfers[requestId];
  });

  socket.on('disconnect', () => {
    const user = connectedUsers[socket.id];
    if (user) {
      console.log(`${user.username} disconnected`);
      delete connectedUsers[socket.id];
      broadcastOnlineUsers();
    }
  });
});

function broadcastOnlineUsers() {
  const userList = Object.values(connectedUsers).map(u => u.username);
  io.emit('online-users', userList);
}

// ─── Start Server ──────────────────────────────────────────────────────────────
server.listen(PORT, '0.0.0.0', () => {
  const interfaces = require('os').networkInterfaces();
  let localIP = 'localhost';
  Object.values(interfaces).forEach(iface => {
    iface.forEach(addr => {
      if (addr.family === 'IPv4' && !addr.internal) localIP = addr.address;
    });
  });
  console.log(`\n🚀 SecureShare Server running!`);
  console.log(`   Local:   http://localhost:${PORT}`);
  console.log(`   Network: http://${localIP}:${PORT}  ← open this on phone/other devices\n`);
});
