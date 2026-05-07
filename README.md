# SecureShare 🔐

SecureShare is a secure file-sharing app built with **Node.js**, **Express**, **Socket.IO**, and **RSA/AES encryption**. It allows authenticated users to send encrypted files securely in real time.

## 🚀 Features

* User authentication with JWT
* RSA key pair generation
* AES-256 file encryption
* Secure file transfer with Socket.IO
* Online user tracking
* Secure file download & decryption

## 📦 Installation

```bash id="3u2oyx"
npm install
node server.js
```

Server runs at:

```bash id="h3hjlwm"
http://localhost:3000
```

## 🔐 Encryption Flow

1. File encrypted using AES-256
2. AES key encrypted using receiver's RSA public key
3. Receiver decrypts file securely using private key

## 🛠 Tech Stack

* Node.js
* Express.js
* Socket.IO
* Multer
* JWT
* bcrypt
* crypto

## 📜 License

MIT License
