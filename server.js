const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
const SECRET = 'TROQUE_ESSE_SEGREDO';

// Middlewares
app.use(cors());
app.use(express.json());

// === BANCO DE DADOS (SQLite) ===
const db = new sqlite3.Database('./database.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password_hash TEXT,
      role TEXT DEFAULT 'user',
      status TEXT DEFAULT 'pending'
    )
  `);

  // Criar admin padrão se não existir
  const adminEmail = 'admin@painel.com';
  const adminPass = 'admin123'; // Troque mais tarde

  db.get('SELECT * FROM users WHERE email = ?', [adminEmail], async (err, row) => {
    if (!row) {
      const hash = await bcrypt.hash(adminPass, 10);
      db.run(
        'INSERT INTO users (name, email, password_hash, role, status) VALUES (?, ?, ?, ?, ?)',
        ['Admin', adminEmail, hash, 'admin', 'approved']
      );
      console.log('Admin criado: ', adminEmail, ' / senha:', adminPass);
    }
  });
});

// === MIDDLEWARES DE AUTENTICAÇÃO ===
function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Token ausente' });

  const token = auth.split(' ')[1];
  try {
    const decoded = jwt.verify(token, SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Somente admin pode acessar' });
  }
  next();
}

// === ROTAS ===

// Registro
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: 'Email e senha são obrigatórios' });

  try {
    const hash = await bcrypt.hash(password, 10);
    db.run(
      `INSERT INTO users (name, email, password_hash, role, status)
       VALUES (?, ?, ?, ?, ?)`,
      [name || '', email, hash, 'user', 'pending'],
      function (err) {
        if (err) return res.status(400).json({ error: 'Email já existente' });
        return res.json({ success: true, id: this.lastID });
      }
    );
  } catch (e) {
    return res.status(500).json({ error: 'Erro interno' });
  }
});

// Login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
    if (!user) return res.status(401).json({ error: 'Credenciais inválidas' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Credenciais inválidas' });

    if (user.status !== 'approved')
      return res.status(403).json({ error: 'Aguarde aprovação do admin' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      SECRET,
      { expiresIn: '7d' }
    );

    return res.json({
      token,
      role: user.role,
      name: user.name
    });
  });
});

// Admin: listar usuários
app.get('/api/admin/users', authMiddleware, adminOnly, (req, res) => {
  db.all('SELECT id, name, email, role, status FROM users', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Erro ao consultar usuários' });
    return res.json(rows);
  });
});

// Admin: aprovar
app.post('/api/admin/users/:id/approve', authMiddleware, adminOnly, (req, res) => {
  db.run(`UPDATE users SET status = 'approved' WHERE id = ?`, [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Erro ao aprovar usuário' });
    return res.json({ success: true });
  });
});

// Admin: recusar
app.post('/api/admin/users/:id/reject', authMiddleware, adminOnly, (req, res) => {
  db.run(`UPDATE users SET status = 'rejected' WHERE id = ?`, [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: 'Erro ao recusar usuário' });
    return res.json({ success: true });
  });
});

// Servir arquivos HTML da pasta public
app.use(express.static(path.join(__dirname, 'public')));

// === INICIAR SERVIDOR ===
const PORT = 3000;
app.listen(PORT, () => {
  console.log('Servidor rodando em http://localhost:' + PORT);
});
