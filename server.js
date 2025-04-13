const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://user:pass@localhost:5432/appstore',
});

// Initialize database
async function initDb() {
  try {
    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL
      )
    `);

    // Create apps table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS apps (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        image VARCHAR(255) NOT NULL,
        link VARCHAR(255) NOT NULL,
        user_id INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Seed initial apps if table is empty
    const appCount = await pool.query('SELECT COUNT(*) FROM apps');
    if (parseInt(appCount.rows[0].count) === 0) {
      await pool.query(`
        INSERT INTO apps (name, description, image, link, user_id) VALUES
        ('Notion', 'Toma notas, gestiona proyectos y colabora en equipo.', 'https://via.placeholder.com/250x150?text=Notion', 'https://notion.so', NULL),
        ('Procreate', 'Crea arte digital con herramientas profesionales.', 'https://via.placeholder.com/250x150?text=Procreate', 'https://procreate.art', NULL),
        ('Duolingo', 'Aprende idiomas de forma divertida y gratuita.', 'https://via.placeholder.com/250x150?text=Duolingo', 'https://duolingo.com', NULL),
        ('Brawl Stars', 'Frenéticas batallas 3v3 y battle royale para móviles.', 'https://via.placeholder.com/250x150?text=Brawl+Stars', 'https://supercell.com', NULL),
        ('Spotify', 'Escucha millones de canciones y podcasts.', 'https://via.placeholder.com/250x150?text=Spotify', 'https://spotify.com', NULL),
        ('Todoist', 'Organiza tus tareas y aumenta tu productividad.', 'https://via.placeholder.com/250x150?text=Todoist', 'https://todoist.com', NULL),
        ('Photoshop Express', 'Edita fotos con herramientas fáciles y potentes.', 'https://via.placeholder.com/250x150?text=Photoshop+Express', 'https://adobe.com', NULL),
        ('GoodNotes', 'Toma notas digitales con estilo y precisión.', 'https://via.placeholder.com/250x150?text=GoodNotes', 'https://goodnotes.com', NULL),
        ('Clash of Clans', 'Construye tu aldea y compite en batallas épicas.', 'https://via.placeholder.com/250x150?text=Clash+of+Clans', 'https://supercell.com', NULL),
        ('Headspace', 'Medita y mejora tu bienestar mental.', 'https://via.placeholder.com/250x150?text=Headspace', 'https://headspace.com', NULL),
        ('Trello', 'Gestiona proyectos con tableros intuitivos.', 'https://via.placeholder.com/250x150?text=Trello', 'https://trello.com', NULL),
        ('Genshin Impact', 'Explora un mundo abierto lleno de aventuras.', 'https://via.placeholder.com/250x150?text=Genshin+Impact', 'https://genshin.hoyoverse.com', NULL)
      `);
    }
  } catch (err) {
    console.error('Error initializing database:', err);
  }
}

initDb();

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Login endpoint
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ id: user.id, email: user.email }, 'secret_key', { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Signup endpoint
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3)',
      [name, email, hashedPassword]
    );
    res.status(201).json({ message: 'User created' });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Upload app endpoint
app.post('/api/apps', authenticateToken, async (req, res) => {
  const { name, description, image, link } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO apps (name, description, image, link, user_id) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [name, description, image, link, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all apps
app.get('/api/apps', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM apps');
    res.json(result.rows);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
