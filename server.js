const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const initSqlJs = require('sql.js');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'school-points-secret-key-2024';
const DB_PATH = path.join(__dirname, 'school.db');

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database setup
let db;

async function initDatabase() {
  const SQL = await initSqlJs();
  
  // Load existing database or create new one
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }
  
  // Create tables
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('student', 'teacher', 'moderator', 'owner')),
      balance INTEGER DEFAULT 0,
      class TEXT,
      subject TEXT,
      profile_color TEXT DEFAULT '#667eea',
      profile_badges TEXT DEFAULT '[]',
      title TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      from_user_id INTEGER,
      to_user_id INTEGER NOT NULL,
      amount INTEGER NOT NULL,
      reason TEXT,
      grade INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (from_user_id) REFERENCES users(id),
      FOREIGN KEY (to_user_id) REFERENCES users(id)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS requests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_id INTEGER NOT NULL,
      type TEXT NOT NULL CHECK(type IN ('immunity', 'bell')),
      status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
      cost INTEGER NOT NULL,
      subject TEXT,
      media_url TEXT,
      media_type TEXT CHECK(media_type IN ('video', 'audio')),
      processed_by INTEGER,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      processed_at DATETIME,
      FOREIGN KEY (student_id) REFERENCES users(id),
      FOREIGN KEY (processed_by) REFERENCES users(id)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS grade_awards (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      teacher_id INTEGER NOT NULL,
      student_id INTEGER NOT NULL,
      grade INTEGER NOT NULL,
      points INTEGER NOT NULL,
      approved_by_bot BOOLEAN DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (teacher_id) REFERENCES users(id),
      FOREIGN KEY (student_id) REFERENCES users(id)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS badges (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      description TEXT,
      icon TEXT NOT NULL,
      requirement TEXT NOT NULL,
      reward_points INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS user_badges (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      badge_id INTEGER NOT NULL,
      earned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (badge_id) REFERENCES badges(id)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS titles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      description TEXT,
      icon TEXT DEFAULT '🏆',
      requirement TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS user_titles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title_id INTEGER NOT NULL,
      earned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id),
      FOREIGN KEY (title_id) REFERENCES titles(id)
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS leader_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      student_id INTEGER NOT NULL,
      month TEXT NOT NULL,
      year INTEGER NOT NULL,
      balance INTEGER NOT NULL,
      title_awarded TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (student_id) REFERENCES users(id)
    )
  `);
  
  saveDatabase();
  
  // Initialize admin account
  initAdmin();
}

function saveDatabase() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_PATH, buffer);
}

function initAdmin() {
  const result = db.exec("SELECT id FROM users WHERE username = 'Ванчело'");
  if (result.length === 0 || result[0].values.length === 0) {
    const hashedPassword = bcrypt.hashSync('Ivan2404!', 10);
    db.run('INSERT INTO users (username, password, role, balance, class, subject) VALUES (?, ?, ?, ?, ?, ?)',
      ['Ванчело', hashedPassword, 'owner', 999999, 'Админ', null]
    );
    saveDatabase();
    console.log('Admin account created: Ванчело');
  }
}

// Helper functions for database
function dbGet(query, params = []) {
  const stmt = db.prepare(query);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

function dbAll(query, params = []) {
  const stmt = db.prepare(query);
  stmt.bind(params);
  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();
  return results;
}

function dbRun(query, params = []) {
  db.run(query, params);
  saveDatabase();
  const result = db.exec('SELECT last_insert_rowid() as id');
  return { lastInsertRowid: result[0]?.values[0]?.[0] || 0 };
}

// Auth middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Токен не предоставлен' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = dbGet('SELECT * FROM users WHERE id = ?', [decoded.id]);
    if (!req.user) return res.status(401).json({ error: 'Пользователь не найден' });
    next();
  } catch (err) {
    res.status(401).json({ error: 'Недействительный токен' });
  }
};

// Role check middleware
const checkRole = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Недостаточно прав' });
    }
    next();
  };
};

// ============ AUTH ROUTES ============

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  const user = dbGet('SELECT * FROM users WHERE username = ?', [username]);
  if (!user) {
    return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
  }
  
  const validPassword = bcrypt.compareSync(password, user.password);
  if (!validPassword) {
    return res.status(401).json({ error: 'Неверное имя пользователя или пароль' });
  }
  
  const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
  
  res.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role,
      balance: user.balance
    }
  });
});

// Register (только для учителей и модераторов через owner/moderator)
app.post('/api/register', auth, checkRole('owner', 'moderator'), (req, res) => {
  const { username, password, role, class: userClass, subject } = req.body;
  
  if (!['student', 'teacher', 'moderator'].includes(role)) {
    return res.status(400).json({ error: 'Недопустимая роль' });
  }
  
  // Модераторы могут создавать только учеников и учителей
  if (req.user.role === 'moderator' && role === 'moderator') {
    return res.status(403).json({ error: 'Модераторы не могут создавать других модераторов' });
  }
  
  const hashedPassword = bcrypt.hashSync(password, 10);
  
  try {
    const result = dbRun('INSERT INTO users (username, password, role, balance, class, subject) VALUES (?, ?, ?, ?, ?, ?)',
      [username, hashedPassword, role, 0, userClass || null, subject || null]
    );
    res.json({ id: result.lastInsertRowid, username, role, balance: 0, class: userClass || null, subject: subject || null });
  } catch (err) {
    res.status(400).json({ error: 'Пользователь уже существует' });
  }
});

// Get current user
app.get('/api/me', auth, (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    role: req.user.role,
    balance: req.user.balance,
    class: req.user.class,
    subject: req.user.subject,
    profile_color: req.user.profile_color || '#667eea',
    title: req.user.title
  });
});

// ============ TEACHER ROUTES ============

// Award points to student
app.post('/api/teacher/award', auth, checkRole('teacher', 'moderator', 'owner'), (req, res) => {
  const { studentId, grade, reason } = req.body;
  
  const student = dbGet('SELECT * FROM users WHERE id = ? AND role = ?', [studentId, 'student']);
  if (!student) {
    return res.status(404).json({ error: 'Ученик не найден' });
  }
  
  // Calculate points based on grade
  let points = 0;
  if (grade === 4) points = 5;
  else if (grade === 5) points = 10;
  else if (grade === 2 || grade === 3) points = 0;
  else {
    return res.status(400).json({ error: 'Оценка должна быть от 2 до 5' });
  }
  
  // Check daily limit (20 points per day)
  const today = new Date().toISOString().split('T')[0];
  const todayPoints = dbGet(`
    SELECT COALESCE(SUM(t.amount), 0) as total 
    FROM transactions t 
    WHERE t.to_user_id = ? AND date(t.created_at) = date(?)
  `, [studentId, today]);
  
  const currentDailyTotal = todayPoints?.total || 0;
  const DAILY_LIMIT = 20;
  
  if (currentDailyTotal + points > DAILY_LIMIT) {
    const remaining = Math.max(0, DAILY_LIMIT - currentDailyTotal);
    return res.status(400).json({ 
      error: `Дневной лимит exceeded. Ученик может получить ещё максимум ${remaining} баллов сегодня. (Лимит: ${DAILY_LIMIT} баллов/день)` 
    });
  }
  
  // Bot check - simple anti-cheat
  const recentAwards = dbAll(`
    SELECT COUNT(*) as count FROM grade_awards 
    WHERE teacher_id = ? AND student_id = ? AND datetime(created_at) > datetime('now', '-1 hour')
  `, [req.user.id, studentId]);
  
  const botApproved = (recentAwards[0]?.count || 0) < 5;
  
  if (!botApproved) {
    return res.status(400).json({ error: 'Подозрительная активность. Обратитесь к модератору.' });
  }
  
  // Record the award
  dbRun('INSERT INTO grade_awards (teacher_id, student_id, grade, points, approved_by_bot) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, studentId, grade, points, botApproved ? 1 : 0]
  );
  
  if (points > 0) {
    // Add points to student
    dbRun('UPDATE users SET balance = balance + ? WHERE id = ?', [points, studentId]);
    
    // Record transaction
    dbRun('INSERT INTO transactions (from_user_id, to_user_id, amount, reason, grade) VALUES (?, ?, ?, ?, ?)',
      [req.user.id, studentId, points, reason || `Оценка ${grade}`, grade]
    );
  }
  
  const newDailyTotal = currentDailyTotal + points;
  const remainingToday = DAILY_LIMIT - newDailyTotal;
  
  res.json({ 
    success: true, 
    points, 
    message: `Ученику ${student.username} начислено ${points} баллов за оценку ${grade}. Осталось на сегодня: ${remainingToday} баллов`,
    dailyTotal: newDailyTotal,
    remainingToday: remainingToday
  });
});

// Get all students (for teachers)
app.get('/api/students', auth, checkRole('teacher', 'moderator', 'owner'), (req, res) => {
  const students = dbAll('SELECT id, username, balance, class FROM users WHERE role = ?', ['student']);
  res.json(students);
});

// Search students by name or ID
app.get('/api/students/search', auth, (req, res) => {
  const query = req.query.q || '';
  
  if (query.length < 2) {
    return res.json([]);
  }
  
  const students = dbAll(`
    SELECT id, username, balance, class, title, profile_color
    FROM users 
    WHERE role = 'student' AND (username LIKE ? OR id = ?)
    ORDER BY balance DESC
    LIMIT 20
  `, [`%${query}%`, parseInt(query) || 0]);
  
  res.json(students);
});

// Get teacher's subject requests
app.get('/api/teacher/my-requests', auth, checkRole('teacher'), (req, res) => {
  const requests = dbAll(`
    SELECT r.id, r.student_id, r.type, r.status, r.cost, r.subject, r.media_url, r.media_type, r.created_at, 
           u.username as student_name, u.class as student_class
    FROM requests r 
    JOIN users u ON r.student_id = u.id
    WHERE r.subject = ? AND r.status = 'pending'
    ORDER BY r.created_at DESC
  `, [req.user.subject]);
  
  res.json(requests);
});

// ============ STUDENT ROUTES ============

// Request immunity from grade 2
app.post('/api/student/immunity', auth, checkRole('student'), (req, res) => {
  const { subject } = req.body;
  const cost = 50;
  
  if (!subject) {
    return res.status(400).json({ error: 'Выберите предмет' });
  }
  
  // Check if user has class and it's 5 or higher
  if (!req.user.class) {
    return res.status(403).json({ error: 'У вас не указан класс. Обратитесь к модератору.' });
  }
  
  const classNumber = parseInt(req.user.class);
  if (isNaN(classNumber) || classNumber < 5) {
    return res.status(403).json({ error: 'Доступно только для учеников с 5 класса' });
  }
  
  // Check if already used today
  const today = new Date().toISOString().split('T')[0];
  const existingRequest = dbGet(`
    SELECT id FROM requests 
    WHERE student_id = ? AND type = 'immunity' 
    AND date(created_at) = date(?)
  `, [req.user.id, today]);
  
  if (existingRequest) {
    return res.status(400).json({ error: 'Вы уже использовали переписывание работы сегодня. Попробуйте завтра.' });
  }
  
  if (req.user.balance < cost) {
    return res.status(400).json({ error: `Недостаточно баллов. Нужно: ${cost}, у вас: ${req.user.balance}` });
  }
  
  // Deduct points
  dbRun('UPDATE users SET balance = balance - ? WHERE id = ?', [cost, req.user.id]);
  
  // Create request for moderators
  const result = dbRun('INSERT INTO requests (student_id, type, cost, subject) VALUES (?, ?, ?, ?)',
    [req.user.id, 'immunity', cost, subject]
  );
  
  res.json({ 
    success: true, 
    message: `Запрос на переписывание работы по предмету "${subject}" отправлен модераторам`,
    requestId: result.lastInsertRowid
  });
});

// Request custom bell
app.post('/api/student/bell', auth, checkRole('student'), (req, res) => {
  const { mediaUrl, songName } = req.body;
  const cost = 40;
  
  if (!mediaUrl) {
    return res.status(400).json({ error: 'Укажите ссылку на песню' });
  }
  
  // Check if user has class and it's 5 or higher
  if (!req.user.class) {
    return res.status(403).json({ error: 'У вас не указан класс. Обратитесь к модератору.' });
  }
  
  const classNumber = parseInt(req.user.class);
  if (isNaN(classNumber) || classNumber < 5) {
    return res.status(403).json({ error: 'Доступно только для учеников с 5 класса' });
  }
  
  // Check if already used today
  const today = new Date().toISOString().split('T')[0];
  const existingRequest = dbGet(`
    SELECT id FROM requests 
    WHERE student_id = ? AND type = 'bell' 
    AND date(created_at) = date(?)
  `, [req.user.id, today]);
  
  if (existingRequest) {
    return res.status(400).json({ error: 'Вы уже заказывали песню сегодня. Попробуйте завтра.' });
  }
  
  if (req.user.balance < cost) {
    return res.status(400).json({ error: `Недостаточно баллов. Нужно: ${cost}, у вас: ${req.user.balance}` });
  }
  
  // Deduct points
  dbRun('UPDATE users SET balance = balance - ? WHERE id = ?', [cost, req.user.id]);
  
  // Create request for moderators (subject stores song name)
  const result = dbRun('INSERT INTO requests (student_id, type, cost, media_url, subject) VALUES (?, ?, ?, ?, ?)',
    [req.user.id, 'bell', cost, mediaUrl, songName || 'Песня']
  );
  
  res.json({ 
    success: true, 
    message: 'Запрос на песню на перемене отправлен модераторам',
    requestId: result.lastInsertRowid
  });
});

// Get student's balance and history
app.get('/api/student/balance', auth, checkRole('student'), (req, res) => {
  const transactions = dbAll(`
    SELECT t.id, t.from_user_id, t.to_user_id, t.amount, t.reason, t.grade, t.created_at, u.username as from_username 
    FROM transactions t 
    LEFT JOIN users u ON t.from_user_id = u.id 
    WHERE t.to_user_id = ?
    ORDER BY t.created_at DESC
  `, [req.user.id]);
  
  const requests = dbAll(`
    SELECT r.id, r.student_id, r.type, r.status, r.cost, r.subject, r.media_url, r.media_type, r.processed_by, r.created_at, r.processed_at, u.username as processed_by_name 
    FROM requests r 
    LEFT JOIN users u ON r.processed_by = u.id
    WHERE r.student_id = ?
    ORDER BY r.created_at DESC
  `, [req.user.id]);
  
  res.json({
    balance: req.user.balance,
    class: req.user.class,
    transactions,
    requests
  });
});

// ============ MODERATOR ROUTES ============

// Get all pending requests
app.get('/api/moderator/requests', auth, checkRole('moderator', 'owner'), (req, res) => {
  const requests = dbAll(`
    SELECT r.id, r.student_id, r.type, r.status, r.cost, r.subject, r.media_url, r.media_type, r.processed_by, r.created_at, r.processed_at, u.username as student_name, u.class as student_class
    FROM requests r 
    JOIN users u ON r.student_id = u.id
    WHERE r.status = 'pending'
    ORDER BY r.created_at DESC
  `);
  
  res.json(requests);
});

// Get all requests (including processed)
app.get('/api/moderator/requests/all', auth, checkRole('moderator', 'owner'), (req, res) => {
  const requests = dbAll(`
    SELECT r.id, r.student_id, r.type, r.status, r.cost, r.subject, r.media_url, r.media_type, r.processed_by, r.created_at, r.processed_at, u.username as student_name, u.class as student_class, u2.username as processed_by_name
    FROM requests r 
    JOIN users u ON r.student_id = u.id
    LEFT JOIN users u2 ON r.processed_by = u2.id
    ORDER BY r.created_at DESC
  `);
  
  res.json(requests);
});

// Approve/reject request
app.post('/api/moderator/requests/:id', auth, checkRole('moderator', 'owner'), (req, res) => {
  const { status } = req.body;
  const requestId = req.params.id;
  
  const request = dbGet('SELECT * FROM requests WHERE id = ?', [requestId]);
  if (!request) {
    return res.status(404).json({ error: 'Запрос не найден' });
  }
  
  if (request.status !== 'pending') {
    return res.status(400).json({ error: 'Запрос уже обработан' });
  }
  
  // Update request
  dbRun(`
    UPDATE requests 
    SET status = ?, processed_by = ?, processed_at = datetime('now')
    WHERE id = ?
  `, [status, req.user.id, requestId]);
  
  // If rejected, return points to student
  if (status === 'rejected') {
    dbRun('UPDATE users SET balance = balance + ? WHERE id = ?', [request.cost, request.student_id]);
  }
  
  res.json({ 
    success: true, 
    message: `Запрос ${status === 'approved' ? 'одобрен' : 'отклонён'}` 
  });
});

// Get all users
app.get('/api/moderator/users', auth, checkRole('moderator', 'owner'), (req, res) => {
  const users = dbAll('SELECT id, username, role, balance, class, subject, created_at FROM users ORDER BY created_at DESC');
  res.json(users);
});

// Add points to any user (moderators have infinite points)
app.post('/api/moderator/add-points', auth, checkRole('moderator', 'owner'), (req, res) => {
  const { userId, amount, reason } = req.body;
  
  const user = dbGet('SELECT * FROM users WHERE id = ?', [userId]);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }
  
  // Add points
  dbRun('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, userId]);
  
  // Record transaction
  dbRun('INSERT INTO transactions (from_user_id, to_user_id, amount, reason) VALUES (?, ?, ?, ?)',
    [req.user.id, userId, amount, reason || 'Начисление модератором']
  );
  
  res.json({ success: true, message: `Начислено ${amount} баллов пользователю ${user.username}` });
});

// Delete user
app.delete('/api/moderator/users/:id', auth, checkRole('owner'), (req, res) => {
  const userId = req.params.id;
  
  const user = dbGet('SELECT * FROM users WHERE id = ?', [userId]);
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }
  
  if (user.role === 'owner') {
    return res.status(403).json({ error: 'Нельзя удалить владельца' });
  }
  
  dbRun('DELETE FROM users WHERE id = ?', [userId]);
  
  res.json({ success: true, message: `Пользователь ${user.username} удалён` });
});

// ============ PROFILE ROUTES ============

// Update profile color
app.post('/api/student/profile/color', auth, checkRole('student'), (req, res) => {
  const { color } = req.body;
  
  if (!color || !/^#[0-9A-Fa-f]{6}$/.test(color)) {
    return res.status(400).json({ error: 'Неверный формат цвета' });
  }
  
  dbRun('UPDATE users SET profile_color = ? WHERE id = ?', [color, req.user.id]);
  
  res.json({ success: true, message: 'Цвет профиля обновлен' });
});

// Set user title (moderator only)
app.post('/api/moderator/set-title', auth, checkRole('moderator', 'owner'), (req, res) => {
  try {
    const { userId, title } = req.body;
    
    const user = dbGet('SELECT * FROM users WHERE id = ?', [userId]);
    if (!user) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    dbRun('UPDATE users SET title = ? WHERE id = ?', [title || null, userId]);
    
    // Also grant the title to user's available titles
    const titleRecord = dbGet('SELECT id FROM titles WHERE name = ?', [title]);
    if (titleRecord) {
      try {
        dbRun('INSERT INTO user_titles (user_id, title_id) VALUES (?, ?)', [userId, titleRecord.id]);
      } catch (e) {
        // Already has this title
      }
    }
    
    res.json({ success: true, message: `Титул "${title}" установлен для ${user.username}` });
  } catch (err) {
    console.error('Error in /api/moderator/set-title:', err);
    res.status(500).json({ error: 'Ошибка при установке титула' });
  }
});

// Get all available titles
app.get('/api/titles', auth, (req, res) => {
  const titles = dbAll('SELECT * FROM titles ORDER BY created_at DESC');
  res.json(titles);
});

// Get user's earned titles
app.get('/api/student/titles', auth, checkRole('student'), (req, res) => {
  const titles = dbAll(`
    SELECT t.*, ut.earned_at 
    FROM titles t 
    JOIN user_titles ut ON t.id = ut.title_id 
    WHERE ut.user_id = ?
    ORDER BY ut.earned_at DESC
  `, [req.user.id]);
  
  res.json(titles);
});

// Set student's active title
app.post('/api/student/title', auth, checkRole('student'), (req, res) => {
  const { titleName } = req.body;
  
  if (!titleName) {
    dbRun('UPDATE users SET title = NULL WHERE id = ?', [req.user.id]);
    return res.json({ success: true, message: 'Титул снят' });
  }
  
  // Check if user has this title
  const userTitle = dbGet(`
    SELECT t.* 
    FROM titles t 
    JOIN user_titles ut ON t.id = ut.title_id 
    WHERE ut.user_id = ? AND t.name = ?
  `, [req.user.id, titleName]);
  
  if (!userTitle) {
    return res.status(403).json({ error: 'У вас нет этого титула' });
  }
  
  dbRun('UPDATE users SET title = ? WHERE id = ?', [titleName, req.user.id]);
  
  res.json({ success: true, message: `Титул "${titleName}" установлен` });
});

// Grant title to user (moderator gives title permanently)
app.post('/api/moderator/grant-title', auth, checkRole('moderator', 'owner'), (req, res) => {
  const { userId, titleName } = req.body;
  
  try {
    // Create title if not exists
    dbRun('INSERT OR IGNORE INTO titles (name, icon) VALUES (?, ?)', [titleName, '🏆']);
    
    const titleRecord = dbGet('SELECT id FROM titles WHERE name = ?', [titleName]);
    
    if (!titleRecord) {
      return res.status(500).json({ error: 'Ошибка создания титула' });
    }
    
    // Grant title to user
    try {
      dbRun('INSERT INTO user_titles (user_id, title_id) VALUES (?, ?)', [userId, titleRecord.id]);
    } catch (e) {
      // Already has this title
    }
    
    // Set as active title
    dbRun('UPDATE users SET title = ? WHERE id = ?', [titleName, userId]);
    
    const user = dbGet('SELECT username FROM users WHERE id = ?', [userId]);
    
    res.json({ success: true, message: `Титул "${titleName}" выдан пользователю ${user?.username}` });
  } catch (err) {
    console.error('Error granting title:', err);
    res.status(500).json({ error: 'Ошибка при выдаче титула' });
  }
});

// Get all available badges
app.get('/api/badges', auth, (req, res) => {
  const badges = dbAll('SELECT * FROM badges ORDER BY created_at DESC');
  res.json(badges);
});

// Get user's earned badges
app.get('/api/student/badges', auth, checkRole('student'), (req, res) => {
  const badges = dbAll(`
    SELECT b.*, ub.earned_at 
    FROM badges b 
    JOIN user_badges ub ON b.id = ub.badge_id 
    WHERE ub.user_id = ?
    ORDER BY ub.earned_at DESC
  `, [req.user.id]);
  
  res.json(badges);
});

// Get leaderboard (top students)
app.get('/api/leaderboard', auth, (req, res) => {
  const leaderboard = dbAll(`
    SELECT id, username, balance, class, title, profile_color
    FROM users 
    WHERE role = 'student' 
    ORDER BY balance DESC 
    LIMIT 100
  `);
  
  res.json(leaderboard);
});

// Get user's rank in leaderboard
app.get('/api/student/rank', auth, checkRole('student'), (req, res) => {
  const result = dbGet(`
    SELECT COUNT(*) + 1 as rank
    FROM users
    WHERE role = 'student' AND balance > ?
  `, [req.user.balance]);
  
  res.json({ rank: result?.rank || 1, balance: req.user.balance });
});

// Get monthly leader
app.get('/api/leaderboard/monthly', auth, (req, res) => {
  try {
    const now = new Date();
    const currentMonth = now.getMonth() + 1;
    const currentYear = now.getFullYear();
    
    // Get all students with their balances
    const students = dbAll(`
      SELECT id, username, balance, class, title
      FROM users 
      WHERE role = 'student' 
      ORDER BY balance DESC 
      LIMIT 1
    `);
    
    if (students.length > 0) {
      res.json({ leader: students[0], month: currentMonth, year: currentYear });
    } else {
      res.json({ leader: null, month: currentMonth, year: currentYear });
    }
  } catch (err) {
    console.error('Error in /api/leaderboard/monthly:', err);
    res.status(500).json({ error: 'Ошибка при получении лидера месяца' });
  }
});

// Get user profile by ID
app.get('/api/user/:id', auth, (req, res) => {
  const user = dbGet(`
    SELECT id, username, role, balance, class, subject, profile_color, title, created_at
    FROM users 
    WHERE id = ?
  `, [req.params.id]);
  
  if (!user) {
    return res.status(404).json({ error: 'Пользователь не найден' });
  }
  
  // Get user badges
  const badges = dbAll(`
    SELECT b.*, ub.earned_at 
    FROM badges b 
    JOIN user_badges ub ON b.id = ub.badge_id 
    WHERE ub.user_id = ?
    ORDER BY ub.earned_at DESC
  `, [user.id]);
  
  // Get user titles
  const titles = dbAll(`
    SELECT t.*, ut.earned_at 
    FROM titles t 
    JOIN user_titles ut ON t.id = ut.title_id 
    WHERE ut.user_id = ?
    ORDER BY ut.earned_at DESC
  `, [user.id]);
  
  res.json({ ...user, badges, titles });
});

// ============ STATS ROUTES ============

app.get('/api/stats', auth, (req, res) => {
  const totalStudents = dbGet("SELECT COUNT(*) as count FROM users WHERE role = 'student'").count || 0;
  const totalTeachers = dbGet("SELECT COUNT(*) as count FROM users WHERE role = 'teacher'").count || 0;
  const totalModerators = dbGet("SELECT COUNT(*) as count FROM users WHERE role = 'moderator'").count || 0;
  const totalResult = dbGet("SELECT COALESCE(SUM(amount), 0) as total FROM transactions");
  const totalPointsAwarded = totalResult?.total || 0;
  const pendingResult = dbGet("SELECT COUNT(*) as count FROM requests WHERE status = 'pending'");
  const pendingRequests = pendingResult?.count || 0;
  
  const stats = {
    totalStudents,
    totalTeachers,
    totalModerators,
    totalPointsAwarded,
    pendingRequests
  };
  
  res.json(stats);
});

// Initialize database and start server
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`🚀 Сервер запущен на http://localhost:${PORT}`);
    console.log(`📚 Школьная система баллов готова к работе!`);
  });
}).catch(err => {
  console.error('Ошибка инициализации базы данных:', err);
  process.exit(1);
});
