const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] }
});

// База данных
const db = new sqlite3.Database('./database.sqlite');

// Создание таблиц
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        public_key TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        from_user TEXT,
        to_user TEXT,
        encrypted_content TEXT,
        iv TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
});

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Регистрация
app.post('/api/register', async (req, res) => {
    const { username, password, publicKey } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Все поля обязательны' });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run(
            'INSERT INTO users (username, password, public_key) VALUES (?, ?, ?)',
            [username, hashedPassword, publicKey],
            function(err) {
                if (err) {
                    if (err.message.includes('UNIQUE')) {
                        return res.status(400).json({ error: 'Имя пользователя уже занято' });
                    }
                    return res.status(500).json({ error: 'Ошибка сервера' });
                }
                res.json({ success: true, userId: this.lastID });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Логин
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
            return res.status(401).json({ error: 'Неверные учетные данные' });
        }
        
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(401).json({ error: 'Неверные учетные данные' });
        }
        
        res.json({
            success: true,
            user: {
                id: user.id,
                username: user.username,
                publicKey: user.public_key
            }
        });
    });
});

// Получить список пользователей (кроме себя)
app.get('/api/users/:username', (req, res) => {
    const currentUser = req.params.username;
    
    db.all('SELECT username FROM users WHERE username != ?', [currentUser], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.json(rows);
    });
});

// Получить историю сообщений между двумя пользователями
app.get('/api/messages/:user1/:user2', (req, res) => {
    const { user1, user2 } = req.params;
    
    db.all(
        `SELECT * FROM messages 
         WHERE (from_user = ? AND to_user = ?) 
         OR (from_user = ? AND to_user = ?)
         ORDER BY timestamp ASC`,
        [user1, user2, user2, user1],
        (err, rows) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            res.json(rows);
        }
    );
});

// WebSocket для реального времени
io.on('connection', (socket) => {
    let currentUser = null;
    
    socket.on('register-user', (username) => {
        currentUser = username;
        socket.join(`user-${username}`);
        console.log(`✅ Пользователь ${username} онлайн`);
        
        // Оповещаем всех о смене статуса
        io.emit('user-online', username);
    });
    
    socket.on('private-message', (data) => {
        // data = { to, encryptedContent, iv, from }
        const { to, encryptedContent, iv, from } = data;
        
        // Сохраняем в БД
        db.run(
            'INSERT INTO messages (from_user, to_user, encrypted_content, iv) VALUES (?, ?, ?, ?)',
            [from, to, encryptedContent, iv],
            (err) => {
                if (!err) {
                    // Отправляем получателю, если он онлайн
                    io.to(`user-${to}`).emit('new-message', {
                        from,
                        encryptedContent,
                        iv,
                        timestamp: new Date().toISOString()
                    });
                    
                    // Подтверждение отправителю
                    socket.emit('message-sent', { to, status: 'delivered' });
                }
            }
        );
    });
    
    socket.on('disconnect', () => {
        if (currentUser) {
            console.log(`❌ Пользователь ${currentUser} офлайн`);
            io.emit('user-offline', currentUser);
        }
    });
});

// Запуск сервера
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🚀 Сервер запущен на http://localhost:${PORT}`);
    console.log(`🔒 Мессенджер с E2EE шифрованием`);
});
