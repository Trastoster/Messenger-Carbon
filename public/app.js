// Глобальное состояние
let currentUser = null;
let activeChat = null;
let socket = null;
let usersList = [];

// Криптографические функции (AES-GCM)
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        encoder.encode(password),
        'PBKDF2',
        false,
        ['deriveKey']
    );
    
    return window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptMessage(message, password, salt) {
    const encoder = new TextEncoder();
    const key = await deriveKey(password, salt);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    
    const encrypted = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        encoder.encode(message)
    );
    
    return {
        encrypted: Array.from(new Uint8Array(encrypted)),
        iv: Array.from(iv),
        salt: Array.from(salt)
    };
}

async function decryptMessage(encryptedData, password) {
    const decoder = new TextDecoder();
    const key = await deriveKey(password, new Uint8Array(encryptedData.salt));
    
    const decrypted = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: new Uint8Array(encryptedData.iv) },
        key,
        new Uint8Array(encryptedData.encrypted)
    );
    
    return decoder.decode(decrypted);
}

// Генерация ключа из пароля (для шифрования сообщений)
function generateChatKey(password) {
    // Используем пароль как основу для шифрования
    // В реальном сценарии лучше использовать обмен ключами Diffie-Hellman
    return password;
}

// Регистрация
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('regUsername').value;
    const password = document.getElementById('regPassword').value;
    const confirm = document.getElementById('regConfirmPassword').value;
    
    if (password !== confirm) {
        document.getElementById('regError').textContent = 'Пароли не совпадают';
        return;
    }
    
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password, publicKey: '' })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert('Регистрация успешна! Теперь войдите');
            document.querySelector('[data-tab="login"]').click();
        } else {
            document.getElementById('regError').textContent = data.error;
        }
    } catch (error) {
        document.getElementById('regError').textContent = 'Ошибка соединения';
    }
});

// Вход
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            currentUser = data.user;
            currentUser.password = password; // Сохраняем пароль для расшифровки
            
            // Подключаем WebSocket
            connectWebSocket();
            
            // Загружаем список пользователей
            await loadUsers();
            
            // Показываем интерфейс мессенджера
            document.getElementById('authScreen').style.display = 'none';
            document.getElementById('messengerScreen').style.display = 'flex';
            document.getElementById('currentUsername').textContent = currentUser.username;
        } else {
            document.getElementById('loginError').textContent = data.error;
        }
    } catch (error) {
        document.getElementById('loginError').textContent = 'Ошибка соединения';
    }
});

// Подключение WebSocket
function connectWebSocket() {
    socket = io();
    
    socket.on('connect', () => {
        socket.emit('register-user', currentUser.username);
    });
    
    socket.on('new-message', async (data) => {
        // Расшифровываем сообщение
        try {
            const decrypted = await decryptMessage(
                {
                    encrypted: data.encryptedContent,
                    iv: data.iv,
                    salt: new Uint8Array(32) // В реальном сценарии salt должен передаваться
                },
                currentUser.password
            );
            
            // Показываем сообщение, если чат с этим пользователем открыт
            if (activeChat === data.from) {
                displayMessage(data.from, decrypted, false);
            }
            
            // Обновляем список чатов (добавляем индикатор непрочитанного)
            updateChatList(data.from);
        } catch (error) {
            console.error('Ошибка расшифровки:', error);
        }
    });
    
    socket.on('user-online', (username) => {
        updateUserStatus(username, true);
    });
    
    socket.on('user-offline', (username) => {
        updateUserStatus(username, false);
    });
}

// Загрузка списка пользователей
async function loadUsers() {
    const response = await fetch(`/api/users/${currentUser.username}`);
    usersList = await response.json();
    
    const usersListDiv = document.getElementById('usersList');
    usersListDiv.innerHTML = usersList.map(user => `
        <div class="user-item" data-username="${user.username}">
            <div class="user-status"></div>
            <span>${user.username}</span>
        </div>
    `).join('');
    
    // Добавляем обработчики кликов
    document.querySelectorAll('.user-item').forEach(el => {
        el.addEventListener('click', () => {
            const username = el.dataset.username;
            openChat(username);
        });
    });
}

// Открытие чата с пользователем
async function openChat(username) {
    activeChat = username;
    
    // Обновляем UI
    document.querySelectorAll('.user-item').forEach(el => {
        el.classList.remove('active');
        if (el.dataset.username === username) {
            el.classList.add('active');
        }
    });
    
    document.getElementById('chatHeader').innerHTML = `<div class="chat-user">${username}</div>`;
    document.querySelector('.message-input-area').style.display = 'flex';
    
    // Загружаем историю сообщений
    const response = await fetch(`/api/messages/${currentUser.username}/${username}`);
    const messages = await response.json();
    
    const container = document.getElementById('messagesContainer');
    container.innerHTML = '';
    
    for (const msg of messages) {
        try {
            const decrypted = await decryptMessage(
                {
                    encrypted: msg.encrypted_content,
                    iv: msg.iv,
                    salt: new Uint8Array(32)
                },
                currentUser.password
            );
            
            const isOutgoing = msg.from_user === currentUser.username;
            displayMessage(msg.from_user, decrypted, isOutgoing);
        } catch (error) {
            console.error('Ошибка расшифровки истории:', error);
        }
    }
}

// Отображение сообщения
function displayMessage(from, text, isOutgoing) {
    const container = document.getElementById('messagesContainer');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${isOutgoing ? 'outgoing' : 'incoming'}`;
    messageDiv.innerHTML = `
        <div>${escapeHtml(text)}</div>
        <div class="message-info">${isOutgoing ? 'Вы' : from} • ${new Date().toLocaleTimeString()}</div>
    `;
    container.appendChild(messageDiv);
    container.scrollTop = container.scrollHeight;
}

// Отправка сообщения
document.getElementById('sendBtn').addEventListener('click', async () => {
    if (!activeChat) return;
    
    const input = document.getElementById('messageInput');
    const text = input.value.trim();
    if (!text) return;
    
    // Шифруем сообщение
    const salt = window.crypto.getRandomValues(new Uint8Array(32));
    const encrypted = await encryptMessage(text, currentUser.password, salt);
    
    // Отправляем на сервер
    socket.emit('private-message', {
        to: activeChat,
        from: currentUser.username,
        encryptedContent: encrypted.encrypted,
        iv: encrypted.iv
    });
    
    // Показываем у себя
    displayMessage(currentUser.username, text, true);
    
    input.value = '';
});

// Обновление статуса пользователя
function updateUserStatus(username, isOnline) {
    const userItem = document.querySelector(`.user-item[data-username="${username}"]`);
    if (userItem) {
        const statusDiv = userItem.querySelector('.user-status');
        if (isOnline) {
            statusDiv.classList.add('online');
        } else {
            statusDiv.classList.remove('online');
        }
    }
}

function updateChatList(from) {
    // Просто подсвечиваем, что есть новое сообщение
    const userItem = document.querySelector(`.user-item[data-username="${from}"]`);
    if (userItem && activeChat !== from) {
        userItem.style.fontWeight = 'bold';
    }
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Выход
document.getElementById('logoutBtn').addEventListener('click', () => {
    if (socket) {
        socket.disconnect();
    }
    currentUser = null;
    activeChat = null;
    document.getElementById('authScreen').style.display = 'flex';
    document.getElementById('messengerScreen').style.display = 'none';
    document.getElementById('loginUsername').value = '';
    document.getElementById('loginPassword').value = '';
});

// Переключение табов
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        
        document.querySelectorAll('.auth-form').forEach(form => form.classList.remove('active'));
        document.getElementById(`${tab}Form`).classList.add('active');
    });
});
