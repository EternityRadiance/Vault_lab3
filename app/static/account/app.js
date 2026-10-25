const TOKEN_KEY = 'vault_account_token';

async function api(path, body) {
    const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    return response.json();
}

async function apiGet(path) {
    const token = localStorage.getItem(TOKEN_KEY);
    const headers = {};
    if (token) headers['Authorization'] = 'Bearer ' + token;

    const response = await fetch(path, { headers });
    return { status: response.status, data: await response.json() };
}

function show(id) {
    ['register-section', 'login-section', 'profile-section'].forEach(sid => {
        document.getElementById(sid).classList.toggle('hidden', sid !== id);
    });
    document.getElementById('logout-btn').classList.toggle('hidden', id !== 'profile-section');
}

function showError(elementId, message) {
    const el = document.getElementById(elementId);
    el.textContent = message;
    el.classList.remove('hidden');
}

function hideError(elementId) {
    document.getElementById(elementId).classList.add('hidden');
}

async function handleRegister(event) {
    event.preventDefault();
    hideError('register-error');

    const email = document.getElementById('register-email').value.trim();
    const password = document.getElementById('register-password').value;

    try {
        const data = await api('/auth/register', { email, password });

        if (!data.access_token) {
            showError('register-error', data.detail || 'Ошибка регистрации');
            return;
        }

        localStorage.setItem(TOKEN_KEY, data.access_token);
        document.getElementById('register-email').value = '';
        document.getElementById('register-password').value = '';

        await loadProfile();
    } catch (err) {
        showError('register-error', 'Сеть недоступна: ' + err.message);
    }
}

async function handleLogin(event) {
    event.preventDefault();
    hideError('login-error');

    const email = document.getElementById('login-email').value.trim();
    const password = document.getElementById('login-password').value;

    try {
        const data = await api('/auth/login', { email, password });

        if (!data.access_token) {
            showError('login-error', data.detail || 'Ошибка входа');
            return;
        }

        localStorage.setItem(TOKEN_KEY, data.access_token);
        document.getElementById('login-email').value = '';
        document.getElementById('login-password').value = '';

        await loadProfile();
    } catch (err) {
        showError('login-error', 'Сеть недоступна: ' + err.message);
    }
}

async function loadProfile() {
    hideError('profile-error');
    const output = document.getElementById('profile-output');
    output.textContent = 'Загрузка...';

    const { status, data } = await apiGet('/auth/me');

    if (status === 401) {
        localStorage.removeItem(TOKEN_KEY);
        show('login-section');
        return;
    }

    if (!data.email) {
        showError('profile-error', JSON.stringify(data));
        return;
    }

    output.textContent = JSON.stringify(data, null, 2);
    show('profile-section');
}

function handleLogout() {
    localStorage.removeItem(TOKEN_KEY);
    show('login-section');
}

function switchToLogin(event) {
    event.preventDefault();
    hideError('register-error');
    show('login-section');
}

function switchToRegister(event) {
    event.preventDefault();
    hideError('login-error');
    show('register-section');
}

document.addEventListener('DOMContentLoaded', () => {
    // Обработчики
    document.getElementById('register-form').addEventListener('submit', handleRegister);
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
    document.getElementById('reload-profile-btn').addEventListener('click', loadProfile);
    document.getElementById('to-login').addEventListener('click', switchToLogin);
    document.getElementById('to-register').addEventListener('click', switchToRegister);

    const token = localStorage.getItem(TOKEN_KEY);
    if (token) {
        loadProfile();
    } else {
        show('register-section');
    }
});