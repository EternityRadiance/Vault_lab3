async function api(path, body) {
    const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(body),
    });
    return response.json();
}

async function apiGet(path) {
    const response = await fetch(path, { credentials: 'include' });
    return { status: response.status, data: await response.json() };
}

function show(id) {
    ['register-section', 'login-section', 'profile-section'].forEach(sid => {
        document.getElementById(sid).classList.toggle('hidden', sid !== id);
    });
    document.getElementById('logout-btn').classList.toggle('hidden', id !== 'profile-section');
}

function showError(id, msg) {
    const el = document.getElementById(id);
    el.textContent = msg;
    el.classList.remove('hidden');
}

function hideError(id) {
    document.getElementById(id).classList.add('hidden');
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

async function handleLogout() {
    await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
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

document.addEventListener('DOMContentLoaded', async () => {
    document.getElementById('register-form').addEventListener('submit', handleRegister);
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
    document.getElementById('reload-profile-btn').addEventListener('click', loadProfile);
    document.getElementById('to-login').addEventListener('click', switchToLogin);
    document.getElementById('to-register').addEventListener('click', switchToRegister);

    const { status } = await apiGet('/auth/me');
    if (status === 200) {
        await loadProfile();
    } else {
        show('register-section');
    }
});