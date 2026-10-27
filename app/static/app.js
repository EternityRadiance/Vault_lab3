async function api(path, body) {
    const response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(body),
    });
    return response.json();
}

function getCsrfToken() {
    const match = document.cookie.split('; ').find(c => c.startsWith('vault_csrf='));
    return match ? match.split('=')[1] : '';
}

async function gql(query, variables = {}) {
    const headers = {
        'Content-Type': 'application/json',
        'X-CSRF-Token': getCsrfToken(),
    };
    const response = await fetch('/graphql/', {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({ query, variables }),
    });
    return response.json();
}

async function renderAuthState() {
    try {
        const resp = await fetch('/auth/me', { credentials: 'include' });
        if (resp.ok) {
            document.getElementById('login-section').classList.add('hidden');
            document.getElementById('admin-section').classList.remove('hidden');
            document.getElementById('logout-btn').classList.remove('hidden');
            return;
        }
    } catch {}
    document.getElementById('login-section').classList.remove('hidden');
    document.getElementById('admin-section').classList.add('hidden');
    document.getElementById('logout-btn').classList.add('hidden');
}

function showError(elementId, message) {
    const el = document.getElementById(elementId);
    el.textContent = message;
    el.classList.remove('hidden');
}

function hideError(elementId) {
    document.getElementById(elementId).classList.add('hidden');
}

function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;');
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
        await renderAuthState();
        await loadClients();
    } catch (err) {
        showError('login-error', 'Сеть недоступна: ' + err.message);
    }
}

async function handleLogout() {
    await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
    document.getElementById('clients-tbody').innerHTML = '';
    document.getElementById('users-tbody').innerHTML = '';
    document.getElementById('users-table').classList.add('hidden');
    document.getElementById('profile-output').classList.add('hidden');
    await renderAuthState();
}

async function loadClients() {
    hideError('clients-error');
    const result = await gql(`query { clients { id clientId name isConfidential redirectUris scopes grantTypes isActive createdAt } }`);

    if (result.errors) {
        const msg = result.errors.map(e => e.message).join('; ');
        showError('clients-error', msg);
        if (msg.includes('Authentication') || msg.includes('Admin')) await handleLogout();
        return;
    }

    const clients = result.data.clients;
    const tbody = document.getElementById('clients-tbody');
    tbody.innerHTML = '';

    if (clients.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:#6c757d;">Пока нет клиентов</td></tr>';
        return;
    }

    for (const c of clients) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${escapeHtml(c.id)}</td>
            <td><code>${escapeHtml(c.clientId)}</code></td>
            <td>${escapeHtml(c.name)}</td>
            <td>${c.isConfidential ? 'да' : 'нет'}</td>
            <td>${escapeHtml((c.redirectUris || []).join(', ')) || '<em>—</em>'}</td>
            <td>${escapeHtml(JSON.stringify(c.scopes))}</td>
            <td>${escapeHtml(JSON.stringify(c.grantTypes))}</td>
            <td>${c.isActive ? 'да' : 'нет'}</td>
        `;
        tbody.appendChild(tr);
    }
}

async function handleCreateClient() {
    const name = prompt('Название клиента:');
    if (!name) return;
    const result = await gql(`mutation CreateClient($name: String!) { createClient(name: $name, isConfidential: true) { clientId clientSecret } }`, { name });

    if (result.errors) {
        alert('Ошибка: ' + result.errors.map(e => e.message).join('; '));
        return;
    }

    const c = result.data.createClient;
    let msg = `Клиент создан.\n\nВнутренний ID: ${c.clientId}`;
    if (c.clientSecret) msg += `\n\nClient Secret (сохрани — показывается один раз):\n${c.clientSecret}`;
    else msg += `\n\nПубличный клиент — client_secret не создаётся.`;
    alert(msg);
    await loadClients();
}

async function loadProfile() {
    const output = document.getElementById('profile-output');
    output.textContent = 'Загрузка...';
    output.classList.remove('hidden');
    const result = await gql(`{ me { id email isActive isAdmin createdAt } }`);

    if (result.errors) {
        output.textContent = result.errors.map(e => e.message).join('\n');
        return;
    }
    output.textContent = JSON.stringify(result.data.me, null, 2);
}

async function loadUsers() {
    hideError('users-error');
    const table = document.getElementById('users-table');
    const tbody = document.getElementById('users-tbody');
    tbody.innerHTML = '';
    table.classList.remove('hidden');

    const result = await gql(`{ users { id email isActive isAdmin createdAt } }`);

    if (result.errors) {
        showError('users-error', result.errors.map(e => e.message).join('; '));
        table.classList.add('hidden');
        return;
    }

    for (const u of result.data.users) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${escapeHtml(u.id)}</td>
            <td>${escapeHtml(u.email)}</td>
            <td>${u.isAdmin ? 'да' : 'нет'}</td>
            <td>${u.isActive ? 'да' : 'нет'}</td>
            <td>${escapeHtml(u.createdAt)}</td>
            <td>${u.isActive ? `<button data-disable-id="${escapeHtml(u.id)}" data-disable-email="${escapeHtml(u.email)}">Отключить</button>` : '<em>отключён</em>'}</td>
        `;
        tbody.appendChild(tr);
    }

    tbody.querySelectorAll('button[data-disable-id]').forEach(btn => {
        btn.addEventListener('click', async () => {
            if (!confirm(`Отключить пользователя ${btn.dataset.disableEmail}?`)) return;
            await disableUser(btn.dataset.disableId);
        });
    });
}

async function disableUser(userId) {
    hideError('users-error');
    const result = await gql(`mutation DisableUser($id: ID!) { disableUser(userId: $id) { id email isActive } }`, { id: userId });
    if (result.errors) {
        showError('users-error', result.errors.map(e => e.message).join('; '));
        return;
    }
    await loadUsers();
}

document.addEventListener('DOMContentLoaded', async () => {
    await renderAuthState();
    document.getElementById('login-form').addEventListener('submit', handleLogin);
    document.getElementById('logout-btn').addEventListener('click', handleLogout);
    document.getElementById('create-client-btn').addEventListener('click', handleCreateClient);
    document.getElementById('load-profile-btn').addEventListener('click', loadProfile);
    document.getElementById('load-users-btn').addEventListener('click', loadUsers);

    if (!document.getElementById('admin-section').classList.contains('hidden')) {
        await loadClients();
    }
});