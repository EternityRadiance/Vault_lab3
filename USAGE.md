# Vault - инструкция по использованию OAuth2/OIDC

## Подготовка
Сервер запущени `python run.py` (порт 8000).

Redis запущен: `docker exec vault-redis redis-cli ping` -> `PONG`.

## Регистрация клиента
Через GraphQL (нужен токен админа):

```bash
ADMIN_TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com","password":"Very strong admin password"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST "http://127.0.0.1:8000/graphql/" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -d '{"query":"mutation { createClient(name: \"My App\", isConfidential: true, scopes: [\"openid\", \"email\"], grantTypes: [\"authorization_code\", \"refresh_token\", \"password\"], redirectUris: [\"http://localhost/cb\"]) { clientId clientSecret } }"}' \
  | python -m json.tool
```

Запомни clientId (внутренний) и clientSecret.

```bash
sqlite3 -header -column vault.db \
  "SELECT id, client_id, name FROM oauth_clients WHERE name = 'My App';"
```

client_id (hex) - из БД.
