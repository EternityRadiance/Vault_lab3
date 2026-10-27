# Vault - инструкция по использованию OAuth2/OIDC

## Подготовка
Сервер запущен:

```bash
python run.py
```

Проверка:

```bash
curl -s http://127.0.0.1:8000/health
# {"status":"ok","app":"Vault"}
```

Redis запущен:

```bash
docker exec vault-redis redis-cli ping
# PONG
```

## Назначение админа
Если admin@example.com не админ:

```bash
python scripts/make_admin.py admin@example.com
```

## Регистрация OAuth-клиента
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

Запомни clientID (внутренний) и clientSecret - они показываются один раз.

client_id (hex) - возьми из БД:

```bash
PGPASSWORD=<password> psql -h 127.0.0.1 -U vault -d vault_db \
  -c "SELECT id, client_id, name FROM oauth_clients WHERE name = 'My App';"
```

## Grant 'password'

Прямой обмен 'username' + 'password' на токены.

```bash
curl -s -X POST "http://127.0.0.1:8000/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=password" \
  --data-urlencode "client_id=<client_id hex>" \
  --data-urlencode "client_secret=<client_secret>" \
  --data-urlencode "username=oauth-test@example.com" \
  --data-urlencode "password=some long password 12345" \
  --data-urlencode "scope=openid email" \
  | python -m json.tool
```
Ответ: access_token, refresh_token, id_token, expires_in, token_type, scope.

## Grant client_credentials

Только для конфиденциальных клиентов. Без refresh, без id_token.

```bash
curl -s -X POST "http://127.0.0.1:8000/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=<hex>" \
  --data-urlencode "client_secret=<secret>" \
  --data-urlencode "scope=openid" \
  | python -m json.tool
```

sub = client_id (не user.id).

## Grant `authorization_code` (с PKCE)

### Шаг 1 — получить `code`

```bash
USER_TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"oauth-test@example.com","password":"some long password 12345"}' \
  | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

RESP=$(curl -s -i "http://127.0.0.1:8000/oauth/authorize?response_type=code&client_id=<hex>&redirect_uri=http://localhost/cb&scope=openid%20email&state=xyz&code_challenge=${CHALLENGE}&code_challenge_method=S256" \
  -H "Authorization: Bearer ${USER_TOKEN}")

CODE=$(echo "$RESP" | grep -i "^location:" | sed 's/.*code=\([^&]*\).*/\1/' | tr -d '\r\n ')
echo "CODE: $CODE"
```

### Шаг 2 — обменять code на токены

```bash
curl -s -X POST "http://127.0.0.1:8000/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "client_id=<hex>" \
  --data-urlencode "code=${CODE}" \
  --data-urlencode "redirect_uri=http://localhost/cb" \
  --data-urlencode "code_verifier=${VERIFIER}" \
  | python -m json.tool
```

Повторный обмен с тем же code выдаст 400 invalid_grant + аудит auth_code.reuse_detected.

Неверный code_verifier выдаст 400 PKCE verification failed.

## Grant refresh_token (rotation)

```bash
RT1="<refresh_token из предыдущего ответа>"

RESP=$(curl -s -X POST "http://127.0.0.1:8000/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "client_id=<hex>" \
  --data-urlencode "client_secret=<secret>" \
  --data-urlencode "refresh_token=${RT1}")

echo "$RESP" | python -m json.tool

RT2=$(echo "$RESP" | python -c "import sys,json; print(json.load(sys.stdin)['refresh_token'])")
```

Reuse RT1 выдаст 400 refresh_token has already been used + отзыв всего семейства (RT1 и RT2). Аудит: token.reuse_detected.

Попытка RT2 после reuse -> 400 has been revoked.

## Отзыв и интроспекция

### `/oauth/revoke`

```bash
curl -s -X POST "http://127.0.0.1:8000/oauth/revoke" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=<access_token>" \
  --data-urlencode "token_type_hint=access_token" \
  --data-urlencode "client_id=<hex>" \
  --data-urlencode "client_secret=<secret>"
```

Всегда 200 {}. Для access - jti в Redis blacklist. Для refresh - revoked_at в БД + UserSession.

### '/oauth/introspect'

```bash
curl -s -X POST "http://127.0.0.1:8000/oauth/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=<access_token>" \
  --data-urlencode "token_type_hint=access_token" \
  --data-urlencode "client_id=<hex>" \
  --data-urlencode "client_secret=<secret>" \
  | python -m json.tool
```

Активный токен: {"active": true, "sub": "...", "scope": "...", ...}.

После revoke: {"active": false}.

### OIDC '/oauth/userinfo'

```bash
curl -s "http://127.0.0.1:8000/oauth/userinfo" \
  -H "Authorization: Bearer <access_token>" \
  | python -m json.tool
```

1) scope openid: {"sub": "..."}.

2) scope openid email: + "email", "email_verified".

3) scope openid email profile: + "name", "preferred_username", "updated_at".

4) Отозванный токен: 401 Token has been revoked.

5) client_credentials токен: 401 Token is not associated with a user.

## JWKS и Discovery

```bash
curl -s http://127.0.0.1:8000/.well-known/openid-configuration | python -m json.tool
curl -s http://127.0.0.1:8000/.well-known/jwks.json | python -m json.tool
```
