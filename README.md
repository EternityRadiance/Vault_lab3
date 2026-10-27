# Vault — OAuth2/OIDC Provider

Сервис управления пользователями и OAuth-клиентами. Реализует **OAuth2 (RFC 6749)** и **OpenID Connect** с поддержкой:

- RS256-подписи JWT и публикацией **JWKS**.
- Grant-типов `authorization_code` (с **PKCE S256**), `refresh_token` (с **rotation** и детекцией reuse), `password`, `client_credentials`.
- OIDC: `id_token`, `/oauth/userinfo`, `/.well-known/openid-configuration`.
- Отзыва токенов (`/oauth/revoke`, RFC 7009) и интроспекции (`/oauth/introspect`, RFC 7662) с Redis blacklist.
- GraphQL API для админки: сессии, refresh-токены, ротация секретов клиентов.

## Стек

- **FastAPI** — веб-фреймворк.
- **Ariadne** — schema-first GraphQL.
- **SQLAlchemy 2.x** — ORM.
- **Alembic** — миграции.
- **PostgreSQL** — БД (SQLite для тестов).
- **Redis** — blacklist access-токенов.
- **cryptography** — RSA-ключи, RS256.
- **python-jose** — JWT.
- **argon2-cffi** — хэширование паролей и `client_secret`.
- **zxcvbn** — политика паролей.
- **jinja2** — шаблоны demo-RP.

## Установка

```bash
git clone <URL_репозитория>
cd lab3_vault
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Настройка
1) Скопировать .env.example в .env:

```bash
cp .env.example .env
```


2) Сгенерировать PASSWORD_PEPPER:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Вставить в .env PASSWORD_PEPPER.

3) Сгенерировать RSA-ключи:

```bash
python scripts/gen_keys.py
```

Создаст keys/rsa_private.pem и keys/rsa_public.pem. Приватный ключ не должен попадать в git — keys/ в .gitignore

4) Поднять PostgreSQL (если не установлен):

```bash
sudo apt install postgresql postgresql-contrib
sudo -u postgres psql -c "CREATE USER vault WITH PASSWORD '<password>';"
sudo -u postgres psql -c "CREATE DATABASE vault_db OWNER <username>;"
```


5) Поднять Redis (Docker):

```bash
docker run -d --name vault-redis --restart=always -p 6379:6379 redis:7-alpine
```


## Запуск
```bash
alembic upgrade head
python run.py
```

## Интерфейсы
1) Swagger UI — http://127.0.0.1:8000/docs
2) GraphQL Playground — http://127.0.0.1:8000/graphql/
3) Админка — http://127.0.0.1:8000/admin/
4) Аккаунт — http://127.0.0.1:8000/account/
5) OIDC Discovery — http://127.0.0.1:8000/.well-known/openid-configuration
6) JWKS — http://127.0.0.1:8000/.well-known/jwks.json

## OAuth2/OIDC эндпоинты

| Метод | Путь | Назначение |
|-------|------|-----------|
| GET  | `/oauth/authorize` | Authorization endpoint (PKCE) |
| POST | `/oauth/token` | Token endpoint (4 grant-типа) |
| POST | `/oauth/revoke` | Отзыв токена (RFC 7009) |
| POST | `/oauth/introspect` | Интроспекция (RFC 7662) |
| GET  | `/oauth/userinfo` | OIDC UserInfo |
| GET  | `/.well-known/jwks.json` | JWKS |
| GET  | `/.well-known/openid-configuration` | OIDC Discovery |

## Поддерживаемые grant-типы

- `authorization_code` (с **PKCE S256** — обязателен для публичных клиентов).
- `refresh_token` (с **rotation** и **reuse detection**).
- `password` (deprecated в OAuth 2.1, но оставлен для first-party приложений).
- `client_credentials` (только для конфиденциальных клиентов).

## Пример обмена code → token

```bash
curl -X POST http://127.0.0.1:8000/oauth/token \
  -d "grant_type=authorization_code" \
  -d "client_id=<client_id>" \
  -d "code=<code>" \
  -d "redirect_uri=http://127.0.0.1:8001/callback" \
  -d "code_verifier=<verifier>"
```

## demo-RP
Демонстрационный OIDC-клиент (FastAPI + Jinja2).

```bash
uvicorn demo_rp.main:app --port 8001
```
Ограничение: в браузере flow требует SSR-логин (WIP). Сейчас — проверяется через curl (см. USAGE.md).

## Назначение админа
```bash
python scripts/make_admin.py user@example.com
```

## Тесты
```bash
python examples/check_oauth.py
pytest
```

## Безопасность

- **JWT (RS256)** для всех токенов: REST, GraphQL, OAuth2. Публичный ключ в JWKS.
- **Argon2id + pepper** для паролей и `client_secret`.
- **PKCE S256** для публичных клиентов.
- **Redirect URI** — точное совпадение.
- **Refresh rotation** + reuse detection -> отзыв всего семейства.
- **Blacklist access-токенов** в Redis (TTL = остаток жизни).
- **httponly cookies** для `/admin/` и `/account/` + CSRF-токен.
- `.env`, `keys/`, `*.db` — в `.gitignore`.