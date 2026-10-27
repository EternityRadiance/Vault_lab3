# Vault — OAuth2/OIDC Provider

Сервис управления пользователями и OAuth-клиентами. Реализует **OAuth2 (RFC 6749)** и **OpenID Connect** с поддержкой:
- RS256-подписи JWT и публикацией **JWKS**;
- grant-типов `authorization_code` (с **PKCE**), `refresh_token` (с **rotation** и детекцией reuse), `password`, `client_credentials`;
- OIDC: `id_token`, `/oauth/userinfo`, `/.well-known/openid-configuration`;
- отзыва токенов (`/oauth/revoke`, RFC 7009) и интроспекции (`/oauth/introspect`, RFC 7662) с Redis blacklist;
- расширенного GraphQL API для админки: сессии, refresh-токены, ротация секретов клиентов.

## Стек

- FastAPI, Ariadne (GraphQL, schema-first), SQLAlchemy 2.x, Alembic.
- **cryptography** — RSA-ключи, RS256.
- **python-jose** — JWT (RS256).
- **redis** — blacklist access-токенов.
- **argon2-cffi** — хэширование паролей и `client_secret`.
- **zxcvbn** — политика паролей.
- **jinja2** — шаблоны для demo-RP.

## Установка

```bash
git clone <URL_репозитория>
cd lab3_vault
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Настройка
1. Скопировать .env.example в .env:
```bash
cp .env.example .env
```

2. Сгенерировать секреты:
```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "import secrets; print(secrets.token_urlsafe(48))"
```
Первый — в JWT_SECRET, второй — в PASSWORD_PEPPER.

3. Сгенерировать RSA-ключи:
```bash
python scripts/gen_keys.py
```

4. Поднять Redis (Docker):
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
|-------------|-------------|-------------|
| GET    | /oauth/authorize    | Authorization endpoint (PKCE)    |
| POST    | /oauth/token    | Token endpoint (4 grant-типа)    |
| POST    | /oauth/revoke    | 	Отзыв токена (RFC 7009)    |
| POST    | /oauth/introspect    | Интроспекция (RFC 7662)    |
| GET    | /oauth/userinfo    | OIDC UserInfo    |
| GET    | /.well-known/jwks.json    | 	JWKS    |
| GET    | /.well-known/openid-configuration    | 	OIDC Discovery    |

## Поддерживаемые grant-типы
1) authorization_code (с PKCE S256 — обязателен для публичных клиентов)
2) refresh_token (с rotation и reuse detection)
3) password (deprecated в OAuth 2.1, но оставлен для first-party приложений)
4) client_credentials (только для конфиденциальных клиентов)


## Пример обмена code -> token
```bash
curl -X POST http://127.0.0.1:8000/oauth/token \
  -d "grant_type=authorization_code" \
  -d "client_id=<client_id>" \
  -d "code=<code>" \
  -d "redirect_uri=http://127.0.0.1:8001/callback" \
  -d "code_verifier=<verifier>"
```

## demo-RP
Демонстрационный OIDC-клиент. См. demo_rp/README.md
```bash
uvicorn demo_rp.main:app --port 8001
```

## Тесты
```bash
pytest
```

## Структура проекта
lab3_vault/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── core/security/       # jwt_rsa, pkce, passwords
│   ├── db/
│   ├── models/              # User, OAuthClient, RefreshToken, AuthCode, UserSession, AuditEvent
│   ├── auth/                # REST /auth/*
│   ├── oauth/               # /oauth/*: authorize, token, revoke, introspect, userinfo, discovery, jwks
│   │   └── grants/          # password, authorization_code, refresh_token, client_credentials
│   ├── graphql/
│   ├── audit/
│   └── static/
├── demo_rp/
│   ├── main.py
│   └── templates/
├── scripts/
│   └── gen_keys.py
├── keys/                    # .gitignore
├── alembic/
├── tests/
├── requirements.txt
├── run.py
└── README.md

## Безопасность
1) RS256 (приватный ключ в keys/, публичный в JWKS).
2) Argon2id + pepper для паролей и client_secret.
3) PKCE обязателен для публичных клиентов.
4) Redirect URI — точное совпадение.
5) Refresh rotation + reuse detection → отзыв всего семейства.
6) Blacklist access-токенов в Redis (TTL = остаток жизни).
7) .env, keys/, *.db — в .gitignore.