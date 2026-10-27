# Vault — архитектура OAuth2/OIDC

Как устроен OAuth2/OIDC-провайдер: слои, жизненный цикл запроса, безопасность.

## Общая картина

Vault — **монолит**: FastAPI + SQLAlchemy + Ariadne (GraphQL). OAuth2/OIDC — **надстройка** над REST-аутентификацией лабы №2.

Все JWT — **RS256**. Публичный ключ — в JWKS, приватный — в `keys/rsa_private.pem`.

## Слои

### Конфигурация — `app/config.py`

`Settings(BaseSettings)` читает `.env`. Все секреты — только здесь. Поля:
- `database_url` (PostgreSQL), `redis_url`
- `password_pepper`, `password_min_length`
- `issuer`, `rsa_key_path`, `rsa_key_id`
- `access_token_ttl_sec`, `refresh_token_ttl_days`, `auth_code_ttl_sec`, `pkce_required_for_public`

### Безопасность — `app/core/security/`

- **`jwt_rsa.py`** — RS256: `load_private_key`, `load_public_key`, `sign_access_token`, `sign_id_token`, `verify_token`.
- **`pkce.py`** — `compute_challenge`, `verify_pkce` (S256 + plain, длина 43–128).
- **`passwords.py`** — Argon2id + pepper (из лабы №2).

### Redis — `app/redis_client.py`

Единый клиент. `blacklist_jti(jti, ttl)`, `is_blacklisted(jti)`. TTL = остаток жизни токена.

### Модели

- **`User`** — id, email, hashed_password, is_active, is_admin, created_at.
- **`OAuthClient`** — id, client_id (hex), name, is_confidential, hashed_secret, redirect_uris, scopes, grant_types, is_active, created_at, updated_at.
- **`RefreshToken`** — jti, family_id, token_hash (SHA-256), user_id, client_id, scope, expires_at, used_at, revoked_at, replaced_by_hash, created_at.
- **`AuthCode`** — code_hash, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at, used_at, created_at.
- **`UserSession`** — user_id, client_id, family_id, ip, user_agent, created_at, last_seen_at, revoked_at.
- **`AuditEvent`** — event_type, actor_id, client_id, ip, user_agent, metadata_json, created_at.

### OAuth2 — `app/oauth/`

- `router.py` — сборка всех роутов.
- `authorize.py` — GET `/oauth/authorize`.
- `token.py` — POST `/oauth/token` (ветвление по grant_type).
- `revoke.py` — POST `/oauth/revoke`.
- `introspect.py` — POST `/oauth/introspect`.
- `userinfo.py` — GET `/oauth/userinfo`.
- `discovery.py` — GET `/.well-known/openid-configuration`.
- `jwks.py` — GET `/.well-known/jwks.json`.
- `errors.py` — OAuth2-ошибки (JSON + redirect).
- `client_auth.py` — аутентификация клиента.
- `tokens.py` — генерация refresh, `issue_token_response`.
- `grants/` — `password.py`, `authorization_code.py`, `refresh_token.py`, `client_credentials.py`.

## Жизненный цикл: authorization_code flow

### 1. `GET /oauth/authorize`

**Параметры:** `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `code_challenge`, `code_challenge_method`, `nonce`.

**Аутентификация пользователя:** `get_current_user` из `deps.py` (RS256, Bearer или cookie). **Если токена нет — 401**.

**Проверки:**

1. Клиент существует, `is_active`.
2. `redirect_uri` **точно** совпадает с одним из `client.redirect_uris`.
3. `response_type == "code"`.
4. `state` присутствует.
5. Запрошенные `scope`- подмножество `client.scopes`.
6. `authorization_code` разрешён в `grant_types`.
7. Если клиент **публичный** и `pkce_required_for_public`: `code_challenge` обязателен, `method == S256`.

**При успехе:**

- Генерирует `secrets.token_urlsafe(48)` -> `raw_code`.
- Создаёт `AuthCode` с `code_hash = sha256(raw_code)`, `expires_at = now + 60s`.
- Аудит `oauth.authorize.success`.
- 302 на `redirect_uri?code=...&state=...`.

**При ошибке:**

- Если `redirect_uri` **невалидный** -> JSON 400 (редиректить некуда).
- Если **валидный** -> 302 на `redirect_uri?error=...&state=...`.

### 2. `POST /oauth/token` (grant_type=authorization_code)

**Параметры:** `code`, `redirect_uri`, `code_verifier`.

**Аутентификация клиента:** `authenticate_client` (secret для конфиденциальных, HTTP Basic).

**Проверки:**

1. `AuthCode` по `sha256(code)`.
2. `used_at IS NULL` -> иначе `auth_code.reuse_detected`.
3. `expires_at > now`.
4. `client_id` совпадает.
5. `redirect_uri` совпадает.
6. `verify_pkce(code_verifier, code_challenge, method)` — для публичных обязателен.
7. `scope` - подмножество `client.scopes`.

**При успехе:**

- `AuthCode.used_at = now`.
- `generate_refresh_token` -> `raw_refresh`, запись с **новым** `family_id`.
- Создаёт `UserSession` с `family_id`, `ip`, `user_agent`.
- `sign_access_token(sub=user.id, client_id, scopes)`.
- Если `openid` в scope -> `sign_id_token` (claims: `iss`, `sub`, `aud`, `exp`, `iat`, `nonce`, `email`, `name`).
- Аудит `token.issued` с `grant_type=authorization_code`.
- 200 + JSON: `access_token`, `token_type`, `expires_in`, `scope`, `refresh_token`, `id_token`.

## Rotation и reuse detection

### Rotation

Каждый `refresh_token`  **одноразовый**. При обмене:

1. Помечаем `used_at = now`.
2. Генерируем **новый** refresh с **тем же `family_id`**.
3. `old.replaced_by_hash = hash(new_token)`.
4. Обновляем `UserSession.last_seen_at`.

### Reuse detection

Если клиент присылает **уже использованный** refresh (`used_at IS NOT NULL`):

1. `UPDATE refresh_tokens SET revoked_at = now WHERE family_id = ...` - отозвать **всё семейство**.
2. `UPDATE user_sessions SET revoked_at = now WHERE family_id = ...`.
3. Аудит `token.reuse_detected` с `family_id`, `user_id`, `ip`.
4. 400 `invalid_grant`.

**Почему так:** если refresh-токен утёк и используется повторно - лучше разлогинить **все** устройства этого семейства, чем дать злоумышленнику пользоваться.

## Blacklist access-токенов

Access-токены **stateless** (RS256). Отозвать «в моменте» нельзя, не храня состояние. Решение  **blacklist в Redis**:

- `/oauth/revoke` для access: `blacklist_jti(jti, ttl = exp - now)`.
- `/oauth/userinfo`, `/oauth/introspect`, `/auth/me`, `/graphql/*`: после проверки подписи  `is_blacklisted(jti)` -> 401.

**TTL = остаток жизни токена.** Когда токен истекает, ключ в Redis удаляется автоматически -> blacklist не растёт бесконечно.

## Обработка `client_secret`

- **Конфиденциальный клиент** (`is_confidential=True`) - `hashed_secret` (Argon2id). Secret обязателен при `/oauth/token`.
- **Публичный** (`is_confidential=False`) - `hashed_secret=None`. Secret не требуется, PKCE обязателен.

**`rotateClientSecret`** - генерирует новый secret, хэширует, возвращает **один раз**. Старый перестаёт работать.

**`createClient`** для конфиденциальных генерирует secret и возвращает `clientSecret` (один раз). Для публичных - `clientSecret = null`.

## Аудит

Все значимые события пишутся в `audit_events` через `write_event`:

- `oauth.authorize.success` / `failure` - `/authorize`.
- `token.issued` - все grant-типы (`grant_type` в metadata).
- `token.refreshed` - rotation.
- `token.reuse_detected` - reuse refresh.
- `auth_code.reuse_detected` - reuse code.
- `token.revoked` - `/oauth/revoke`.
- `client.created`, `client.secret_rotated`, `client.enabled`, `client.disabled`.
- `session.revoked` - `revokeUserSessions`.

**Секреты в metadata запрещены** (`FORBIDDEN_METADATA_KEYS`).

## Аутентификация на клиенте

- **demo-RP** — `httponly` cookie (`access_token`, `id_token`, `refresh_token`). Не читается из JS — XSS не даёт доступа.
- **`/admin/` и `/account/`** — `httponly` cookie `vault_session` + CSRF-токен `vault_csrf` (не httponly). `SameSite=Lax`.

**CSRF-защита:** для `POST`/`PUT`/`PATCH`/`DELETE` через cookie - проверяется `cookie vault_csrf` === `header X-CSRF-Token`.

**`/oauth/*`** - всегда `Authorization: Bearer`. Cookie **не используется** .

## demo-RP

`demo_rp/` - отдельное FastAPI-приложение (порт 8001). Использует `httpx` + `jinja2` + `jose`.

**Роуты:**

- `GET /` - главная. Залогинен — «Привет, email». Нет - «Войти через Vault».
- `GET /login` - генерирует PKCE + state + nonce, редиректит на `/oauth/authorize`.
- `GET /callback` - принимает code, обменивает на токены, проверяет `id_token` по JWKS, сохраняет в cookie.
- `POST /logout` - отзывает refresh, чистит cookies.
- `GET /profile` - показывает claims из `id_token` и `access_token`.

**Ограничение:** `/oauth/authorize` требует Bearer-токен (RS256). Полноценный SSR-логин будет реализован позже. Сейчас demo-RP **не может** пройти flow в браузере end-to-end. Проверяется через **curl** вручную (см. test.py в корне проекта).

## Структура БД после миграций

- **users** - добавлено is_active, is_admin.
- **oauth_clients** - добавлено hashed_secret, scopes, grant_types, is_active, updated_at.
- **audit_events** - не изменилось.
- **refresh_tokens** - jti, family_id, token_hash, user_id, client_id, scope, expires_at, used_at, revoked_at, replaced_by_hash.
- **auth_codes** - code_hash, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at, used_at.
- **user_sessions** - user_id, client_id, family_id, ip, user_agent, created_at, last_seen_at, revoked_at.

## TODO:

- **SSR-логин** в `/oauth/authorize` (сейчас 401 без Bearer).
- **Consent screen** (страница «Разрешить доступ?»).
- **Ротация RSA-ключей** (два активных kid одновременно).
- **Rate limiting** на `/oauth/token` и `/oauth/authorize`.
- **`/oauth/device_authorization`**
- **`response_mode=form_post`**.
- **CI (GitHub Actions)**.
- **Метрики Prometheus**.
