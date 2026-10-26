import secrets
from uuid import uuid4

from app.db.session import SessionLocal
from app.models.oauth_client import OAuthClient
from app.core.passwords import hash_password

db = SessionLocal()

client = db.query(OAuthClient).filter_by(name="password-test-client").first()
if not client:
    raw_secret = secrets.token_urlsafe(48)
    client = OAuthClient(
        client_id="password-client-" + uuid4().hex[:8],
        name="password-test-client",
        is_confidential=True,
        hashed_secret=hash_password(raw_secret),
        redirect_uris=[],
        scopes=["openid", "profile", "email"],
        grant_types=["password", "refresh_token"],
        is_active=True,
    )
    db.add(client); db.commit(); db.refresh(client)
    print(f"[+] created: {client.client_id}")
    print(f"    secret: {raw_secret}")
else:
    print(f"[=] exists: {client.client_id}")
    print("    secret unknown (already hashed). Delete client to regenerate.")
    # Не показываем secret повторно -- он хэширован

print()
print("CLIENT_ID:", client.client_id)
db.close()
