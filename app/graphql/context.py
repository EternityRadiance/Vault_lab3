from __future__ import annotations

from app.core.deps import _extract_bearer_token
from app.core.jwt import decode_token
from app.db import session as db_session_module
from app.models.user import User

def get_context_value(request, data) -> dict:

    db = db_session_module.SessionLocal()

    context = {
        "request": request,
        "db": db,
        "user": None,
    }

    token = _extract_bearer_token(request)
    if token:
        try:
            payload = decode_token(token)
            user_id = int(payload["sub"])
            user = db.get(User, user_id)
            if user is not None and user.is_active:
                context["user"] = user
        except (ValueError, KeyError, TypeError):
            pass

    return context