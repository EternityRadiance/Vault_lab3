from __future__ import annotations
from ariadne import MutationType, ObjectType, QueryType, convert_kwargs_to_snake_case
from sqlalchemy import select
from sqlalchemy.orm import Session
from uuid import uuid4
import json

from app.audit.events import ClientEvents, UserEvents
from app.audit.service import get_client_info, write_event
from app.auth.service import (
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    register_user,
)
from app.core.passwords import WeakPasswordError
from app.models.oauth_client import OAuthClient
from app.models.audit_event import AuditEvent
from app.models.user import User

query = QueryType()
mutation = MutationType()
audit_event_type = ObjectType("AuditEvent")


@audit_event_type.field("metadata")
def resolve_audit_metadata(event, info):
    if event.metadata_json is None:
        return None
    return json.dumps(event.metadata_json, ensure_ascii=False)

@query.field("users")
@convert_kwargs_to_snake_case
def resolve_users(obj, info, search=None, limit=50, offset=0):

    db: Session = info.context["db"]

    stmt = select(User).order_by(User.id)
    if search:
        stmt = stmt.where(User.email.ilike(f"%{search}"))
    stmt = stmt.offset(offset).limit(limit)

    return db.execute(stmt).scalars().all()

@query.field("clients")
def resolve_clients(obj, info):

    db: Session = info.context["db"]
    return db.execute(select(OAuthClient).order_by(OAuthClient.id)).scalars().all()

@query.field("auditEvents")
@convert_kwargs_to_snake_case
def resolve_audit_events(obj, info, event_type=None, limit=100, offset=0):

    db: Session = info.context["db"]

    stmt = select(AuditEvent).order_by(AuditEvent.created_at.desc())
    if event_type:
        stmt = stmt.where(AuditEvent.event_type == event_type)
    stmt = stmt.offset(offset).limit(limit)

    return db.execute(stmt).scalars().all()

@query.field("me")
def resolve_me(obj, info):
    return info.context["user"]



@mutation.field("registerUser")
@convert_kwargs_to_snake_case
def resolve_register_user(obj, info, email, password):

    db: Session = info.context["db"]
    request = info.context.get("request")

    try:
        user, token = register_user(
            db,
            email=email,
            password=password,
            request=request,
        )
    except EmailAlreadyExistsError as e:
        raise ValueError(f"Email already registered") from e
    except WeakPasswordError as e:
        raise ValueError(str(e)) from e

    return {"access_token": token, "token_type": "bearer"}

@mutation.field("createClient")
@convert_kwargs_to_snake_case
def resolve_create_client(obj, info, name, is_confidential=True):

    db: Session = info.context["db"]
    request = info.context.get("request")
    current_user: User = info.context["user"]

    client = OAuthClient(
        client_id=uuid4().hex,
        name=name,
        is_confidential=is_confidential,
        redirect_uris=[]
    )
    db.add(client)
    db.flush()

    info_dict = get_client_info(request)
    write_event(
        db,
        ClientEvents.CREATED,
        actor_id=current_user.id,
        ip=info_dict["ip"],
        user_agent=info_dict["user_agent"],
        metadata={"name": client.name},
    )

    return client

@mutation.field("disableUser")
@convert_kwargs_to_snake_case
def resolve_disable_user(obj, info, user_id):

    db: Session = info.context["db"]
    request = info.context.get("request")
    current_user: User = info.context["user"]

    try:
        uid = int(user_id)
    except (TypeError, ValueError):
        raise ValueError("invalid user id")

    target = db.execute(
        select(User).where(User.id == uid)
    ).scalar_one_or_none()

    if target is None:
        raise ValueError("User not found")

    if not target.is_active:
        return target

    target.is_active = False

    info_dict = get_client_info(request)
    write_event(
        db,
        UserEvents.DISABLED,
        actor_id=current_user.id,
        ip=info_dict["ip"],
        user_agent=info_dict["user_agent"],
        metadata={"target_user_id": target.id, "target_email": target.email},
    )

    return target