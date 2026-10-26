from __future__ import annotations
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.auth.router import router as auth_router
from app.config import settings
from app.graphql.schema import graphql_app

from app.oauth.discovery import router as discovery_router
from app.oauth.jwks import router as jwks_router
from app.oauth.router import router as oauth_router

app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
)

app.include_router(auth_router)
app.include_router(jwks_router)
app.include_router(discovery_router)
app.include_router(oauth_router)

@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok", "app": settings.app_name}

app.mount("/graphql", graphql_app)
app.mount("/admin", StaticFiles(directory="app/static", html=True), name="admin")
app.mount("/account", StaticFiles(directory="app/static/account", html=True), name="account")