from fastapi import APIRouter

from app.oauth.authorize import router as authorize_router
from app.oauth.token import router as token_router

from app.oauth.introspect import router as introspect_router
from app.oauth.revoke import router as revoke_router
from app.oauth.userinfo import router as userinfo_router

router = APIRouter(tags=["oauth"])
router.include_router(authorize_router)
router.include_router(token_router)
router.include_router(revoke_router)
router.include_router(introspect_router)
router.include_router(userinfo_router)