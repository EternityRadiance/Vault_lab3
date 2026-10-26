from fastapi import APIRouter

from app.oauth.authorize import router as authorize_router
from app.oauth.token import router as token_router

router = APIRouter(tags=["oauth"])
router.include_router(authorize_router)
router.include_router(token_router)