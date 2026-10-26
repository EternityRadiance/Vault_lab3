from fastapi import APIRouter

from app.oauth.authorize import router as authorize_router

router = APIRouter(tags=["oauth"])
router.include_router(authorize_router)