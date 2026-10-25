from __future__ import annotations
from pydantic import BaseModel, EmailStr, Field

class Credentials(BaseModel):

    email: EmailStr
    password: str = Field(..., min_length=1)

class TokenResponse(BaseModel):

    access_token: str
    token_type: str = "bearer"

class MeResponse(BaseModel):

    id: int
    email: EmailStr
    is_admin: bool