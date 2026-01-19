from pydantic import BaseModel, Field
from typing import List


class RegisterRequest(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=6, max_length=128)


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class SolveRequest(BaseModel):
    degree: int = Field(ge=1, le=50)
    coeffs: List[float]
    x_min: float = -10.0
    x_max: float = 10.0


class RootOut(BaseModel):
    re: float
    im: float


class SolveResponse(BaseModel):
    equation: str
    roots: List[RootOut]
    x_min: float
    x_max: float
    y_min: float
    y_max: float


class HistoryOut(BaseModel):
    id: int
    created_at: str
    equation: str
    coeffs_csv: str
    roots: List[RootOut]
    x_min: float
    x_max: float
    y_min: float
    y_max: float


class HistoryListResponse(BaseModel):
    items: List[HistoryOut]
class PasswordResetRequest(BaseModel):
    username: str
    new_password: str = Field(min_length=8, max_length=128)
class ForgotPasswordRequest(BaseModel):
    username: str
    new_password: str = Field(min_length=8, max_length=128)
class ChangeExpiredPasswordRequest(BaseModel):
    username: str
    old_password: str
    new_password: str = Field(min_length=8, max_length=128)
