# Em backend/auth.py
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext
from config import settings

# --- NOVAS IMPORTAÇÕES PARA DEPENDÊNCIA ---
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, EmailStr
from models import UserRole # Importe nosso Enum
# --- FIM DAS NOVAS IMPORTAÇÕES ---


# --- MUDANÇA PRINCIPAL (sem mudanças) ---
pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")

# --- Funções de Senha (sem mudanças) ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password.encode('utf-8'), hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password.encode('utf-8'))

# --- FUNÇÃO DE TOKEN JWT (sem mudanças) ---
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)

    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)
    return encoded_jwt

# --- INÍCIO DAS NOVAS ADIÇÕES (FASE 2) ---

# Define o "esquema" de autenticação. 
# "tokenUrl" aponta para a NOSSA rota de login.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

class TokenPayload(BaseModel):
    """Define a estrutura do payload que colocamos no token"""
    sub: EmailStr # O email do usuário
    role: UserRole # O papel (FREELANCER, CONTRATANTE)

async def get_current_user_payload(token: str = Depends(oauth2_scheme)) -> TokenPayload:
    """
    Dependência: Decodifica o token, valida e retorna o payload.
    Esta é a nossa "leitura de crachá".
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Não foi possível validar as credenciais",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, settings.secret_key, algorithms=[settings.algorithm]
        )
        # Extrai os dados do payload
        email: str = payload.get("sub")
        role: str = payload.get("role")
        
        if email is None or role is None:
            raise credentials_exception
            
        # Valida os dados usando o modelo Pydantic
        token_data = TokenPayload(sub=email, role=role)

    except JWTError:
        raise credentials_exception
    
    return token_data

async def get_current_contratante(
    payload: TokenPayload = Depends(get_current_user_payload)
) -> TokenPayload:
    """
    Dependência: Garante que o usuário é um CONTRATANTE.
    Usa a dependência anterior e adiciona uma verificação de "papel".
    """
    if payload.role != UserRole.contratante:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: Requer privilégios de Contratante.",
        )
    return payload

# --- FIM DAS NOVAS ADIÇÕES (FASE 2) ---
async def get_current_freelancer(
    payload: TokenPayload = Depends(get_current_user_payload)
) -> TokenPayload:
    """
    Dependência: Garante que o usuário logado é um FREELANCER.
    Usa a dependência get_current_user_payload e verifica o 'role'.
    """
    if payload.role != UserRole.freelancer:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado: Requer privilégios de Freelancer.",
        )
    return payload

# --- FIM DA NOVA ADIÇÃO (FASE 6) ---