# Em backend/models.py
from pydantic import BaseModel, EmailStr, Field, computed_field, GetJsonSchemaHandler
from pydantic_core import core_schema
from enum import Enum
from datetime import datetime
from bson import ObjectId
from typing import Any, List

try:
    # Tenta importar do Python 3.9+
    from typing import Annotated
except ImportError:
    # Se falhar (Python 3.8), importa do pacote de extensão
    from typing_extensions import Annotated

# --- DEFINIÇÃO CORRIGIDA DE PyObjectId ---
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v: Any) -> ObjectId:
        if isinstance(v, ObjectId):
            return v
        if ObjectId.is_valid(v):
            return ObjectId(v)
        raise ValueError("Invalid ObjectId")

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source_type: Any, handler: Any
    ) -> core_schema.CoreSchema:
        return core_schema.no_info_after_validator_function(
            cls.validate,
            core_schema.union_schema([
                core_schema.is_instance_schema(ObjectId),
                core_schema.str_schema(),
            ]),
            serialization=core_schema.plain_serializer_function_ser_schema(lambda x: str(x)),
        )

    @classmethod
    def __get_pydantic_json_schema__(
        cls, core_schema: core_schema.CoreSchema, handler: GetJsonSchemaHandler
    ) -> dict[str, Any]:
        return {"type": "string", "format": "objectid"}
# --- FIM DA DEFINIÇÃO DE PyObjectId ---


# --- Modelos de Autenticação e Usuário ---
class UserRole(str, Enum): 
    admin = "ADMIN"
    contratante = "CONTRATANTE"
    freelancer = "FREELANCER"

class UserLogin(BaseModel): 
    email: EmailStr
    password: str

class Token(BaseModel): 
    access_token: str
    token_type: str
    username: str
    role: UserRole

# --- MODELOS FREELANCER ---
class FreelancerCreate(BaseModel):
    full_name: str
    birth_date: str
    email: EmailStr
    phone: str
    portfolio: str | None = None
    password: str

class FreelancerResponse(BaseModel):
    full_name: str
    email: EmailStr
    role: str = UserRole.freelancer.value

class FreelancerUpdate(BaseModel):
    full_name: str | None = None
    birth_date: str | None = None
    phone: str | None = None
    portfolio: str | None = None
    skills: List[str] | None = None
    interests: List[str] | None = None
    endereco: str | None = None
    documento: str | None = None

class CertificateItem(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id") 
    course_name: str = Field(..., min_length=1) 
    file_url: str = Field(...) 

    @computed_field(alias="id") 
    @property
    def id_str(self) -> str:
        return str(self.id)

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str}
    }

class FreelancerDetailResponse(BaseModel):
    email: EmailStr
    role: UserRole = UserRole.freelancer
    full_name: str
    birth_date: str | None = None
    phone: str | None = None
    portfolio: str | None = None
    skills: List[str] = []
    avatar_url: str | None = None
    interests: List[str] = []
    certificates: List[CertificateItem] = []
    endereco: str | None = None
    documento: str | None = None

    model_config = {
        "from_attributes": True,
        "populate_by_name": True,
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str}
    }

class FreelancerCandidateResponse(BaseModel):
    full_name: str | None = Field(None)
    email: EmailStr
    phone: str | None = Field(None)
    
    model_config = {
        "from_attributes": True,
        "populate_by_name": True
    }

# --- MODELOS CONTRATANTE ---
class ContratanteCreate(BaseModel): 
    company_name: str
    cnpj: str
    address: str
    phone: str
    email: EmailStr
    password: str
    industry: str

class ContratanteResponse(BaseModel): 
    company_name: str
    email: EmailStr
    role: str = UserRole.contratante.value

class ContratanteUpdate(BaseModel): 
    company_name: str | None = None
    cnpj: str | None = None
    address: str | None = None
    phone: str | None = None
    industry: str | None = None

class ContratanteDetailResponse(BaseModel): 
    email: EmailStr
    role: UserRole = UserRole.contratante
    company_name: str
    cnpj: str | None = None
    address: str | None = None
    phone: str | None = None
    industry: str | None = None
    
    model_config = {
        "from_attributes": True,
        "populate_by_name": True
    }

# --- MODELOS DE VAGA ---
class VagaStatus(str, Enum): 
    aberta = "ABERTA"
    em_andamento = "EM_ANDAMENTO"
    concluida = "CONCLUIDA"
    cancelada = "CANCELADA"

class VagaBase(BaseModel): 
    titulo: str
    descricao: str
    categoria: str
    habilidades: str | None = None # Input as comma-separated string
    nivel: str
    orcamento: float
    prazo: int | None = None
    tipo_pagamento: str

class VagaCreate(VagaBase): pass

# ==========================================================
# --- CORREÇÃO (Sugerida pela outra IA) ---
# =ilizando a versão simplificada para VagaInDB e VagaResponse
# ==========================================================

class VagaInDB(VagaBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    owner_email: EmailStr
    habilidades: List[str] = [] # Stored as a list in DB
    status: VagaStatus = VagaStatus.aberta
    created_at: datetime = Field(default_factory=datetime.now)
    applicants_emails: List[EmailStr] = []
    accepted_freelancer_email: EmailStr | None = None
    rejected_emails: List[EmailStr] = []

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str}
    }

class VagaResponse(VagaBase):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    owner_email: EmailStr
    habilidades: List[str] = [] # Output as a list
    status: VagaStatus
    created_at: datetime
    applicants_emails: List[EmailStr] = []
    accepted_freelancer_email: EmailStr | None = None
    rejected_emails: List[EmailStr] = []

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str}
    }
# --- FIM DA CORREÇÃO ---

class VagaStatsResponse(BaseModel): 
    vagas_abertas: int
    vagas_concluidas: int