# Em backend/api.py

# --- Importações da Biblioteca Padrão ---
import aiofiles
import uuid
from pathlib import Path
from datetime import timedelta, datetime, timezone
from typing import List

try:
    # Tenta importar do Python 3.9+
    from typing import Annotated
except ImportError:
    # Se falhar (Python 3.8), importa do pacote de extensão
    from typing_extensions import Annotated

# --- Importações de Terceiros (FastAPI, Pydantic, etc.) ---
from fastapi import (
    FastAPI, HTTPException, status, Depends, Response,
    UploadFile, File, Form
)
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, EmailStr
from bson.objectid import ObjectId, InvalidId

# --- Importações Locais (Nossos Módulos) ---
from database import collection_user, db, collection_vagas
from config import settings
from auth import (
    create_access_token, get_password_hash, verify_password,
    get_current_contratante, TokenPayload,
    get_current_freelancer,
    get_current_user_payload
)
from models import (
    UserLogin, Token,
    FreelancerCreate, FreelancerResponse,
    ContratanteCreate, ContratanteResponse, ContratanteUpdate, ContratanteDetailResponse,
    UserRole,
    VagaCreate, VagaResponse, VagaInDB, VagaStatus,
    VagaStatsResponse,
    FreelancerCandidateResponse,
    FreelancerDetailResponse,
    FreelancerUpdate,
    CertificateItem
)


app = FastAPI()
# --- MONTAGEM DO DIRETÓRIO ESTÁTICO ---
Path("static/avatars").mkdir(parents=True, exist_ok=True)
Path("static/certificates").mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")
# --- FIM DA MONTAGEM ---

# --- CONFIGURAÇÃO DO CORS ---
origins = ["*"] # Em produção, restrinja isso!
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================================
# --- FUNÇÃO HELPER DE LIMPEZA (ESSENCIAL) ---
# ==========================================================
def clean_vaga_data(vaga_doc: dict) -> dict:
    """
    Corrige o campo 'habilidades' de string (formato antigo) para lista.
    Isso evita o erro 400 Bad Request na validação do response_model.
    """
    if "habilidades" in vaga_doc and isinstance(vaga_doc["habilidades"], str):
        vaga_doc["habilidades"] = [h.strip() for h in vaga_doc["habilidades"].split(",") if h.strip()]
    elif "habilidades" not in vaga_doc or not isinstance(vaga_doc["habilidades"], list):
        vaga_doc["habilidades"] = []
    return vaga_doc
# ==========================================================

# --- ROTAS DA API ---

@app.get("/")
def read_root():
    return {"message": "Bem-vindo à API AssisFreela!"}

# --- Rotas de Registro (Sem Mudanças) ---
@app.post("/register/freelancer", response_model=FreelancerResponse, status_code=status.HTTP_201_CREATED)
async def create_freelancer(user: FreelancerCreate):
    existing_user = await run_in_threadpool(collection_user.find_one, {"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email já cadastrado.")
    hashed_password = await run_in_threadpool(get_password_hash, user.password)
    new_user_data = {
        "username": user.full_name, "email": user.email, "hashed_password": hashed_password,
        "role": UserRole.freelancer.value,
        "details": {
            "full_name": user.full_name, "birth_date": user.birth_date, "phone": user.phone,
            "portfolio": user.portfolio, "skills": [], "interests": [], "certificates": [],
            "avatar_url": None, "endereco": None, "documento": None
        }
    }
    result = await run_in_threadpool(collection_user.insert_one, new_user_data)
    if result.inserted_id:
        return FreelancerResponse(full_name=user.full_name, email=user.email)
    raise HTTPException(status_code=500, detail="Erro ao criar o usuário freelancer.")

@app.post("/register/contratante", response_model=ContratanteResponse, status_code=status.HTTP_201_CREATED)
async def create_contratante(user: ContratanteCreate):
    existing_user = await run_in_threadpool(collection_user.find_one, {"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email já cadastrado.")
    hashed_password = await run_in_threadpool(get_password_hash, user.password)
    new_user_data = {
        "username": user.company_name, "email": user.email, "hashed_password": hashed_password,
        "role": UserRole.contratante.value,
        "details": {
            "company_name": user.company_name, "cnpj": user.cnpj, "address": user.address,
            "phone": user.phone, "industry": user.industry
        }
    }
    result = await run_in_threadpool(collection_user.insert_one, new_user_data)
    if result.inserted_id:
        return ContratanteResponse(company_name=user.company_name, email=user.email)
    raise HTTPException(status_code=500, detail="Erro ao criar o usuário contratante.")

# --- Rota de Login (Sem Mudanças) ---
@app.post("/login", response_model=Token)
async def login_for_access_token(user_credentials: UserLogin):
    db_user = await run_in_threadpool(collection_user.find_one, {"email": user_credentials.email})
    password_ok = False
    if db_user:
        try:
            password_ok = await run_in_threadpool(
                verify_password, user_credentials.password, db_user.get("hashed_password", "")
            )
        except Exception as e:
             print(f"Erro ao verificar senha para {user_credentials.email}: {e}")
             raise HTTPException(status_code=500, detail="Erro interno ao verificar credenciais.")
    if not db_user or not password_ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email ou senha incorretos.", headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = create_access_token(
        data={"sub": db_user["email"], "role": db_user["role"]},
        expires_delta=access_token_expires
    )
    return Token(
        access_token=access_token, token_type="bearer",
        username=db_user.get("username", db_user["email"]),
        role=db_user["role"]
    )

# --- Rotas de Vagas ---

@app.get("/vagas", response_model=List[VagaResponse])
async def read_all_open_vagas():
    query = {"status": VagaStatus.aberta.value}
    vagas_list_db = await run_in_threadpool(lambda: list(collection_vagas.find(query).sort("created_at", -1)))
    # Limpa CADA vaga na lista ANTES de retornar
    return [clean_vaga_data(vaga) for vaga in vagas_list_db]

@app.get("/vagas/{vaga_id}", response_model=VagaResponse)
async def read_vaga_details(vaga_id: str):
    try:
        object_id_vaga = ObjectId(vaga_id)
    except InvalidId:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ID da vaga inválido.")
    vaga = await run_in_threadpool(collection_vagas.find_one, {"_id": object_id_vaga})
    if not vaga:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vaga não encontrada.")
    # Limpa a vaga ANTES de retornar
    return clean_vaga_data(vaga)

@app.post("/vagas", response_model=VagaResponse, status_code=status.HTTP_201_CREATED)
async def create_vaga(
    vaga_data: VagaCreate,
    payload: Annotated[TokenPayload, Depends(get_current_contratante)]
):
    owner_email = payload.sub
    vaga_dict = vaga_data.model_dump()
    habilidades_list = [h.strip() for h in vaga_data.habilidades.split(",")] if vaga_data.habilidades else []
    vaga_completa = {
        **vaga_dict, "habilidades": habilidades_list, "owner_email": owner_email,
        "status": VagaStatus.aberta.value, "created_at": datetime.now(timezone.utc),
        "applicants_emails": [], "rejected_emails": [], "accepted_freelancer_email": None
    }
    try:
        result = await run_in_threadpool(collection_vagas.insert_one, vaga_completa)
        created_vaga = await run_in_threadpool(collection_vagas.find_one, {"_id": result.inserted_id})
        if created_vaga:
             return created_vaga
        else:
             raise HTTPException(status_code=500, detail="Erro crítico: Não foi possível encontrar a vaga após a criação.")
    except Exception as e:
        print(f"Erro ao salvar vaga no MongoDB: {e}")
        raise HTTPException(status_code=500, detail=f"Erro interno ao salvar vaga: {e}")


# ==========================================================
# --- INÍCIO DA CORREÇÃO FINAL (A ROTA DO ERRO) ---
# ==========================================================
@app.get("/vagas/me", response_model=List[VagaResponse])
async def read_own_vagas(
    payload: Annotated[TokenPayload, Depends(get_current_contratante)]
):
    """Retorna as vagas criadas pelo Contratante logado."""
    owner_email = payload.sub
    
    print(">>> Rota /vagas/me foi chamada (VERSÃO FINAL)") # Print de Debug
    
    vagas_list_db = await run_in_threadpool(lambda: list(collection_vagas.find({"owner_email": owner_email}).sort("created_at", -1)))
    
    try:
        # Limpa CADA vaga na lista ANTES de retornar
        # Isso corrige o erro de dados antigos (habilidades como string)
        clean_list = [clean_vaga_data(vaga) for vaga in vagas_list_db]
        
        # Valida manualmente (para dar um erro 500 se falhar, em vez de 400)
        # A simplificação do VagaResponse no models.py deve fazer isso passar.
        valid_list = [VagaResponse.model_validate(vaga) for vaga in clean_list]
        
        return valid_list
        
    except Exception as e:
        print(f"--- ERRO CRÍTICO AO PROCESSAR VAGAS EM /vagas/me ---")
        print(f"Erro: {e}")
        print(f"--------------------------------------------------")
        # Se mesmo após a limpeza falhar, é um erro interno do servidor
        raise HTTPException(status_code=500, detail=f"Erro ao processar dados da vaga: {e}")
# ==========================================================
# --- FIM DA CORREÇÃO FINAL ---
# ==========================================================


@app.get("/vagas/me/active", response_model=List[VagaResponse])
async def read_own_active_vagas(
    payload: Annotated[TokenPayload, Depends(get_current_contratante)]
):
    """Retorna as vagas EM_ANDAMENTO do Contratante logado."""
    owner_email = payload.sub
    query = {"owner_email": owner_email, "status": VagaStatus.em_andamento.value}
    vagas_list_db = await run_in_threadpool(lambda: list(collection_vagas.find(query).sort("created_at", -1)))
    # Limpa CADA vaga na lista ANTES de retornar
    return [clean_vaga_data(vaga) for vaga in vagas_list_db]

@app.delete("/vagas/{vaga_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vaga(
    vaga_id: str,
    payload: Annotated[TokenPayload, Depends(get_current_contratante)]
):
    owner_email = payload.sub
    try:
        object_id_to_delete = ObjectId(vaga_id)
    except InvalidId:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ID da vaga inválido.")
    query = {"_id": object_id_to_delete, "owner_email": owner_email}
    result = await run_in_threadpool(collection_vagas.delete_one, query)
    if result.deleted_count == 0:
        vaga_exists = await run_in_threadpool(collection_vagas.count_documents, {"_id": object_id_to_delete})
        if vaga_exists > 0:
             raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Você não tem permissão para excluir esta vaga.")
        else:
             raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vaga não encontrada.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@app.get("/vagas/stats", response_model=VagaStatsResponse)
async def get_vaga_stats(
    payload: Annotated[TokenPayload, Depends(get_current_contratante)]
):
    owner_email = payload.sub
    query_abertas = {"owner_email": owner_email, "status": VagaStatus.aberta.value}
    count_abertas = await run_in_threadpool(collection_vagas.count_documents, query_abertas)
    query_concluidas = {"owner_email": owner_email, "status": VagaStatus.concluida.value}
    count_concluidas = await run_in_threadpool(collection_vagas.count_documents, query_concluidas)
    return VagaStatsResponse(vagas_abertas=count_abertas, vagas_concluidas=count_concluidas)

# --- Rotas de Candidatura (Sem Mudanças) ---
@app.post("/vagas/{vaga_id}/apply", status_code=status.HTTP_200_OK)
async def apply_to_vaga(
    vaga_id: str,
    payload: Annotated[TokenPayload, Depends(get_current_freelancer)]
):
    freelancer_email = payload.sub
    try: object_id_vaga = ObjectId(vaga_id)
    except InvalidId: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ID da vaga inválido.")
    vaga = await run_in_threadpool(collection_vagas.find_one, {"_id": object_id_vaga})
    if not vaga: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vaga não encontrada.")
    if vaga.get("status") != VagaStatus.aberta.value: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Esta vaga não está mais aceitando candidaturas.")
    if freelancer_email in vaga.get("applicants_emails", []): return {"message": "Você já está candidatado para esta vaga."}
    result = await run_in_threadpool(collection_vagas.update_one, {"_id": object_id_vaga}, {"$addToSet": {"applicants_emails": freelancer_email}})
    if result.matched_count == 0: raise HTTPException(status_code=404, detail="Erro inesperado: Vaga desapareceu durante a candidatura.")
    return {"message": "Candidatura registrada com sucesso!"}

@app.get("/vagas/{vaga_id}/candidates", response_model=List[FreelancerCandidateResponse])
async def get_vaga_candidates(
    vaga_id: str,
    payload: Annotated[TokenPayload, Depends(get_current_contratante)]
):
    contratante_email = payload.sub
    try: object_id_vaga = ObjectId(vaga_id)
    except InvalidId: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ID da vaga inválido.")
    vaga = await run_in_threadpool(collection_vagas.find_one, {"_id": object_id_vaga})
    if not vaga: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vaga não encontrada.")
    if vaga.get("owner_email") != contratante_email: raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Você não tem permissão para ver os candidatos desta vaga.")
    applicant_emails = vaga.get("applicants_emails", [])
    if not applicant_emails: return []
    query_freelancers = {"email": {"$in": applicant_emails}, "role": UserRole.freelancer.value}
    freelancers_list = await run_in_threadpool(lambda: list(collection_user.find(query_freelancers)))
    candidates_details = []
    for freelancer_doc in freelancers_list:
        details = freelancer_doc.get("details", {})
        candidates_details.append(FreelancerCandidateResponse(
            full_name=details.get("full_name", freelancer_doc.get("username")),
            email=freelancer_doc.get("email"),
            phone=details.get("phone")
        ))
    return candidates_details

@app.post("/vagas/{vaga_id}/candidates/{freelancer_email}/accept", status_code=status.HTTP_200_OK)
async def accept_candidate(
    vaga_id: str, freelancer_email: EmailStr, payload: Annotated[TokenPayload, Depends(get_current_contratante)]
):
    contratante_email = payload.sub
    try: object_id_vaga = ObjectId(vaga_id)
    except InvalidId: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ID da vaga inválido.")
    vaga = await run_in_threadpool(collection_vagas.find_one, {"_id": object_id_vaga})
    if not vaga: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vaga não encontrada.")
    if vaga.get("owner_email") != contratante_email: raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Você não tem permissão para gerenciar esta vaga.")
    if vaga.get("status") != VagaStatus.aberta.value: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Esta vaga não está mais aberta para aceitar candidatos.")
    if freelancer_email not in vaga.get("applicants_emails", []): raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Este freelancer não se candidatou ou já foi removido.")
    freelancer_doc = await run_in_threadpool(collection_user.find_one, {"email": freelancer_email})
    freelancer_name = freelancer_doc.get("details", {}).get("full_name", freelancer_doc.get("username", freelancer_email)) if freelancer_doc else freelancer_email
    update_query = {"$set": {"status": VagaStatus.em_andamento.value, "accepted_freelancer_email": freelancer_email}}
    result = await run_in_threadpool(collection_vagas.update_one, {"_id": object_id_vaga}, update_query)
    if result.matched_count == 0: raise HTTPException(status_code=404, detail="Erro ao atualizar: Vaga desapareceu.")
    return {"message": f"Freelancer '{freelancer_name}' aceito! Status da vaga: Em Andamento."}

@app.post("/vagas/{vaga_id}/candidates/{freelancer_email}/reject", status_code=status.HTTP_200_OK)
async def reject_candidate(
    vaga_id: str, freelancer_email: EmailStr, payload: Annotated[TokenPayload, Depends(get_current_contratante)]
):
    contratante_email = payload.sub
    try: object_id_vaga = ObjectId(vaga_id)
    except InvalidId: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ID da vaga inválido.")
    vaga = await run_in_threadpool(collection_vagas.find_one, {"_id": object_id_vaga}, {"owner_email": 1, "status": 1, "applicants_emails": 1})
    if not vaga: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vaga não encontrada.")
    if vaga.get("owner_email") != contratante_email: raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Você não tem permissão.")
    if freelancer_email not in vaga.get("applicants_emails", []): return {"message": "Freelancer já não estava na lista de candidatos ativos."}
    freelancer_doc = await run_in_threadpool(collection_user.find_one, {"email": freelancer_email}, {"details.full_name": 1, "username": 1})
    freelancer_name = freelancer_doc.get("details", {}).get("full_name", freelancer_doc.get("username", freelancer_email)) if freelancer_doc else freelancer_email
    update_query = {"$pull": {"applicants_emails": freelancer_email}, "$addToSet": {"rejected_emails": freelancer_email}}
    result = await run_in_threadpool(collection_vagas.update_one, {"_id": object_id_vaga}, update_query)
    if result.matched_count == 0: raise HTTPException(status_code=404, detail="Erro ao atualizar: Vaga desapareceu.")
    return {"message": f"Freelancer '{freelancer_name}' rejeitado."}

@app.delete("/vagas/{vaga_id}/cancel_apply", status_code=status.HTTP_200_OK)
async def cancel_application_to_vaga(
    vaga_id: str, payload: Annotated[TokenPayload, Depends(get_current_freelancer)]
):
    freelancer_email = payload.sub
    try: object_id_vaga = ObjectId(vaga_id)
    except InvalidId: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ID da vaga inválido.")
    vaga = await run_in_threadpool(collection_vagas.find_one, {"_id": object_id_vaga}, {"status": 1, "applicants_emails": 1})
    if not vaga: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vaga não encontrada.")
    if vaga.get("status") != VagaStatus.aberta.value: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Não é possível cancelar (vaga não está aberta).")
    if freelancer_email not in vaga.get("applicants_emails", []): return {"message": "Você não está candidatado ou sua candidatura já foi processada."}
    result = await run_in_threadpool(collection_vagas.update_one, {"_id": object_id_vaga}, {"$pull": {"applicants_emails": freelancer_email}})
    if result.matched_count == 0: raise HTTPException(status_code=404, detail="Erro inesperado: Vaga desapareceu.")
    return {"message": "Candidatura cancelada com sucesso!"}

# --- Rotas de Consulta do Freelancer ---

@app.get("/vagas/me/applied", response_model=List[VagaResponse])
async def read_freelancer_applied_vagas(payload: Annotated[TokenPayload, Depends(get_current_freelancer)]):
    freelancer_email = payload.sub
    query = {"applicants_emails": freelancer_email, "status": VagaStatus.aberta.value}
    vagas_list_db = await run_in_threadpool(lambda: list(collection_vagas.find(query).sort("created_at", -1)))
    # Limpa CADA vaga na lista ANTES de retornar
    return [clean_vaga_data(vaga) for vaga in vagas_list_db]

@app.get("/vagas/me/active_freelancer", response_model=List[VagaResponse])
async def read_freelancer_active_vagas(payload: Annotated[TokenPayload, Depends(get_current_freelancer)]):
    freelancer_email = payload.sub
    query = {"accepted_freelancer_email": freelancer_email, "status": VagaStatus.em_andamento.value}
    vagas_list_db = await run_in_threadpool(lambda: list(collection_vagas.find(query).sort("created_at", -1)))
    # Limpa CADA vaga na lista ANTES de retornar
    return [clean_vaga_data(vaga) for vaga in vagas_list_db]

@app.get("/freelancers/{freelancer_email}/profile", response_model=FreelancerDetailResponse)
async def read_freelancer_profile(freelancer_email: EmailStr):
    db_freelancer = await run_in_threadpool(collection_user.find_one, {"email": freelancer_email, "role": UserRole.freelancer.value})
    if not db_freelancer: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Perfil de freelancer não encontrado.")
    freelancer_details = db_freelancer.get("details", {})
    return FreelancerDetailResponse(
        email=db_freelancer.get("email"),
        role=db_freelancer.get("role"),
        full_name=db_freelancer.get("username"), # Corrigido o typo aqui
        birth_date=freelancer_details.get("birth_date"),
        phone=freelancer_details.get("phone"),
        portfolio=freelancer_details.get("portfolio"),
        skills=freelancer_details.get("skills", []),
        avatar_url=freelancer_details.get("avatar_url"),
        interests=freelancer_details.get("interests", []),
        certificates=freelancer_details.get("certificates", []),
        endereco=freelancer_details.get("endereco"),
        documento=None 
    )

# --- Rotas de Perfil do Usuário Logado (Sem Mudanças) ---
@app.get("/users/me", response_model=ContratanteDetailResponse)
async def read_users_me(payload: Annotated[TokenPayload, Depends(get_current_contratante)]):
    user_email = payload.sub
    db_user = await run_in_threadpool(collection_user.find_one, {"email": user_email})
    if not db_user: raise HTTPException(status_code=404, detail="Usuário Contratante não encontrado.")
    user_details = db_user.get("details", {})
    return ContratanteDetailResponse(
        email=db_user.get("email"), role=db_user.get("role"),
        company_name=db_user.get("username"), cnpj=user_details.get("cnpj"),
        address=user_details.get("address"), phone=user_details.get("phone"),
        industry=user_details.get("industry")
    )

@app.put("/users/me", response_model=ContratanteDetailResponse)
async def update_user_me(user_update: ContratanteUpdate, payload: Annotated[TokenPayload, Depends(get_current_contratante)]):
    user_email = payload.sub
    update_data = user_update.model_dump(exclude_unset=True)
    if not update_data: return await read_users_me(payload)
    update_query = {"$set": {}}
    if "company_name" in update_data:
        update_query["$set"]["username"] = update_data["company_name"]
        update_query["$set"]["details.company_name"] = update_data["company_name"]
        del update_data["company_name"]
    for key, value in update_data.items():
        if value is not None: update_query["$set"][f"details.{key}"] = value
    if not update_query["$set"]: return await read_users_me(payload)
    result = await run_in_threadpool(collection_user.update_one, {"email": user_email}, update_query)
    if result.matched_count == 0: raise HTTPException(status_code=404, detail="Usuário Contratante não encontrado.")
    return await read_users_me(payload)

@app.get("/users/me/freelancer", response_model=FreelancerDetailResponse)
async def read_freelancer_me(payload: Annotated[TokenPayload, Depends(get_current_freelancer)]):
    user_email = payload.sub
    db_user = await run_in_threadpool(collection_user.find_one, {"email": user_email})
    if not db_user: raise HTTPException(status_code=404, detail="Usuário freelancer não encontrado.")
    user_details = db_user.get("details", {})
    return FreelancerDetailResponse(
        email=db_user.get("email"), role=db_user.get("role"),
        full_name=db_user.get("username"), birth_date=user_details.get("birth_date"),
        phone=user_details.get("phone"), portfolio=user_details.get("portfolio"),
        skills=user_details.get("skills", []), avatar_url=user_details.get("avatar_url"),
        interests=user_details.get("interests", []),
        certificates=user_details.get("certificates", []),
        endereco=user_details.get("endereco"),
        documento=user_details.get("documento")
    )

@app.put("/users/me/freelancer", response_model=FreelancerDetailResponse)
async def update_freelancer_me(
    user_update: FreelancerUpdate, payload: Annotated[TokenPayload, Depends(get_current_freelancer)]
):
    user_email = payload.sub
    update_data = user_update.model_dump(exclude_unset=True)
    if not update_data:
        db_user = await run_in_threadpool(collection_user.find_one, {"email": user_email})
        if not db_user: raise HTTPException(status_code=404, detail="Usuário não encontrado (ao tentar retornar perfil não modificado).")
        user_details = db_user.get("details", {})
        return FreelancerDetailResponse(
            email=db_user.get("email"), full_name=db_user.get("username"),
            birth_date=user_details.get("birth_date"), phone=user_details.get("phone"),
            portfolio=user_details.get("portfolio"), skills=user_details.get("skills", []),
            avatar_url=user_details.get("avatar_url"),
            interests=user_details.get("interests", []),
            certificates=user_details.get("certificates", []),
            endereco=user_details.get("endereco"),
            documento=user_details.get("documento")
        )
    update_query = {"$set": {}}
    if "full_name" in update_data:
        update_query["$set"]["username"] = update_data["full_name"]
        update_query["$set"]["details.full_name"] = update_data["full_name"]
        del update_data["full_name"]
    for key, value in update_data.items():
        update_query["$set"][f"details.{key}"] = value
    if not update_query["$set"]:
         print("Aviso: update_freelancer_me chamado sem dados válidos para $set.")
         return await read_freelancer_me(payload)
    try:
        result = await run_in_threadpool(collection_user.update_one, {"email": user_email, "role": UserRole.freelancer.value}, update_query)
    except Exception as e:
         print(f"Erro ao atualizar freelancer no MongoDB: {e}")
         raise HTTPException(status_code=500, detail=f"Erro interno ao salvar dados: {e}")
    if result.matched_count == 0: raise HTTPException(status_code=404, detail="Usuário freelancer não encontrado para atualizar.")
    return await read_freelancer_me(payload)

@app.post("/users/me/avatar", response_model=FreelancerDetailResponse)
async def upload_freelancer_avatar(
    payload: Annotated[TokenPayload, Depends(get_current_freelancer)], file: UploadFile = File(...)
):
    user_email = payload.sub
    allowed_content_types = ["image/jpeg", "image/png", "image/jpg"]
    if file.content_type not in allowed_content_types:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Tipo '{file.content_type}' inválido. Apenas JPG/PNG.")
    max_size = 5 * 1024 * 1024
    content = await file.read()
    if len(content) > max_size: raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"Arquivo > {max_size/(1024*1024)} MB.")
    await file.seek(0)
    file_extension = Path(file.filename).suffix.lower()
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    save_path = Path("static/avatars") / unique_filename
    try:
        async with aiofiles.open(save_path, 'wb') as out_file: await out_file.write(content)
    except Exception as e:
        print(f"Erro ao salvar arquivo de avatar '{save_path}': {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Erro ao salvar arquivo: {e}")
    finally: await file.close()
    avatar_url = f"/static/avatars/{unique_filename}"
    try:
        result = await run_in_threadpool(collection_user.update_one, {"email": user_email, "role": UserRole.freelancer.value}, {"$set": {"details.avatar_url": avatar_url}})
    except Exception as e:
         print(f"Erro ao atualizar avatar_url no MongoDB para {user_email}: {e}")
         save_path.unlink(missing_ok=True)
         raise HTTPException(status_code=500, detail=f"Erro ao atualizar perfil no banco: {e}")
    if result.matched_count == 0:
        save_path.unlink(missing_ok=True)
        raise HTTPException(status_code=404, detail="Usuário não encontrado para atualizar URL do avatar.")
    return await read_freelancer_me(payload)

@app.post("/users/me/certificates", response_model=CertificateItem, status_code=status.HTTP_201_CREATED)
async def add_freelancer_certificate(
    payload: Annotated[TokenPayload, Depends(get_current_freelancer)],
    course_name: str = Form(..., min_length=1),
    file: UploadFile = File(...)
):
    user_email = payload.sub
    allowed_content_types = ["image/jpeg", "image/png", "image/jpg", "application/pdf"]
    if file.content_type not in allowed_content_types: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Tipo '{file.content_type}' inválido. Apenas JPG/PNG/PDF.")
    max_size = 10 * 1024 * 1024
    content = await file.read()
    if len(content) > max_size: raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=f"Arquivo > {max_size/(1024*1024)} MB.")
    await file.seek(0)
    file_extension = Path(file.filename).suffix.lower()
    unique_filename = f"{uuid.uuid4()}{file_extension}"
    certificates_dir = Path("static/certificates"); certificates_dir.mkdir(parents=True, exist_ok=True)
    save_path = certificates_dir / unique_filename
    try:
        async with aiofiles.open(save_path, 'wb') as out_file: await out_file.write(content)
    except Exception as e:
        print(f"Erro ao salvar arquivo de certificado '{save_path}': {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Erro ao salvar arquivo: {e}")
    finally: await file.close()
    certificate_url = f"/static/certificates/{unique_filename}"
    new_certificate_obj = CertificateItem(course_name=course_name, file_url=certificate_url)
    certificate_dict = new_certificate_obj.model_dump(by_alias=True, exclude={"id"})
    print("-" * 20); print(f"Adding certificate for: {user_email}"); print(f"Data: {certificate_dict}"); print("-" * 20) # DEBUG
    try:
        result = await run_in_threadpool(
            collection_user.update_one,
            {"email": user_email, "role": UserRole.freelancer.value},
            {"$push": {"details.certificates": certificate_dict}}
        )
        print(f"MongoDB update result: Matched={result.matched_count}, Modified={result.modified_count}") # DEBUG
    except Exception as e:
         print(f"Erro ao adicionar certificado no MongoDB para {user_email}: {e}")
         save_path.unlink(missing_ok=True)
         raise HTTPException(status_code=500, detail=f"Erro ao salvar info do certificado: {e}")
    if result.matched_count == 0:
        save_path.unlink(missing_ok=True)
        raise HTTPException(status_code=404, detail="Usuário não encontrado para adicionar certificado.")
    if result.modified_count == 0:
         print(f"Aviso: $push do certificado para {user_email} não modificou o documento.")
    return new_certificate_obj

@app.delete("/users/me/certificates/{certificate_id}", status_code=status.HTTP_200_OK)
async def delete_freelancer_certificate(
    certificate_id: str,
    payload: Annotated[TokenPayload, Depends(get_current_freelancer)]
):
    user_email = payload.sub
    try:
        object_id_cert = ObjectId(certificate_id)
    except InvalidId:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="ID do certificado inválido.")
    user_doc = await run_in_threadpool(
        collection_user.find_one,
        {
            "email": user_email, 
            "role": UserRole.freelancer.value,
            "details.certificates._id": object_id_cert 
        },
        {"details.certificates.$": 1} 
    )
    file_url_to_delete = None
    if user_doc and "details" in user_doc and "certificates" in user_doc["details"] and user_doc["details"]["certificates"]:
        file_url_to_delete = user_doc["details"]["certificates"][0].get("file_url")
    try:
        result = await run_in_threadpool(
            collection_user.update_one,
            {"email": user_email, "role": UserRole.freelancer.value},
            {"$pull": {"details.certificates": {"_id": object_id_cert}}}
        )
    except Exception as e:
         print(f"Erro ao remover certificado do MongoDB para {user_email} (ID: {certificate_id}): {e}")
         raise HTTPException(status_code=500, detail=f"Erro ao remover informações do certificado: {e}")
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Usuário freelancer não encontrado.")
    if result.modified_count == 0:
        print(f"Aviso: Tentativa de excluir certificado {certificate_id} para {user_email}, mas não foi encontrado no array (talvez já excluído).")
    if file_url_to_delete:
        try:
            file_path = Path("." + file_url_to_delete)
            if file_path.is_file():
                file_path.unlink()
                print(f"Arquivo de certificado excluído: {file_path}")
            else:
                 print(f"Aviso: Arquivo de certificado não encontrado para exclusão: {file_path}")
        except Exception as e:
            print(f"Erro ao tentar excluir arquivo de certificado '{file_path}': {e}")
            
    return {"message": "Certificado excluído com sucesso!"}