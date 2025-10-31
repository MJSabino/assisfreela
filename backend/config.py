# Em backend/config.py
from pydantic_settings import BaseSettings
import os

# Carrega as variáveis do arquivo .env automaticamente
# Tenta carregar o .env da pasta atual ou uma acima
env_path = os.path.join(os.path.dirname(__file__), '.env')
if not os.path.exists(env_path):
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env') # Tenta pasta acima

class Settings(BaseSettings):
    mongo_uri: str = "mongodb://localhost:27017/" # Valor padrão caso não ache no .env
    secret_key: str = "default_secret"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30

    class Config:
        env_file = env_path
        env_file_encoding = 'utf-8'

settings = Settings()