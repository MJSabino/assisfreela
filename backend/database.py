# Em backend/database.py
from pymongo import MongoClient
from config import settings # Assume que você importa 'settings' do config.py

# Coloque aqui a sua "Connection String" do MongoDB Atlas
MONGO_URI_FROM_ENV = settings.mongo_uri # Lê do .env através do config.py

# !!! ADICIONE ESTA LINHA PARA DEBUG !!!
print(f"DEBUG: Tentando conectar com URI: {settings.mongo_uri}")
# !!! ----------------------------- !!!

# Use a variável lida das configurações
client = MongoClient(settings.mongo_uri)

# Define o banco de dados
db = client.assis_freela_db

# Define as coleções
collection_user = db["users"]
collection_vagas = db["vagas"] # <-- LINHA ADICIONADA AQUI

# ... etc ... (pode adicionar outras coleções aqui no futuro)

print("Conectado ao MongoDB!") # Esta linha só aparecerá se a conexão funcionar