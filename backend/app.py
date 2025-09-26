import os 
import json  
import base64  
import hashlib  
import time  
from typing import Dict, List  

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Header  
from fastapi.responses import JSONResponse, FileResponse  
from fastapi.middleware.cors import CORSMiddleware  
from fastapi.staticfiles import StaticFiles  
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  
from jose import jwt, JWTError  

app = FastAPI()
import boto3
from dotenv import load_dotenv
from pathlib import Path
load_dotenv(dotenv_path=Path(__file__).parent / ".env")


import os
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
AWS_REGION = os.getenv("AWS_REGION")
S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME")
print("Loaded bucket:", S3_BUCKET_NAME)


s3_client = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)
  

# Enable CORS for frontend  
app.add_middleware(  
    CORSMiddleware,  
    allow_origins=["*"],  # For demo only; restrict in production  
    allow_methods=["*"],  
    allow_headers=["*"],  
)  

# Local file storage directory  
STORAGE_DIR = "encrypted_files"  
LOGCHAIN_FILE = "blockchain_log.json"  

# AES-256 key (32 bytes). For demo, hardcoded. Change for production.  
AES_KEY = b"0123456789abcdef0123456789abcdef"  
# JWT secret key  
JWT_SECRET = "your-secret-key-for-jwt-signing"  
JWT_ALGORITHM = "HS256"  

blockchain_log = []  

def load_blockchain_log():  
    global blockchain_log  
    if os.path.exists(LOGCHAIN_FILE):  
        with open(LOGCHAIN_FILE, "r") as f:  
            blockchain_log = json.load(f)  
    else:  
        genesis_block = {  
            "index": 0,  
            "timestamp": time.time(),  
            "prev_hash": "0"*64,  
            "event": "Genesis block",  
            "hash": ""  
        }  
        genesis_block["hash"] = calculate_hash(genesis_block)  
        blockchain_log = [genesis_block]  
        save_blockchain_log()  

def save_blockchain_log():  
    with open(LOGCHAIN_FILE, "w") as f:  
        json.dump(blockchain_log, f, indent=4)  

def calculate_hash(block: Dict) -> str:  
    data_string = f'{block["index"]}{block["timestamp"]}{block["prev_hash"]}{block["event"]}'  
    return hashlib.sha256(data_string.encode()).hexdigest()  

def add_block(event: str):  
    prev_block = blockchain_log[-1]  
    new_block = {  
        "index": prev_block["index"] + 1,  
        "timestamp": time.time(),  
        "prev_hash": prev_block["hash"],  
        "event": event,  
        "hash": ""  
    }  
    new_block["hash"] = calculate_hash(new_block)  
    blockchain_log.append(new_block)  
    save_blockchain_log()  

def verify_jwt_token(token: str) -> Dict:  
    try:  
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])  
        if payload.get("exp") and time.time() > payload["exp"]:  
            raise HTTPException(status_code=401, detail="Token expired")  
        return payload  
    except JWTError as e:  
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")  

def get_current_user(authorization: str = Header(None)):  
    if not authorization:  
        # For demo purposes, create a default user if no token is provided  
        return {"sub": "demo_user", "name": "Demo User"}  
        
    if not authorization.startswith("Bearer "):  
        raise HTTPException(status_code=401, detail="Invalid authorization header")  
    
    token = authorization[7:]  
    user = verify_jwt_token(token)  
    return user  

def encrypt_file(data: bytes) -> bytes:  
    nonce = os.urandom(12)  
    aesgcm = AESGCM(AES_KEY)  
    encrypted = aesgcm.encrypt(nonce, data, None)  
    return nonce + encrypted  

def decrypt_file(encrypted_data: bytes) -> bytes:  
    nonce = encrypted_data[:12]  
    ciphertext = encrypted_data[12:]  
    aesgcm = AESGCM(AES_KEY)  
    return aesgcm.decrypt(nonce, ciphertext, None)  

def get_file_list() -> List[str]:
    try:
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET_NAME)
        objects = response.get("Contents", [])
        return [obj["Key"] for obj in objects]
    except Exception as e:
        print("S3 list error:", e)
        return []  

@app.post("/upload")  
async def upload_file(file: UploadFile = File(...), user=Depends(get_current_user)):  
    contents = await file.read()  
    try:  
        encrypted_data = encrypt_file(contents)  
    except Exception as e:  
        raise HTTPException(status_code=500, detail=f"Encryption failed: {str(e)}")  

    filename = os.path.basename(file.filename)  
    s3_client.put_object(Bucket=S3_BUCKET_NAME, Key=filename, Body=encrypted_data)  

    add_block(f"File uploaded: {filename} by user: {user.get('sub', 'unknown')}")  
    return {"message": f"File '{filename}' uploaded and encrypted successfully."}  


from fastapi.responses import StreamingResponse
from io import BytesIO

@app.get("/download/{filename}")
async def download_file(filename: str, user=Depends(get_current_user)):
    filename = os.path.basename(filename)
    try:
        obj = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=filename)
        encrypted_data = obj["Body"].read()
        decrypted_data = decrypt_file(encrypted_data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Download failed: {str(e)}")

    add_block(f"File downloaded: {filename} by user: {user.get('sub', 'unknown')}")
    return StreamingResponse(
        BytesIO(decrypted_data),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/files")  
async def list_files(user=Depends(get_current_user)):  
    files = get_file_list()  
    return {"files": files}  

@app.get("/logchain")  
def get_blockchain_log():  
    return blockchain_log  

@app.get("/login")  
def login(username: str, password: str):  
    # In a real app, you would verify credentials against a database  
    # This is a simple demo implementation  
    if username and password:  # Any non-empty username/password is accepted for demo  
        payload = {  
            "sub": username,  
            "name": username.capitalize(),  
            "exp": time.time() + 3600  # Token expires in 1 hour  
        }  
        token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)  
        return {"access_token": token, "token_type": "bearer"}  
    else:  
        raise HTTPException(status_code=401, detail="Invalid credentials")  

@app.get("/")  
def root():  
    return {"message": "Secure File Sharing System API. Use frontend to upload/download files."}  

# Mount static files handler for the frontend  
app.mount("/ui", StaticFiles(directory=".", html=True), name="static")  

# Initialize the application  
os.makedirs(STORAGE_DIR, exist_ok=True)  
load_blockchain_log()

# === AUTHENTICATION EXTENSION ===

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from passlib.context import CryptContext
from fastapi import Body

# Database setup
DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)

Base.metadata.create_all(bind=engine)

# Helpers
def get_user(db, username: str):
    return db.query(User).filter(User.username == username).first()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str):
    return pwd_context.hash(password)

# DB Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Register endpoint
@app.post("/register")
def register(username: str = Body(...), password: str = Body(...), db=Depends(get_db)):
    if get_user(db, username):
        raise HTTPException(status_code=400, detail="Username already exists")
    db_user = User(username=username, hashed_password=hash_password(password))
    db.add(db_user)
    db.commit()
    add_block(f"User registered: {username}")
    return {"message": "User registered successfully"}

# Updated login
@app.post("/login")
def login(username: str = Body(...), password: str = Body(...), db=Depends(get_db)):
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    payload = {
        "sub": username,
        "name": username.capitalize(),
        "exp": time.time() + 3600
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    add_block(f"User login: {username}")
    return {"access_token": token, "token_type": "bearer"}

# Logout endpoint (client-side clears token, server logs event)
@app.post("/logout")
def logout(user=Depends(get_current_user)):
    add_block(f"User logout: {user.get('sub')}")
    return {"message": f"User {user.get('sub')} logged out successfully"}

# === Phase 1 Blockchain Export & Filter ===


from fastapi.responses import StreamingResponse
import csv
from io import StringIO

@app.get("/logchain")
def get_logchain(user: str = None, event: str = None):
    if user or event:
        filtered = [block for block in blockchain if
                    (user in block["event"] if user else True) and
                    (event in block["event"] if event else True)]
        return filtered
    return blockchain

@app.get("/export-log")
def export_log(format: str = "csv"):
    if format == "json":
        return blockchain
    elif format == "csv":
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=["index", "timestamp", "event", "previous_hash", "hash"])
        writer.writeheader()
        for block in blockchain:
            writer.writerow(block)
        output.seek(0)
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=blockchain_log.csv"})
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")



@app.delete("/delete/{filename}")
def delete_file(filename: str, user=Depends(get_current_user)):
    filename = os.path.basename(filename)
    try:
        s3_client.delete_object(Bucket=S3_BUCKET_NAME, Key=filename)
        add_block(f"File deleted: {filename} by user: {user.get('sub', 'unknown')}")
        return {"message": f"File '{filename}' deleted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Deletion failed: {str(e)}")
