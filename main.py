import os  
import json  
import base64 
import hashlib  
import time  
import uuid  
import io  
from typing import Dict, List, Optional, Union  
from datetime import datetime, timedelta  

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Header, Query  
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse  
from fastapi.middleware.cors import CORSMiddleware  
from fastapi.staticfiles import StaticFiles  
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  
from jose import jwt, JWTError  
import boto3  
from botocore.exceptions import ClientError  
from pydantic import BaseModel  

app = FastAPI(title="Secure File Sharing System",   
              description="A secure file sharing system with blockchain audit logs and AES-256 encryption")  

# Enable CORS for frontend  
app.add_middleware(  
    CORSMiddleware,  
    allow_origins=["*"],  # For demo only; restrict in production  
    allow_methods=["*"],  
    allow_headers=["*"],  
)  

# Configuration  
class AppConfig:  
    # Storage options (S3 or local)  
    STORAGE_TYPE = os.getenv("STORAGE_TYPE", "local")  # "s3" or "local"  
    
    # Local storage settings  
    LOCAL_STORAGE_DIR = os.getenv("LOCAL_STORAGE_DIR", "encrypted_files")  
    
    # S3 settings  
    S3_BUCKET_NAME = os.getenv("S3_BUCKET_NAME", "secure-file-sharing-demo")  
    S3_REGION = os.getenv("S3_REGION", "us-east-1")  
    S3_PREFIX = os.getenv("S3_PREFIX", "encrypted/")  
    
    # Blockchain log settings  
    BLOCKCHAIN_FILE = os.getenv("BLOCKCHAIN_FILE", "blockchain_log.json")  
    
    # Encryption settings  
    AES_KEY = os.getenv("AES_KEY", "0123456789abcdef0123456789abcdef").encode()  
    
    # JWT settings  
    JWT_SECRET = os.getenv("JWT_SECRET", "your-secret-key-for-jwt-signing")  
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")  
    JWT_EXPIRATION_MINUTES = int(os.getenv("JWT_EXPIRATION_MINUTES", "60"))  
    
    # File size limits  
    MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", "100"))  # 100MB by default  

config = AppConfig()  

# Initialize S3 client if using S3 storage  
s3_client = None  
if config.STORAGE_TYPE == "s3":  
    try:  
        s3_client = boto3.client('s3', region_name=config.S3_REGION)  
    except Exception as e:  
        print(f"Warning: S3 client initialization failed: {str(e)}")  
        print("Falling back to local storage.")  
        config.STORAGE_TYPE = "local"  

# Initialize blockchain log  
blockchain_log = []  

class ShareLinkModel(BaseModel):  
    file_id: str  
    expiration_days: int = 7  
    max_downloads: Optional[int] = None  

class ShareLink(BaseModel):  
    id: str  
    file_id: str  
    created_at: float  
    expires_at: float  
    max_downloads: Optional[int] = None  
    downloads: int = 0  

# In-memory storage for share links (would use a database in production)  
share_links = {}  

def load_blockchain_log():  
    global blockchain_log  
    if config.STORAGE_TYPE == "s3" and s3_client:  
        try:  
            response = s3_client.get_object(Bucket=config.S3_BUCKET_NAME, Key=config.BLOCKCHAIN_FILE)  
            blockchain_log = json.loads(response['Body'].read().decode('utf-8'))  
        except ClientError as e:  
            if e.response['Error']['Code'] == 'NoSuchKey':  
                initialize_blockchain()  
            else:  
                raise  
    elif os.path.exists(config.BLOCKCHAIN_FILE):  
        with open(config.BLOCKCHAIN_FILE, "r") as f:  
            blockchain_log = json.load(f)  
    else:  
        initialize_blockchain()  

def initialize_blockchain():  
    global blockchain_log  
    genesis_block = {  
        "index": 0,  
        "timestamp": time.time(),  
        "prev_hash": "0"*64,  
        "event": "Genesis block",  
        "data": {  
            "creator": "system",  
            "type": "initialization"  
        },  
        "hash": ""  
    }  
    genesis_block["hash"] = calculate_hash(genesis_block)  
    blockchain_log = [genesis_block]  
    save_blockchain_log()  

def save_blockchain_log():  
    if config.STORAGE_TYPE == "s3" and s3_client:  
        try:  
            s3_client.put_object(  
                Bucket=config.S3_BUCKET_NAME,  
                Key=config.BLOCKCHAIN_FILE,  
                Body=json.dumps(blockchain_log, indent=2).encode('utf-8'),  
                ContentType='application/json'  
            )  
        except Exception as e:  
            print(f"Error saving blockchain to S3: {str(e)}")  
            # Fallback to local file  
            with open(config.BLOCKCHAIN_FILE, "w") as f:  
                json.dump(blockchain_log, f, indent=2)  
    else:  
        with open(config.BLOCKCHAIN_FILE, "w") as f:  
            json.dump(blockchain_log, f, indent=2)  

def calculate_hash(block: Dict) -> str:  
    # Create a string representation of the block (excluding hash)  
    block_copy = block.copy()  
    if "hash" in block_copy:  
        del block_copy["hash"]  
    
    # Convert to ordered JSON string for consistent hashing  
    data_string = json.dumps(block_copy, sort_keys=True)  
    return hashlib.sha256(data_string.encode()).hexdigest()  

def verify_blockchain_integrity() -> Dict:  
    results = {"valid": True, "errors": []}  
    
    for i in range(1, len(blockchain_log)):  
        current_block = blockchain_log[i]  
        prev_block = blockchain_log[i-1]  
        
        # Check that previous hash matches  
        if current_block["prev_hash"] != prev_block["hash"]:  
            results["valid"] = False  
            results["errors"].append(f"Block {i}: Previous hash mismatch")  
        
        # Check that current hash is valid  
        calculated_hash = calculate_hash(current_block)  
        if current_block["hash"] != calculated_hash:  
            results["valid"] = False  
            results["errors"].append(f"Block {i}: Hash mismatch")  
    
    return results  

def add_block(event: str, data: Dict = None):  
    if data is None:  
        data = {}  
    
    prev_block = blockchain_log[-1]  
    new_block = {  
        "index": prev_block["index"] + 1,  
        "timestamp": time.time(),  
        "prev_hash": prev_block["hash"],  
        "event": event,  
        "data": data,  
        "hash": ""  
    }  
    new_block["hash"] = calculate_hash(new_block)  
    blockchain_log.append(new_block)  
    save_blockchain_log()  
    return new_block  

def verify_jwt_token(token: str) -> Dict:  
    try:  
        payload = jwt.decode(token, config.JWT_SECRET, algorithms=[config.JWT_ALGORITHM])  
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

def encrypt_file(data: bytes, metadata: Dict = None) -> bytes:  
    """Encrypt file with AES-GCM and include metadata in the encrypted file."""  
    # Generate a random nonce  
    nonce = os.urandom(12)  
    
    # Convert metadata to JSON bytes if provided  
    metadata_bytes = b""  
    if metadata:  
        metadata_bytes = json.dumps(metadata).encode('utf-8')  
    
    # Get metadata length as 4-byte integer  
    metadata_length = len(metadata_bytes).to_bytes(4, byteorder='big')  
    
    # Create AESGCM cipher  
    aesgcm = AESGCM(config.AES_KEY)  
    
    # Encrypt the data  
    encrypted_data = aesgcm.encrypt(nonce, data, None)  
    
    # Format: nonce (12 bytes) + metadata_length (4 bytes) + metadata + encrypted_data  
    return nonce + metadata_length + metadata_bytes + encrypted_data  

def decrypt_file(encrypted_data: bytes) -> tuple:  
    """Decrypt file and return the data and metadata if available."""  
    # Extract nonce (first 12 bytes)  
    nonce = encrypted_data[:12]  
    
    # Extract metadata length (next 4 bytes)  
    metadata_length = int.from_bytes(encrypted_data[12:16], byteorder='big')  
    
    # Extract metadata if present  
    metadata = None  
    if metadata_length > 0:  
        metadata_bytes = encrypted_data[16:16+metadata_length]  
        try:  
            metadata = json.loads(metadata_bytes.decode('utf-8'))  
        except:  
            metadata = None  
    
    # Extract ciphertext  
    ciphertext_start = 16 + metadata_length  
    ciphertext = encrypted_data[ciphertext_start:]  
    
    # Decrypt the data  
    aesgcm = AESGCM(config.AES_KEY)  
    data = aesgcm.decrypt(nonce, ciphertext, None)  
    
    return data, metadata  

def store_file(file_id: str, encrypted_data: bytes) -> bool:  
    """Store an encrypted file in the configured storage backend."""  
    try:  
        if config.STORAGE_TYPE == "s3" and s3_client:  
            s3_client.put_object(  
                Bucket=config.S3_BUCKET_NAME,  
                Key=f"{config.S3_PREFIX}{file_id}",  
                Body=encrypted_data  
            )  
        else:  
            os.makedirs(config.LOCAL_STORAGE_DIR, exist_ok=True)  
            with open(os.path.join(config.LOCAL_STORAGE_DIR, file_id), "wb") as f:  
                f.write(encrypted_data)  
        return True  
    except Exception as e:  
        print(f"Error storing file: {str(e)}")  
        return False  

def retrieve_file(file_id: str) -> Optional[bytes]:  
    """Retrieve an encrypted file from the configured storage backend."""  
    try:  
        if config.STORAGE_TYPE == "s3" and s3_client:  
            response = s3_client.get_object(  
                Bucket=config.S3_BUCKET_NAME,  
                Key=f"{config.S3_PREFIX}{file_id}"  
            )  
            return response['Body'].read()  
        else:  
            filepath = os.path.join(config.LOCAL_STORAGE_DIR, file_id)  
            if not os.path.exists(filepath):  
                return None  
            with open(filepath, "rb") as f:  
                return f.read()  
    except Exception as e:  
        print(f"Error retrieving file: {str(e)}")  
        return None  

def list_files() -> List[Dict]:  
    """List all files in the configured storage backend with metadata."""  
    files = []  
    
    try:  
        if config.STORAGE_TYPE == "s3" and s3_client:  
            # List objects in the S3 bucket with the specified prefix  
            response = s3_client.list_objects_v2(  
                Bucket=config.S3_BUCKET_NAME,  
                Prefix=config.S3_PREFIX  
            )  
            
            if 'Contents' in response:  
                for item in response['Contents']:  
                    file_id = item['Key'].replace(config.S3_PREFIX, '')  
                    if file_id:  # Skip empty strings or directory markers  
                        files.append({  
                            "id": file_id,  
                            "size": item['Size'],  
                            "last_modified": item['LastModified'].timestamp()  
                        })  
        else:  
            # List files in the local storage directory  
            if os.path.exists(config.LOCAL_STORAGE_DIR):  
                for filename in os.listdir(config.LOCAL_STORAGE_DIR):  
                    filepath = os.path.join(config.LOCAL_STORAGE_DIR, filename)  
                    if os.path.isfile(filepath):  
                        stat = os.stat(filepath)  
                        files.append({  
                            "id": filename,  
                            "size": stat.st_size,  
                            "last_modified": stat.st_mtime  
                        })  
    except Exception as e:  
        print(f"Error listing files: {str(e)}")  
    
    # Add file metadata by checking the blockchain log  
    for file in files:  
        # Find the upload event for this file  
        for block in reversed(blockchain_log):  
            if block["event"] == "File uploaded" and block["data"].get("file_id") == file["id"]:  
                file["name"] = block["data"].get("original_filename", file["id"])  
                file["uploaded_by"] = block["data"].get("user", "unknown")  
                file["uploaded_at"] = block["timestamp"]  
                break  
    
    return files  

def delete_file(file_id: str) -> bool:  
    """Delete a file from the storage backend."""  
    try:  
        if config.STORAGE_TYPE == "s3" and s3_client:  
            s3_client.delete_object(  
                Bucket=config.S3_BUCKET_NAME,  
                Key=f"{config.S3_PREFIX}{file_id}"  
            )  
        else:  
            filepath = os.path.join(config.LOCAL_STORAGE_DIR, file_id)  
            if os.path.exists(filepath):  
                os.remove(filepath)  
        return True  
    except Exception as e:  
        print(f"Error deleting file: {str(e)}")  
        return False  

def create_share_link(file_id: str, expiration_days: int = 7, max_downloads: Optional[int] = None) -> ShareLink:  
    """Create a share link for a file."""  
    # Verify file exists  
    file_data = retrieve_file(file_id)  
    if not file_data:  
        raise HTTPException(status_code=404, detail="File not found")  
    
    # Create share link  
    link_id = str(uuid.uuid4())  
    now = time.time()  
    expires_at = now + (expiration_days * 24 * 60 * 60)  
    
    share_link = ShareLink(  
        id=link_id,  
        file_id=file_id,  
        created_at=now,  
        expires_at=expires_at,  
        max_downloads=max_downloads,  
        downloads=0  
    )  
    
    # Store share link  
    share_links[link_id] = share_link  
    
    return share_link  

@app.post("/upload")  
async def upload_file(file: UploadFile = File(...), user=Depends(get_current_user)):  
    # Validate file size  
    contents = await file.read()  
    file_size_mb = len(contents) / (1024 * 1024)  
    if file_size_mb > config.MAX_FILE_SIZE_MB:  
        raise HTTPException(  
            status_code=413,   
            detail=f"File too large. Maximum size is {config.MAX_FILE_SIZE_MB}MB."  
        )  
    
    try:  
        # Generate a unique file ID (using UUID)  
        file_id = str(uuid.uuid4())  
        
        # Add metadata for the file  
        metadata = {  
            "original_filename": file.filename,  
            "content_type": file.content_type,  
            "uploaded_by": user.get("sub", "unknown"),  
            "upload_time": time.time()  
        }  
        
        # Encrypt the file with metadata  
        encrypted_data = encrypt_file(contents, metadata)  
        
        # Store the encrypted file  
        if not store_file(file_id, encrypted_data):  
            raise HTTPException(status_code=500, detail="Failed to store file")  
        
        # Add a block to the blockchain  
        add_block("File uploaded", {  
            "file_id": file_id,  
            "original_filename": file.filename,  
            "user": user.get("sub", "unknown"),  
            "size": len(contents),  
            "content_type": file.content_type  
        })  
        
        return {  
            "message": f"File '{file.filename}' uploaded and encrypted successfully.",  
            "file_id": file_id  
        }  
    except Exception as e:  
        raise HTTPException(status_code=500, detail=f"Error during upload: {str(e)}")  

@app.get("/download/{file_id}")  
async def download_file(file_id: str, user=Depends(get_current_user)):  
    try:  
        # Retrieve the encrypted file  
        encrypted_data = retrieve_file(file_id)  
        if not encrypted_data:  
            raise HTTPException(status_code=404, detail="File not found")  
        
        # Decrypt the file  
        decrypted_data, metadata = decrypt_file(encrypted_data)  
        
        # Get original filename if available  
        filename = metadata.get("original_filename", file_id) if metadata else file_id  
        
        # Add a block to the blockchain  
        add_block("File downloaded", {  
            "file_id": file_id,  
            "user": user.get("sub", "unknown"),  
            "filename": filename  
        })  
        
        # Return the decrypted file as a download  
        return StreamingResponse(  
            io.BytesIO(decrypted_data),  
            media_type="application/octet-stream",  
            headers={"Content-Disposition": f"attachment; filename=\"{filename}\""}  
        )  
    except Exception as e:  
        raise HTTPException(status_code=500, detail=f"Error during download: {str(e)}")  

@app.get("/files")  
async def list_available_files(user=Depends(get_current_user)):  
    files = list_files()  
    return {"files": files}  

@app.delete("/files/{file_id}")  
async def delete_file_endpoint(file_id: str, user=Depends(get_current_user)):  
    # Check if file exists  
    if not retrieve_file(file_id):  
        raise HTTPException(status_code=404, detail="File not found")  
    
    # Delete the file  
    if delete_file(file_id):  
        # Add a block to the blockchain  
        add_block("File deleted", {  
            "file_id": file_id,  
            "user": user.get("sub", "unknown")  
        })  
        return {"message": f"File {file_id} deleted successfully"}  
    else:  
        raise HTTPException(status_code=500, detail="Failed to delete file")  

@app.post("/share")  
async def create_share_link_endpoint(  
    share_data: ShareLinkModel,   
    user=Depends(get_current_user)  
):  
    try:  
        # Check if file exists  
        if not retrieve_file(share_data.file_id):  
            raise HTTPException(status_code=404, detail="File not found")  
        
        # Create share link  
        share_link = create_share_link(  
            share_data.file_id,   
            share_data.expiration_days,   
            share_data.max_downloads  
        )  
        
        # Add a block to the blockchain  
        add_block("Share link created", {  
            "file_id": share_data.file_id,  
            "link_id": share_link.id,  
            "user": user.get("sub", "unknown"),  
            "expires_at": share_link.expires_at,  
            "max_downloads": share_link.max_downloads  
        })  
        
        return {  
            "message": "Share link created successfully",  
            "link_id": share_link.id,  
            "expires_at": share_link.expires_at,  
            "download_url": f"/shared/{share_link.id}"  
        }  
    except Exception as e:  
        raise HTTPException(status_code=500, detail=f"Error creating share link: {str(e)}")  

@app.get("/shared/{link_id}")  
async def download_shared_file(link_id: str):  
    # Check if share link exists  
    if link_id not in share_links:  
        raise HTTPException(status_code=404, detail="Share link not found or expired")  
    
    share_link = share_links[link_id]  
    
    # Check if share link is expired  
    if time.time() > share_link.expires_at:  
        del share_links[link_id]  
        raise HTTPException(status_code=410, detail="Share link has expired")  
    
    # Check if max downloads reached  
    if share_link.max_downloads and share_link.downloads >= share_link.max_downloads:  
        raise HTTPException(status_code=410, detail="Maximum downloads reached")  
    
    try:  
        # Retrieve and decrypt the file  
        encrypted_data = retrieve_file(share_link.file_id)  
        if not encrypted_data:  
            raise HTTPException(status_code=404, detail="File not found")  
        
        decrypted_data, metadata = decrypt_file(encrypted_data)  
        
        # Get original filename if available  
        filename = metadata.get("original_filename", share_link.file_id) if metadata else share_link.file_id  
        
        # Increment download counter  
        share_link.downloads += 1  
        
        # Add a block to the blockchain  
        add_block("Shared file downloaded", {  
            "file_id": share_link.file_id,  
            "link_id": link_id,  
            "user": "anonymous"  
        })  
        
        # Return the decrypted file  
        return StreamingResponse(  
            io.BytesIO(decrypted_data),  
            media_type="application/octet-stream",  
            headers={"Content-Disposition": f"attachment; filename=\"{filename}\""}  
        )  
    except Exception as e:  
        raise HTTPException(status_code=500, detail=f"Error during download: {str(e)}")  

@app.get("/logchain")  
def get_blockchain_log(limit: int = Query(10, description="Limit the number of entries returned")):  
    if limit < 0:  
        limit = len(blockchain_log)  
        
    return blockchain_log[-limit:] if limit < len(blockchain_log) else blockchain_log  

@app.get("/logchain/verify")  
def verify_blockchain():  
    return verify_blockchain_integrity()  

@app.get("/login")  
def login(username: str, password: str):  
    # In a real app, you would verify credentials against a database  
    # This is a simple demo implementation  
    if username and password:  # Any non-empty username/password is accepted for demo  
        payload = {  
            "sub": username,  
            "name": username.capitalize(),  
            "exp": time.time() + (config.JWT_EXPIRATION_MINUTES * 60)  
        }  
        token = jwt.encode(payload, config.JWT_SECRET, algorithm=config.JWT_ALGORITHM)  
        return {"access_token": token, "token_type": "bearer"}  
    else:  
        raise HTTPException(status_code=401, detail="Invalid credentials")  

@app.get("/")  
def root():  
    return {  
        "message": "Secure File Sharing System API",  
        "version": "1.0.0",  
        "features": [  
            "AES-256 encryption",  
            "Blockchain audit logs",  
            "File sharing",  
            "AWS S3 integration (optional)"  
        ]  
    }  

# Mount static files handler for the frontend  
app.mount("/ui", StaticFiles(directory=".", html=True), name="static")  

# Initialize the application  
if config.STORAGE_TYPE == "local":  
    os.makedirs(config.LOCAL_STORAGE_DIR, exist_ok=True)  
load_blockchain_log()