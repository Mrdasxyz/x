from fastapi import FastAPI, Request, Form, Depends, HTTPException, Header
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, Column, Integer, String, MetaData, Table
from sqlalchemy.orm import declarative_base, Session
import uvicorn
import rsa
import base64
from typing import Optional

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Aiven Cloud MySQL credentials
db_credentials = {
    'host': 'mysql-30c37a4d-projectx.a.aivencloud.com',
    'port': 13625,
    'user': 'avnadmin',
    'password': 'AVNS_og4Acl6XOMIp2M3NyB2',
    'db': 'defaultdb',
    'ssl': {'sslmode': 'REQUIRED'}
}

# SQLAlchemy setup
DATABASE_URL = f"mysql+pymysql://{db_credentials['user']}:{db_credentials['password']}@{db_credentials['host']}:{db_credentials['port']}/{db_credentials['db']}"
engine = create_engine(DATABASE_URL)
Base = declarative_base()


class KCEncryptDecrypt(object):
    def __init__(self, user_id):
        self.publicKey, self.privateKey = rsa.newkeys(512)
        self.user_id = user_id

    def encrypt(self, pwd):
        encrypt_data = rsa.encrypt(pwd.encode('utf-8'), self.publicKey)
        base64_data = base64.b64encode(encrypt_data)
        return base64_data

    def decrypt(self, base64_data):
        decrypt_data = rsa.decrypt(base64.b64decode(base64_data), self.privateKey).decode('utf-8')
        return decrypt_data


# Create a table class using SQLAlchemy ORM
class UserData(Base):
    __tablename__ = 'user_data'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), index=True)
    email = Column(String(255), index=True)
    address = Column(String(255))
    position = Column(String(255))
    public_key = Column(String(4096))  # Adjust the size based on your RSA key size

# Create the table
metadata = MetaData()
user_data_table = Table('user_data', metadata,
                       Column('id', Integer, primary_key=True, index=True),
                       Column('name', String(255), index=True),
                       Column('email', String(255), index=True),
                       Column('address', String(255)),
                       Column('position', String(255)),
                       Column('public_key', String(4096)),
                       )

metadata.create_all(bind=engine)

# Dependency to get the database session
def get_db():
    db = Session(engine)
    try:
        yield db
    finally:
        db.close()

# Dependency to get RSA keys for the user
def get_rsa_keys(user_id: int, db: Session = Depends(get_db)):
    user = db.query(UserData).filter(UserData.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    encrypt_decrypt = KCEncryptDecrypt(user_id)
    return encrypt_decrypt

@app.get("/headers/")
async def read_header(accept_language: Optional[str] = Header(None)):
    return {"Accept-Language": accept_language} 

@app.get("/rspheader/")
def set_rsp_headers():
    content = {"message": "Hello World"}
    headers = {"X-Web-Framework": "FastAPI", "Content-Language": "en-US"}
    return JSONResponse(content=content, headers=headers)

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("upload_form_template.html", {"request": request})

@app.post("/submit")
async def submit(
    name: str = Form(...),
    email: str = Form(...),
    address: str = Form(...),
    position: str = Form(...),
    rsa_keys: KCEncryptDecrypt = Depends(get_rsa_keys),
    db: Session = Depends(get_db)
):
    password = input("Enter password for RSA encryption: ")  # Prompt for password
    encrypted_password = rsa_keys.encrypt(password)
    
    user_data = UserData(name=name, email=email, address=address, position=position, public_key=encrypted_password)
    db.add(user_data)
    db.commit()

    return {"message": "Data submitted successfully."}

@app.get("/search", response_class=HTMLResponse)
async def search_form(request: Request):
    return templates.TemplateResponse("search_form_template.html", {"request": request})

@app.post("/search")
async def search(
    search_name: str = Form(...),
    password: str = Form(...),  # Prompt for password
    rsa_keys: KCEncryptDecrypt = Depends(get_rsa_keys),
    db: Session = Depends(get_db)
):
    user_data = db.query(UserData).filter(UserData.name == search_name).first()
    if not user_data:
        raise HTTPException(status_code=404, detail="User not found")

    decrypted_password = rsa_keys.decrypt(user_data.public_key)
    
    if password != decrypted_password:
        raise HTTPException(status_code=403, detail="Incorrect password")

    return {"search_result": user_data}

if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8000)
