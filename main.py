from fastapi import FastAPI, Request, Response, HTTPException, status, Depends, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from jose import jwt, JWTError
from datetime import datetime, timedelta
import time

app = FastAPI()
templates = Jinja2Templates(directory="templates")

SECRET_KEY = "not_your_key_not_your_token"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

@app.get("/", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("jwt_login.html", {"request": request})

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/token")
async def login_for_token(
    username: str = Form(...),
    role: str = Form(...),
    lang: str = Form(...),
    uid: int = Form(...)
):
    if not username:
        raise HTTPException(status_code=400, detail="Kein Nutzername angegeben.")
    token = create_access_token({
        "sub": username,
        "role": role,
        "lang": lang,
        "uid": uid
    })
    return {"access_token": token, "token_type": "bearer"}

async def verify_token(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token fehlt")
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Ungültiger Token")

@app.get("/protected")
async def protected(request: Request,user: str = Depends(verify_token)):
    token = request.headers.get("Authorization").split(" ")[1]
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return {
        "user": payload.get("sub"),
        "role": payload.get("role"),
        "lang": payload.get("lang"),
        "uid": payload.get("uid")
    }
