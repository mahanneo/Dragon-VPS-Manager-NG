from pathlib import Path
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from .config import APP_NAME, VERSION, COOKIE_NAME, ALLOWED_SERVICES
from .db import init_db, connect, audit
from .security import verify_password, make_session, read_session, hash_password
from . import system_ops

BASE = Path(__file__).resolve().parent
app = FastAPI(title=APP_NAME, version=VERSION, docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")

@app.on_event("startup")
def startup(): init_db()

def current_user(request: Request): return read_session(request.cookies.get(COOKIE_NAME))

def require_user(request: Request):
    user = current_user(request)
    if not user: raise HTTPException(status_code=401, detail="authentication required")
    return user

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    if not current_user(request): return RedirectResponse("/login", 302)
    return templates.TemplateResponse("dashboard.html", {"request":request, "app_name":APP_NAME, "version":VERSION})

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request":request, "app_name":APP_NAME, "version":VERSION, "error":None})

@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    with connect() as con: row = con.execute("SELECT * FROM admins WHERE username=? AND active=1", (username,)).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        audit(username or "unknown", "login_failed", ip=request.client.host if request.client else None)
        return templates.TemplateResponse("login.html", {"request":request,"app_name":APP_NAME,"version":VERSION,"error":"نام کاربری یا رمز عبور صحیح نیست."}, status_code=401)
    audit(username, "login_success", ip=request.client.host if request.client else None)
    r = RedirectResponse("/", 302)
    r.set_cookie(COOKIE_NAME, make_session(username), httponly=True, secure=False, samesite="strict", max_age=43200)
    return r

@app.post("/logout")
def logout(request: Request):
    user=current_user(request)
    if user: audit(user,"logout",ip=request.client.host if request.client else None)
    r=RedirectResponse("/login",302); r.delete_cookie(COOKIE_NAME); return r

@app.get("/api/overview")
def overview(request: Request):
    require_user(request)
    services=[]
    for name in ALLOWED_SERVICES:
        try: services.append(system_ops.service_status(name))
        except Exception as e: services.append({"name":name,"label":ALLOWED_SERVICES[name],"active":False,"state":"error"})
    return {"version":VERSION,"metrics":system_ops.metrics(),"services":services,"users":len(system_ops.ssh_users())}

@app.get("/api/users")
def users(request: Request): require_user(request); return system_ops.ssh_users()

class UserCreate(BaseModel): username:str; password:str; expire:str|None=None
@app.post("/api/users")
def create_user(payload: UserCreate, request: Request):
    actor=require_user(request)
    try: result=system_ops.create_ssh_user(payload.username,payload.password,payload.expire)
    except system_ops.OperationError as e: raise HTTPException(400,str(e))
    audit(actor,"ssh_user_create",payload.username,payload.expire,request.client.host if request.client else None); return result

@app.post("/api/users/{username}/{mode}")
def user_mode(username:str, mode:str, request:Request):
    actor=require_user(request)
    try:
        if mode=="lock": result=system_ops.lock_user(username,True)
        elif mode=="unlock": result=system_ops.lock_user(username,False)
        elif mode=="delete": result=system_ops.delete_user(username)
        else: raise HTTPException(404,"unknown action")
    except system_ops.OperationError as e: raise HTTPException(400,str(e))
    audit(actor,f"ssh_user_{mode}",username,ip=request.client.host if request.client else None); return result

@app.post("/api/services/{name}/{action}")
def service(name:str, action:str, request:Request):
    actor=require_user(request)
    try: result=system_ops.service_action(name,action)
    except system_ops.OperationError as e: raise HTTPException(400,str(e))
    audit(actor,f"service_{action}",name,ip=request.client.host if request.client else None); return result

@app.get("/api/audit")
def audit_list(request:Request, limit:int=100):
    require_user(request); limit=max(1,min(limit,500))
    with connect() as con: rows=con.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [dict(r) for r in rows]

class PasswordChange(BaseModel): current_password:str; new_password:str
@app.post("/api/admin/password")
def change_password(payload:PasswordChange, request:Request):
    actor=require_user(request)
    if len(payload.new_password)<12: raise HTTPException(400,"new password must be at least 12 characters")
    with connect() as con:
        row=con.execute("SELECT * FROM admins WHERE username=?",(actor,)).fetchone()
        if not row or not verify_password(payload.current_password,row["password_hash"]): raise HTTPException(400,"current password is incorrect")
        con.execute("UPDATE admins SET password_hash=? WHERE username=?",(hash_password(payload.new_password),actor))
    audit(actor,"admin_password_change",actor,ip=request.client.host if request.client else None); return {"ok":True}

@app.get("/healthz")
def healthz(): return {"ok":True,"version":VERSION}
