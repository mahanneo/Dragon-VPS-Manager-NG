from pathlib import Path
from datetime import date, datetime, timedelta
import time, io, base64, secrets, string, urllib.request
import pyotp, qrcode
import qrcode.image.svg
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from .config import APP_NAME, VERSION, COOKIE_NAME, ALLOWED_SERVICES, DATA_DIR
from .db import init_db, connect, audit, upsert_profile, all_profiles, delete_profile, metrics_since, get_admin_2fa, set_admin_totp_secret, set_admin_totp_enabled, clear_admin_totp, create_api_token, list_api_tokens, revoke_api_token, verify_api_token, create_node, list_nodes, revoke_node, node_by_token, update_node_heartbeat
from .security import verify_password, make_session, read_session, hash_password, make_preauth, read_preauth
from . import system_ops, protocol_ops

BASE=Path(__file__).resolve().parent
app=FastAPI(title=APP_NAME,version=VERSION,docs_url=None,redoc_url=None)
app.mount("/static",StaticFiles(directory=BASE/"static"),name="static")
templates=Jinja2Templates(directory=BASE/"templates")

@app.on_event("startup")
def startup(): init_db()

def current_user(request:Request): return read_session(request.cookies.get(COOKIE_NAME))
def require_user(request:Request):
    user=current_user(request)
    if not user: raise HTTPException(status_code=401,detail="authentication required")
    return user

def require_mutation(request:Request):
    user=require_user(request)
    if request.headers.get("x-makia-request")!="1":
        raise HTTPException(status_code=403,detail="invalid management request")
    return user

def ip(request:Request): return request.client.host if request.client else None

def bearer(request:Request):
    auth=request.headers.get("authorization","")
    if auth.lower().startswith("bearer "):
        return auth.split(" ",1)[1].strip()
    return None

def require_api_scope(request:Request,scope:str):
    token=bearer(request)
    if not token:
        raise HTTPException(status_code=401,detail="bearer token required")
    identity=verify_api_token(token,scope)
    if not identity:
        raise HTTPException(status_code=403,detail="invalid token or scope")
    return identity

def days_left(expire_date):
    if not expire_date: return None
    try: return (date.fromisoformat(str(expire_date))-date.today()).days
    except Exception: return None


def generate_user_secret(mode:str="strong"):
    mode=(mode or "strong").lower()
    if mode=="pin4":
        return "".join(secrets.choice(string.digits) for _ in range(4))
    if mode=="pin6":
        return "".join(secrets.choice(string.digits) for _ in range(6))
    if mode=="easy8":
        alphabet="ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        return "".join(secrets.choice(alphabet) for _ in range(8))
    if mode=="strong":
        alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%"
        return "".join(secrets.choice(alphabet) for _ in range(14))
    raise HTTPException(400,"unknown password mode")

def suggested_username():
    used={u["username"] for u in system_ops.ssh_users()}
    for i in range(1,10000):
        name=f"user{i:03d}"
        if name not in used:
            return name
    return "user"+secrets.token_hex(2)

def account_rows():
    profiles=all_profiles()
    sessions=system_ops.online_sessions()
    counts={}
    for s in sessions: counts[s["username"]]=counts.get(s["username"],0)+1
    rows=[]
    for u in system_ops.ssh_users():
        p=profiles.get(u["username"],{})
        left=days_left(p.get("expire_date"))
        rows.append({
            **u,
            "plan":p.get("plan",""),
            "note":p.get("note",""),
            "expire_date":p.get("expire_date"),
            "days_left":left,
            "connection_limit":int(p.get("connection_limit",1) or 1),
            "quota_mb":int(p.get("quota_mb",0) or 0),
            "enabled":bool(p.get("enabled",1)),
            "online":counts.get(u["username"],0),
            "expired":left is not None and left<0,
        })
    return rows

@app.get("/",response_class=HTMLResponse)
def root(request:Request):
    if not current_user(request): return RedirectResponse("/login",302)
    return templates.TemplateResponse("dashboard.html",{"request":request,"app_name":APP_NAME,"version":VERSION})

@app.get("/login",response_class=HTMLResponse)
def login_page(request:Request):
    return templates.TemplateResponse("login.html",{"request":request,"app_name":APP_NAME,"version":VERSION,"error":None})

@app.post("/login")
def login(request:Request,username:str=Form(...),password:str=Form(...)):
    with connect() as con:
        row=con.execute("SELECT * FROM admins WHERE username=? AND active=1",(username,)).fetchone()
    if not row or not verify_password(password,row["password_hash"]):
        audit(username or "unknown","login_failed",ip=ip(request))
        return templates.TemplateResponse("login.html",{"request":request,"app_name":APP_NAME,"version":VERSION,"error":"نام کاربری یا رمز عبور صحیح نیست."},status_code=401)
    twofa=get_admin_2fa(username)
    if twofa and twofa.get("totp_enabled"):
        audit(username,"login_password_success_2fa_required",ip=ip(request))
        return templates.TemplateResponse("login_2fa.html",{"request":request,"app_name":APP_NAME,"version":VERSION,"token":make_preauth(username),"error":None})
    audit(username,"login_success",ip=ip(request))
    r=RedirectResponse("/",302)
    secure_cookie=request.headers.get("x-forwarded-proto","").lower()=="https"
    r.set_cookie(COOKIE_NAME,make_session(username),httponly=True,secure=secure_cookie,samesite="strict",max_age=43200)
    return r

@app.post("/login/2fa")
def login_2fa(request:Request,token:str=Form(...),code:str=Form(...)):
    username=read_preauth(token)
    if not username:
        return RedirectResponse("/login",302)
    state=get_admin_2fa(username)
    valid=bool(state and state.get("totp_enabled") and state.get("totp_secret") and pyotp.TOTP(state["totp_secret"]).verify(code.strip(),valid_window=1))
    if not valid:
        audit(username,"login_2fa_failed",ip=ip(request))
        return templates.TemplateResponse("login_2fa.html",{"request":request,"app_name":APP_NAME,"version":VERSION,"token":token,"error":"کد تایید صحیح نیست."},status_code=401)
    audit(username,"login_success_2fa",ip=ip(request))
    r=RedirectResponse("/",302)
    secure_cookie=request.headers.get("x-forwarded-proto","").lower()=="https"
    r.set_cookie(COOKIE_NAME,make_session(username),httponly=True,secure=secure_cookie,samesite="strict",max_age=43200)
    return r

@app.post("/logout")
def logout(request:Request):
    user=current_user(request)
    if user: audit(user,"logout",ip=ip(request))
    r=RedirectResponse("/login",302); r.delete_cookie(COOKIE_NAME); return r

@app.get("/api/overview")
def overview(request:Request):
    require_user(request)
    services=[]
    for name in ALLOWED_SERVICES:
        try: services.append(system_ops.service_status(name))
        except Exception: services.append({"name":name,"label":ALLOWED_SERVICES[name],"active":False,"state":"error"})
    sessions=system_ops.online_sessions()
    accounts=account_rows()
    expiring=sum(1 for a in accounts if a["days_left"] is not None and 0<=a["days_left"]<=7)
    violations=sum(1 for a in accounts if a["online"]>a["connection_limit"])
    return {
        "version":VERSION,
        "metrics":system_ops.metrics(),
        "services":services,
        "users":len(accounts),
        "online_sessions":len(sessions),
        "online_users":len({s["username"] for s in sessions}),
        "expiring_soon":expiring,
        "limit_violations":violations,
        "sessions":sessions[:25],
    }

@app.get("/api/metrics/history")
def metric_history(request:Request,hours:int=24):
    require_user(request)
    hours=max(1,min(hours,168))
    return metrics_since(int(time.time())-hours*3600)

@app.get("/api/accounts")
def accounts(request:Request):
    require_user(request)
    return account_rows()

class AccountCreate(BaseModel):
    username:str
    password:str|None=Field(default=None,min_length=4,max_length=128)
    password_mode:str="manual"
    expire_date:str|None=None
    plan:str=""
    note:str=""
    connection_limit:int=Field(default=1,ge=1,le=50)
    quota_mb:int=Field(default=0,ge=0,le=10_000_000)

@app.get("/api/accounts/new-defaults")
def account_new_defaults(request:Request):
    require_user(request)
    return {
        "username":suggested_username(),
        "password_modes":["pin4","pin6","easy8","strong"],
        "recommended_mode":"pin6",
        "expiry_presets":[1,7,30,60,90],
    }

@app.get("/api/accounts/generate-secret")
def account_generate_secret(request:Request,mode:str="strong"):
    require_user(request)
    return {"mode":mode,"secret":generate_user_secret(mode)}

@app.post("/api/accounts")
def create_account(payload:AccountCreate,request:Request):
    actor=require_mutation(request)
    generated=False
    password=payload.password
    if payload.password_mode!="manual":
        password=generate_user_secret(payload.password_mode)
        generated=True
    if not password:
        raise HTTPException(400,"password is required")
    try:
        system_ops.create_ssh_user(payload.username,password,payload.expire_date)
        upsert_profile(payload.username,payload.plan,payload.note,payload.expire_date,payload.connection_limit,payload.quota_mb,1)
    except system_ops.OperationError as e: raise HTTPException(400,str(e))
    audit(actor,"account_create",payload.username,f"plan={payload.plan}; limit={payload.connection_limit}; quota_mb={payload.quota_mb}; password_mode={payload.password_mode}",ip(request))
    return {"ok":True,"username":payload.username,"password":password if generated else None,"generated":generated}

class AccountUpdate(BaseModel):
    password:str|None=Field(default=None,min_length=4,max_length=128)
    expire_date:str|None=None
    clear_expire:bool=False
    plan:str=""
    note:str=""
    connection_limit:int=Field(default=1,ge=1,le=50)
    quota_mb:int=Field(default=0,ge=0,le=10_000_000)
    enabled:bool=True

@app.put("/api/accounts/{username}")
def update_account(username:str,payload:AccountUpdate,request:Request):
    actor=require_mutation(request)
    try:
        system_ops.update_ssh_user(username,payload.password,payload.expire_date,payload.clear_expire)
        system_ops.lock_user(username,not payload.enabled)
        upsert_profile(username,payload.plan,payload.note,None if payload.clear_expire else payload.expire_date,payload.connection_limit,payload.quota_mb,1 if payload.enabled else 0)
    except system_ops.OperationError as e: raise HTTPException(400,str(e))
    audit(actor,"account_update",username,f"enabled={payload.enabled}; limit={payload.connection_limit}; quota_mb={payload.quota_mb}",ip(request))
    return {"ok":True}

@app.post("/api/accounts/{username}/{action}")
def account_action(username:str,action:str,request:Request):
    actor=require_mutation(request)
    try:
        if action=="lock":
            result=system_ops.lock_user(username,True)
            p=next((a for a in account_rows() if a["username"]==username),None)
            if p: upsert_profile(username,p["plan"],p["note"],p["expire_date"],p["connection_limit"],p["quota_mb"],0)
        elif action=="unlock":
            result=system_ops.lock_user(username,False)
            p=next((a for a in account_rows() if a["username"]==username),None)
            if p: upsert_profile(username,p["plan"],p["note"],p["expire_date"],p["connection_limit"],p["quota_mb"],1)
        elif action=="disconnect":
            targets=[s for s in system_ops.online_sessions() if s["username"]==username and s["tty"]]
            for s in targets:
                try: system_ops.disconnect_session(s["tty"])
                except system_ops.OperationError: pass
            result={"username":username,"disconnected":len(targets)}
        elif action=="delete":
            result=system_ops.delete_user(username); delete_profile(username)
        else: raise HTTPException(404,"unknown action")
    except system_ops.OperationError as e: raise HTTPException(400,str(e))
    audit(actor,f"account_{action}",username,ip=ip(request))
    return result

class BulkAccountAction(BaseModel):
    usernames:list[str]=Field(min_length=1,max_length=200)
    action:str
    days:int=Field(default=0,ge=0,le=3650)

@app.post("/api/accounts/bulk")
def bulk_account_action(payload:BulkAccountAction,request:Request):
    actor=require_mutation(request)
    if payload.action not in {"lock","unlock","disconnect","extend"}:
        raise HTTPException(400,"bulk action not allowed")
    if payload.action=="extend" and payload.days<1:
        raise HTTPException(400,"days must be at least 1")
    profiles=all_profiles()
    done=[]; failed=[]
    for username in payload.usernames:
        try:
            system_ops.validate_username(username)
            if payload.action=="lock":
                system_ops.lock_user(username,True)
            elif payload.action=="unlock":
                system_ops.lock_user(username,False)
            elif payload.action=="extend":
                p=profiles.get(username,{})
                base=date.today()
                if p.get("expire_date"):
                    try:
                        current=date.fromisoformat(str(p.get("expire_date")))
                        if current>base: base=current
                    except Exception:
                        pass
                new_expire=(base+timedelta(days=payload.days)).isoformat()
                system_ops.update_ssh_user(username,expire=new_expire)
                upsert_profile(username,p.get("plan",""),p.get("note",""),new_expire,p.get("connection_limit",1),p.get("quota_mb",0),p.get("enabled",1))
            else:
                for s in [x for x in system_ops.online_sessions() if x["username"]==username and x["tty"]]:
                    try: system_ops.disconnect_session(s["tty"])
                    except system_ops.OperationError: pass
            done.append(username)
        except Exception as exc:
            failed.append({"username":username,"error":str(exc)[:160]})
    audit(actor,f"accounts_bulk_{payload.action}",",".join(done[:30]),f"done={len(done)}; failed={len(failed)}; days={payload.days}",ip(request))
    return {"done":done,"failed":failed}

@app.get("/api/sessions")
def sessions(request:Request):
    require_user(request)
    return system_ops.online_sessions()

class SessionDisconnect(BaseModel):
    tty:str
    username:str|None=None

@app.post("/api/sessions/disconnect")
def session_disconnect(payload:SessionDisconnect,request:Request):
    actor=require_mutation(request)
    try: result=system_ops.disconnect_session(payload.tty)
    except system_ops.OperationError as e: raise HTTPException(400,str(e))
    audit(actor,"session_disconnect",payload.username or payload.tty,payload.tty,ip(request))
    return result

@app.post("/api/services/{name}/{action}")
def service(name:str,action:str,request:Request):
    actor=require_mutation(request)
    try: result=system_ops.service_action(name,action)
    except system_ops.OperationError as e: raise HTTPException(400,str(e))
    audit(actor,f"service_{action}",name,ip=ip(request))
    return result

@app.get("/api/security")
def security(request:Request):
    require_user(request)
    return system_ops.security_status()

@app.get("/api/protocols")
def protocols(request:Request):
    require_user(request)
    return {"xray":protocol_ops.status()}

@app.get("/api/backups")
def backups(request:Request):
    require_user(request)
    return system_ops.backup_list()

@app.post("/api/backups")
def backup_create(request:Request):
    actor=require_mutation(request)
    try: result=system_ops.create_backup(str(DATA_DIR))
    except system_ops.OperationError as e: raise HTTPException(400,str(e))
    audit(actor,"backup_create",result["name"],ip=ip(request))
    return result

@app.get("/api/audit")
def audit_list(request:Request,limit:int=100):
    require_user(request); limit=max(1,min(limit,500))
    with connect() as con: rows=con.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?",(limit,)).fetchall()
    return [dict(r) for r in rows]

class PasswordChange(BaseModel):
    current_password:str
    new_password:str=Field(min_length=12,max_length=128)

@app.post("/api/admin/password")
def change_password(payload:PasswordChange,request:Request):
    actor=require_mutation(request)
    with connect() as con:
        row=con.execute("SELECT * FROM admins WHERE username=?",(actor,)).fetchone()
        if not row or not verify_password(payload.current_password,row["password_hash"]): raise HTTPException(400,"current password is incorrect")
        con.execute("UPDATE admins SET password_hash=? WHERE username=?",(hash_password(payload.new_password),actor))
    audit(actor,"admin_password_change",actor,ip=ip(request))
    return {"ok":True}

@app.get("/api/v1/status")
def api_v1_status(request:Request):
    require_api_scope(request,"status:read")
    return {"product":APP_NAME,"version":VERSION,"metrics":system_ops.metrics(),"sessions":len(system_ops.online_sessions())}

@app.get("/api/v1/accounts")
def api_v1_accounts(request:Request):
    require_api_scope(request,"accounts:read")
    return account_rows()

class APITokenCreate(BaseModel):
    name:str=Field(min_length=1,max_length=80)
    scopes:list[str]=Field(default_factory=lambda:["status:read"])

@app.get("/api/admin/tokens")
def admin_tokens(request:Request):
    require_user(request)
    return list_api_tokens()

@app.post("/api/admin/tokens")
def admin_token_create(payload:APITokenCreate,request:Request):
    actor=require_mutation(request)
    allowed={"status:read","accounts:read"}
    scopes=[x for x in payload.scopes if x in allowed]
    if not scopes:
        raise HTTPException(400,"at least one valid scope is required")
    result=create_api_token(payload.name,scopes)
    audit(actor,"api_token_create",payload.name,",".join(scopes),ip(request))
    return result

@app.post("/api/admin/tokens/{token_id}/revoke")
def admin_token_revoke(token_id:int,request:Request):
    actor=require_mutation(request)
    revoke_api_token(token_id)
    audit(actor,"api_token_revoke",str(token_id),ip=ip(request))
    return {"ok":True}

class NodeCreate(BaseModel):
    name:str=Field(min_length=1,max_length=80)

class NodeHeartbeat(BaseModel):
    hostname:str=Field(min_length=1,max_length=255)
    version:str=Field(default="",max_length=80)
    cpu:float=Field(ge=0,le=100)
    memory:float=Field(ge=0,le=100)
    disk:float=Field(ge=0,le=100)

@app.get("/api/nodes")
def nodes_get(request:Request):
    require_user(request)
    return list_nodes()

@app.post("/api/nodes")
def nodes_create(payload:NodeCreate,request:Request):
    actor=require_mutation(request)
    result=create_node(payload.name)
    audit(actor,"node_create",payload.name,ip=ip(request))
    return result

@app.post("/api/nodes/{node_id}/revoke")
def nodes_revoke(node_id:int,request:Request):
    actor=require_mutation(request)
    revoke_node(node_id)
    audit(actor,"node_revoke",str(node_id),ip=ip(request))
    return {"ok":True}

@app.post("/api/node/heartbeat")
def node_heartbeat(payload:NodeHeartbeat,request:Request):
    token=bearer(request)
    node=node_by_token(token or "")
    if not node:
        raise HTTPException(403,"invalid node token")
    update_node_heartbeat(node["id"],payload.hostname,payload.version,payload.cpu,payload.memory,payload.disk)
    return {"ok":True,"node_id":node["id"]}

@app.get("/api/admin/2fa/status")
def twofa_status(request:Request):
    actor=require_user(request)
    state=get_admin_2fa(actor) or {}
    return {"enabled":bool(state.get("totp_enabled")),"configured":bool(state.get("totp_secret"))}

@app.post("/api/admin/2fa/setup")
def twofa_setup(request:Request):
    actor=require_mutation(request)
    secret=pyotp.random_base32()
    set_admin_totp_secret(actor,secret)
    uri=pyotp.TOTP(secret).provisioning_uri(name=actor,issuer_name="Makia VPS Manager")
    qr=qrcode.make(uri,image_factory=qrcode.image.svg.SvgPathImage)
    buf=io.BytesIO(); qr.save(buf)
    qr_data="data:image/svg+xml;base64,"+base64.b64encode(buf.getvalue()).decode()
    audit(actor,"admin_2fa_setup",actor,ip=ip(request))
    return {"secret":secret,"uri":uri,"qr":qr_data}

class TwoFACode(BaseModel):
    code:str

@app.post("/api/admin/2fa/enable")
def twofa_enable(payload:TwoFACode,request:Request):
    actor=require_mutation(request)
    state=get_admin_2fa(actor)
    if not state or not state.get("totp_secret") or not pyotp.TOTP(state["totp_secret"]).verify(payload.code.strip(),valid_window=1):
        raise HTTPException(400,"invalid authenticator code")
    set_admin_totp_enabled(actor,True)
    audit(actor,"admin_2fa_enable",actor,ip=ip(request))
    return {"ok":True}

class TwoFADisable(BaseModel):
    password:str
    code:str

@app.post("/api/admin/2fa/disable")
def twofa_disable(payload:TwoFADisable,request:Request):
    actor=require_mutation(request)
    with connect() as con:
        row=con.execute("SELECT password_hash FROM admins WHERE username=?",(actor,)).fetchone()
    state=get_admin_2fa(actor)
    if not row or not verify_password(payload.password,row["password_hash"]):
        raise HTTPException(400,"current password is incorrect")
    if state and state.get("totp_enabled") and (not state.get("totp_secret") or not pyotp.TOTP(state["totp_secret"]).verify(payload.code.strip(),valid_window=1)):
        raise HTTPException(400,"invalid authenticator code")
    clear_admin_totp(actor)
    audit(actor,"admin_2fa_disable",actor,ip=ip(request))
    return {"ok":True}

@app.get("/api/update/status")
def update_status(request:Request):
    require_user(request)
    latest=None
    error=None
    try:
        req=urllib.request.Request(
            "https://raw.githubusercontent.com/mahanneo/Makia-VPS-Manager/main/VERSION",
            headers={"User-Agent":"Makia-VPS-Manager"}
        )
        with urllib.request.urlopen(req,timeout=4) as resp:
            latest=resp.read(64).decode("utf-8","replace").strip()
    except Exception as exc:
        error=str(exc)[:160]
    return {"current":VERSION,"latest":latest,"update_available":bool(latest and latest!=VERSION),"error":error}

@app.get("/healthz")
def healthz(): return {"ok":True,"version":VERSION,"product":APP_NAME}
