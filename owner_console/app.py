import hmac, os, re, time
from pathlib import Path
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field
from .config import COOKIE_NAME, ADMIN_PASSWORD_HASH, INGEST_TOKEN, PUBLIC_URL, PRIVATE_KEY_PATH
from .security import make_session, valid_session, verify_password
from . import db, license_service

BASE=Path(__file__).resolve().parent
app=FastAPI(title="Makia Owner Control Center",docs_url=None,redoc_url=None)
app.mount("/static",StaticFiles(directory=BASE/"static"),name="static")
templates=Jinja2Templates(directory=BASE/"templates")

@app.on_event("startup")
def startup():
    db.init_db()
    if not PRIVATE_KEY_PATH.exists():
        raise RuntimeError("MAKIA_OWNER_PRIVATE_KEY_PATH does not exist")
    if not ADMIN_PASSWORD_HASH:
        raise RuntimeError("MAKIA_OWNER_ADMIN_PASSWORD_HASH is required")

@app.middleware("http")
async def security_headers(request:Request,call_next):
    response=await call_next(request)
    response.headers.setdefault("X-Frame-Options","DENY")
    response.headers.setdefault("X-Content-Type-Options","nosniff")
    response.headers.setdefault("Referrer-Policy","no-referrer")
    response.headers.setdefault("Permissions-Policy","camera=(), microphone=(), geolocation=(), payment=()")
    response.headers.setdefault("Content-Security-Policy","default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; form-action 'self'")
    response.headers["Cache-Control"]="no-store"
    if request.headers.get("x-forwarded-proto","").lower()=="https" or request.url.scheme=="https":
        response.headers.setdefault("Strict-Transport-Security","max-age=31536000; includeSubDomains")
    return response

def client_ip(request):return request.client.host if request.client else ""

def require_owner(request):
    if not valid_session(request.cookies.get(COOKIE_NAME)):
        raise HTTPException(401,"owner authentication required")
    return "owner"

def require_mutation(request):
    require_owner(request)
    if request.headers.get("x-owner-request")!="1":
        raise HTTPException(403,"invalid owner management request")
    return "owner"

@app.get("/healthz")
def healthz():return {"ok":True}

@app.get("/login",response_class=HTMLResponse)
def login_page(request:Request):
    return templates.TemplateResponse("login.html",{"request":request,"error":None})

@app.post("/login")
def login(request:Request,password:str=Form(...)):
    if not verify_password(password,ADMIN_PASSWORD_HASH):
        db.audit("login_failed",ip=client_ip(request))
        return templates.TemplateResponse("login.html",{"request":request,"error":"رمز Owner صحیح نیست."},status_code=401)
    db.audit("login_success",ip=client_ip(request))
    r=RedirectResponse("/",302)
    secure=request.headers.get("x-forwarded-proto","").lower()=="https"
    r.set_cookie(COOKIE_NAME,make_session(),httponly=True,secure=secure,samesite="strict",max_age=43200)
    return r

@app.post("/logout")
def logout(request:Request):
    db.audit("logout",ip=client_ip(request))
    r=RedirectResponse("/login",302);r.delete_cookie(COOKIE_NAME);return r

@app.get("/",response_class=HTMLResponse)
def root(request:Request):
    if not valid_session(request.cookies.get(COOKIE_NAME)):return RedirectResponse("/login",302)
    return templates.TemplateResponse("index.html",{"request":request,"public_url":PUBLIC_URL})

class CustomerCreate(BaseModel):
    name:str=Field(min_length=1,max_length=120)
    contact:str=Field(default="",max_length=200)
    note:str=Field(default="",max_length=1000)

@app.get("/api/customers")
def api_customers(request:Request):require_owner(request);return db.customers()

@app.post("/api/customers")
def api_customer_create(payload:CustomerCreate,request:Request):
    require_mutation(request);cid=db.create_customer(payload.name,payload.contact,payload.note)
    db.audit("customer_create",str(cid),payload.name,client_ip(request));return {"id":cid}

class InstallationCreate(BaseModel):
    customer_id:int|None=None
    installation_id:str=Field(min_length=10,max_length=64)
    domain:str=Field(default="",max_length=253)
    note:str=Field(default="",max_length=1000)

@app.get("/api/installations")
def api_installations(request:Request):require_owner(request);return db.installations()

@app.post("/api/installations")
def api_installation_create(payload:InstallationCreate,request:Request):
    require_mutation(request)
    iid=payload.installation_id.strip().upper()
    if not re.fullmatch(r"MK-[A-F0-9]{20}",iid):raise HTTPException(400,"Installation ID must match MK- + 20 hex characters")
    rid=db.upsert_installation(payload.customer_id,iid,payload.domain,payload.note)
    db.audit("installation_upsert",iid,payload.domain,client_ip(request));return {"id":rid}

class LicenseIssue(BaseModel):
    customer_id:int
    installation_id:str
    days:int=Field(default=365,ge=0,le=3650)
    features:str=Field(default="full",max_length=500)

@app.get("/api/licenses")
def api_licenses(request:Request):require_owner(request);return db.licenses()

@app.post("/api/licenses/issue")
def api_license_issue(payload:LicenseIssue,request:Request):
    require_mutation(request)
    customer=db.customer(payload.customer_id)
    if not customer:raise HTTPException(404,"customer not found")
    try:item=license_service.issue(payload.customer_id,payload.installation_id,customer["name"],payload.days,payload.features)
    except Exception as exc:raise HTTPException(400,str(exc))
    db.audit("license_issue",item["license_id"],f"{item['installation_id']}; days={payload.days}",client_ip(request))
    return item

class LicenseRenew(BaseModel):
    days:int=Field(default=365,ge=0,le=3650)

@app.post("/api/licenses/{license_id}/renew")
def api_license_renew(license_id:str,payload:LicenseRenew,request:Request):
    require_mutation(request)
    try:item=license_service.renew(license_id,payload.days)
    except Exception as exc:raise HTTPException(400,str(exc))
    db.audit("license_renew",license_id,f"days={payload.days}",client_ip(request));return item

@app.post("/api/licenses/{license_id}/revoke")
def api_license_revoke(license_id:str,request:Request):
    require_mutation(request)
    try:r=license_service.revoke(license_id)
    except Exception as exc:raise HTTPException(400,str(exc))
    db.audit("license_revoke",license_id,ip=client_ip(request));return r

@app.post("/api/licenses/{license_id}/restore")
def api_license_restore(license_id:str,request:Request):
    require_mutation(request)
    try:r=license_service.restore(license_id)
    except Exception as exc:raise HTTPException(400,str(exc))
    db.audit("license_restore",license_id,ip=client_ip(request));return r

class LeaseRequest(BaseModel):
    installation_id:str
    license_id:str
    sync_token:str
    revision:int=1

@app.post("/api/public/license/lease")
def public_license_lease(payload:LeaseRequest):
    try:return license_service.lease(payload.installation_id,payload.license_id,payload.sync_token,payload.revision)
    except PermissionError as exc:raise HTTPException(403,str(exc))
    except Exception as exc:raise HTTPException(400,str(exc))

@app.post("/api/public/tickets")
async def public_ticket(request:Request):
    auth=request.headers.get("authorization","")
    token=auth.split(" ",1)[1].strip() if auth.lower().startswith("bearer ") else ""
    if not INGEST_TOKEN or not hmac.compare_digest(token,INGEST_TOKEN):
        raise HTTPException(403,"invalid ticket ingest token")
    body=await request.json()
    for key in ["installation_id","subject","message"]:
        if not str(body.get(key) or "").strip():raise HTTPException(400,f"{key} required")
    tid=db.add_ticket(body)
    db.audit("ticket_ingest",str(tid),str(body.get("installation_id") or ""),client_ip(request))
    return {"ticket_id":tid}

@app.get("/api/tickets")
def api_tickets(request:Request):require_owner(request);return db.tickets()

class TicketStatus(BaseModel):
    status:str=Field(pattern="^(open|pending|closed)$")

@app.post("/api/tickets/{ticket_id}/status")
def api_ticket_status(ticket_id:int,payload:TicketStatus,request:Request):
    require_mutation(request);db.set_ticket_status(ticket_id,payload.status)
    db.audit("ticket_status",str(ticket_id),payload.status,client_ip(request));return {"ok":True}

@app.get("/api/audit")
def api_audit(request:Request):require_owner(request);return db.audit_rows()
