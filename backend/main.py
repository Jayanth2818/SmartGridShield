"""SmartGridShield: isolated, local-only research prototype."""
import base64, hashlib, json, secrets, time, os
from pathlib import Path
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, String, Integer, Boolean, Text, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

DB=Path(__file__).parent/'smartgridshield.db'; engine=create_engine(f'sqlite:///{DB}',connect_args={'check_same_thread':False})
class Base(DeclarativeBase): pass
class User(Base):
 __tablename__='users'
 id:Mapped[int]=mapped_column(primary_key=True); username:Mapped[str]=mapped_column(String,unique=True); email:Mapped[str]=mapped_column(String,unique=True); password:Mapped[str]=mapped_column(String); sg_id:Mapped[str]=mapped_column(String,unique=True); credential:Mapped[str]=mapped_column(Text); public_key:Mapped[str]=mapped_column(Text); private_key:Mapped[str]=mapped_column(Text); permissions:Mapped[str]=mapped_column(Text,default='["p2p","ev","microgrid"]'); revoked:Mapped[bool]=mapped_column(Boolean,default=False); role:Mapped[str]=mapped_column(String,default='user')
class Vault(Base):
 __tablename__='vault'
 id:Mapped[int]=mapped_column(primary_key=True); sg_id:Mapped[str]=mapped_column(String,unique=True); identity:Mapped[str]=mapped_column(Text)
class Challenge(Base):
 __tablename__='challenges'
 id:Mapped[str]=mapped_column(String,primary_key=True); sg_id:Mapped[str]=mapped_column(String); service:Mapped[str]=mapped_column(String); action:Mapped[str]=mapped_column(String); nonce:Mapped[str]=mapped_column(Text); expires:Mapped[int]=mapped_column(Integer); consumed:Mapped[bool]=mapped_column(Boolean,default=False)
class Audit(Base):
 __tablename__='audits'
 id:Mapped[int]=mapped_column(primary_key=True); ts:Mapped[int]=mapped_column(Integer); event:Mapped[str]=mapped_column(String); sg_id:Mapped[str]=mapped_column(String,default=''); detail:Mapped[str]=mapped_column(Text,default='')
class ServiceRecord(Base):
 __tablename__='service_records'
 id:Mapped[int]=mapped_column(primary_key=True); ts:Mapped[int]=mapped_column(Integer); sg_id:Mapped[str]=mapped_column(String); service:Mapped[str]=mapped_column(String); record_type:Mapped[str]=mapped_column(String); payload:Mapped[str]=mapped_column(Text); status:Mapped[str]=mapped_column(String,default='active')
class Investigation(Base):
 __tablename__='investigations'
 id:Mapped[int]=mapped_column(primary_key=True); incident_id:Mapped[str]=mapped_column(String,unique=True); target_sg_id:Mapped[str]=mapped_column(String); requester:Mapped[str]=mapped_column(String); reason:Mapped[str]=mapped_column(Text); evidence:Mapped[str]=mapped_column(Text); status:Mapped[str]=mapped_column(String,default='pending'); approver:Mapped[str]=mapped_column(String,default=''); created:Mapped[int]=mapped_column(Integer)
class ServiceSession(Base):
 __tablename__='service_sessions'
 id:Mapped[str]=mapped_column(String,primary_key=True); sg_id:Mapped[str]=mapped_column(String); service:Mapped[str]=mapped_column(String); expires:Mapped[int]=mapped_column(Integer); consumed_operations:Mapped[int]=mapped_column(Integer,default=0)
class LoginSession(Base):
 __tablename__='login_sessions'
 id:Mapped[str]=mapped_column(String,primary_key=True); token_hash:Mapped[str]=mapped_column(String,unique=True); user_id:Mapped[int]=mapped_column(Integer); expires:Mapped[int]=mapped_column(Integer); revoked:Mapped[bool]=mapped_column(Boolean,default=False)
Base.metadata.create_all(engine)
# Lightweight migration for local SQLite databases created before the role field.
with engine.begin() as conn:
 cols=[x[1] for x in conn.exec_driver_sql('PRAGMA table_info(users)').fetchall()]
 if 'role' not in cols:conn.exec_driver_sql("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'")
_secret_path=Path(__file__).parent/'.demo_secret'
if os.getenv('SMARTGRIDSHIELD_SECRET'): SECRET=hashlib.sha256(os.environ['SMARTGRIDSHIELD_SECRET'].encode()).digest()
elif _secret_path.exists(): SECRET=base64.urlsafe_b64decode(_secret_path.read_text().encode())
else:
 SECRET=secrets.token_bytes(32);_secret_path.write_text(base64.urlsafe_b64encode(SECRET).decode())
ISSUER=Ed25519PrivateKey.from_private_bytes(SECRET); VAULT=Fernet(base64.urlsafe_b64encode(hashlib.sha256(SECRET+b'vault').digest())); PWD=PasswordHasher()
ADMIN_KEY=os.getenv('SMARTGRIDSHIELD_ADMIN_KEY','demo-admin-local-key')
app=FastAPI(title='SmartGridShield API'); app.add_middleware(CORSMiddleware,allow_origins=['http://localhost:5173','http://127.0.0.1:5173'],allow_methods=['*'],allow_headers=['*'])
@app.get('/health')
def health(): return {'status':'ok','service':'SmartGridShield API','demo_mode':True}
@app.get('/')
def root(): return {'name':'SmartGridShield','status':'ok','docs':'/docs'}
LOGIN_ATTEMPTS:dict[str,tuple[int,int]]={}
def b64(x):return base64.urlsafe_b64encode(x).decode().rstrip('=')
def log(db,event,sg='',detail=''):db.add(Audit(ts=int(time.time()),event=event,sg_id=sg,detail=detail))
def token(claims):
 raw=b64(json.dumps(claims,separators=(',',':'),sort_keys=True).encode());return raw+'.'+b64(ISSUER.sign(raw.encode()))
def seed_demo_data():
 """Creates only fictional local presentation data for a fresh clone."""
 with Session(engine) as db:
  if db.scalar(select(User).where(User.sg_id=='SGS-DEMO-ALICE')):return
  issued=int(time.time());key=Ed25519PrivateKey.generate()
  pub=b64(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
  private=b64(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()))
  credential=token({'sg_id':'SGS-DEMO-ALICE','permissions':['p2p','ev','microgrid'],'pub':pub,'issued':issued,'expires':issued+31536000})
  db.add(User(username='alice.demo',email='alice.demo@smartgridshield.test',password=PWD.hash('Demo-Only-Password-2026'),sg_id='SGS-DEMO-ALICE',credential=credential,public_key=pub,private_key=VAULT.encrypt(private.encode()).decode(),permissions='["p2p","ev","microgrid"]',role='user'))
  db.add(Vault(sg_id='SGS-DEMO-ALICE',identity=VAULT.encrypt(json.dumps({'name':'Alice Demonstration','government_id':'DEMO-ALICE-1001','phone':'Not a real person'}).encode()).decode()))
  db.add_all([
   ServiceRecord(ts=issued-7200,sg_id='SGS-DEMO-ALICE',service='p2p',record_type='energy_purchase',payload=json.dumps({'seller':'Sunrise Solar Co-op','quantity_kwh':5,'price':7.2}),status='settled'),
   ServiceRecord(ts=issued-3600,sg_id='SGS-DEMO-ALICE',service='ev',record_type='session_stopped',payload=json.dumps({'station':'Central Hub','energy_kwh':6.4,'cost':70.4}),status='completed'),
   ServiceRecord(ts=issued-1800,sg_id='SGS-DEMO-ALICE',service='microgrid',record_type='demand_response',payload=json.dumps({'commitment_kw':2}),status='accepted'),
   Investigation(incident_id='INC-DEMO-2026-01',target_sg_id='SGS-DEMO-ALICE',requester='requester@demo',reason='Fictional security research case',evidence='Demonstration audit event',status='approved',approver='approver@demo',created=issued-900)
  ])
  log(db,'demo_data_seeded','SGS-DEMO-ALICE','fictional demonstration identity, history, and approved research case created');db.commit()
seed_demo_data()
def repair_demo_credential():
 """Keep the fictional classroom card usable after a local secret/database change."""
 with Session(engine) as db:
  u=db.scalar(select(User).where(User.sg_id=='SGS-DEMO-ALICE'))
  if not u:return
  try: VAULT.decrypt(u.private_key.encode())
  except Exception:
   key=Ed25519PrivateKey.generate();pub=b64(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw));private=b64(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()));issued=int(time.time());u.public_key=pub;u.private_key=VAULT.encrypt(private.encode()).decode();u.credential=token({'sg_id':u.sg_id,'permissions':json.loads(u.permissions),'pub':pub,'issued':issued,'expires':issued+31536000});u.revoked=False;log(db,'demo_credential_repaired',u.sg_id,'local demo key material refreshed');db.commit()
repair_demo_credential()
def verify(t):
 try:
  raw,s=t.split('.');ISSUER.public_key().verify(base64.urlsafe_b64decode(s+'='*(-len(s)%4)),raw.encode());return json.loads(base64.urlsafe_b64decode(raw+'='*(-len(raw)%4)))
 except: raise HTTPException(401,'Credential signature invalid')
class Register(BaseModel):full_name:str;email:str;username:str;password:str;government_id_type:str;government_id_number:str;phone:str|None=None;consent:bool
class Auth(BaseModel):credential:str;challenge_id:str;proof:str
class CardLogin(BaseModel):smart_grid_id:str
class PasswordLogin(BaseModel):identifier:str;password:str
class ServiceAction(BaseModel):smart_grid_id:str;record_type:str;payload:dict
class Revoke(BaseModel):reason:str
class InvestigationCreate(BaseModel):incident_id:str;target_sg_id:str;requester:str;reason:str;evidence:str
class InvestigationDecision(BaseModel):approver:str;approved:bool
class PermissionUpdate(BaseModel):permissions:list[str]
def token_hash(token:str):return hashlib.sha256(token.encode()).hexdigest()
def issue_session(db,u):
 raw=secrets.token_urlsafe(32);db.add(LoginSession(id=secrets.token_hex(12),token_hash=token_hash(raw),user_id=u.id,expires=int(time.time())+1800));return raw
def current_user(authorization:str|None):
 if not authorization or not authorization.startswith('Bearer '):raise HTTPException(401,'Authenticated session required')
 raw=authorization[7:]
 with Session(engine) as db:
  s=db.scalar(select(LoginSession).where(LoginSession.token_hash==token_hash(raw)))
  if not s or s.revoked or s.expires<int(time.time()):raise HTTPException(401,'Session expired or invalid')
  u=db.get(User,s.user_id)
  if not u or u.revoked:raise HTTPException(401,'Account unavailable')
  return {'id':u.id,'sg_id':u.sg_id,'role':u.role,'permissions':json.loads(u.permissions)}
def require_role(authorization:str|None,*roles:str):
 u=current_user(authorization)
 if u['role'] not in roles:raise HTTPException(403,'Insufficient role permission')
 return u
@app.post('/api/register')
def register(x:Register):
 if not x.consent or len(x.password)<10:raise HTTPException(400,'Consent and a 10-character password are required')
 if x.government_id_number not in {'DEMO-ALICE-1001','DEMO-BOB-2002','DEMO-CHARLIE-3003'}:raise HTTPException(400,'Demo Verification Authority rejected this test identity')
 with Session(engine) as db:
  if db.scalar(select(User).where((User.username==x.username)|(User.email==x.email))):raise HTTPException(409,'Account already exists')
  sg='SGS-'+secrets.token_hex(5).upper();key=Ed25519PrivateKey.generate();pub=b64(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw));priv=b64(key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()));cred=token({'sg_id':sg,'permissions':['p2p','ev','microgrid'],'pub':pub,'issued':int(time.time()),'expires':int(time.time())+31536000})
  db.add(User(username=x.username,email=x.email,password=PWD.hash(x.password),sg_id=sg,credential=cred,public_key=pub,private_key=VAULT.encrypt(priv.encode()).decode()));db.add(Vault(sg_id=sg,identity=VAULT.encrypt(json.dumps({'name':x.full_name,'government_id':x.government_id_number,'phone':x.phone}).encode()).decode()));log(db,'credential_issued',sg,'mock verification accepted');db.commit();return {'smart_grid_id':sg,'credential':cred,'verification':'verified','card':{'issuer':'SmartGridShield Demo Issuer','fingerprint':hashlib.sha256(pub.encode()).hexdigest()[:16]}}
@app.post('/api/login')
def password_login(x:PasswordLogin):
 key=x.identifier.lower();count,until=LOGIN_ATTEMPTS.get(key,(0,0))
 if until>int(time.time()):raise HTTPException(429,'Too many login attempts. Try again later.')
 with Session(engine) as db:
  u=db.scalar(select(User).where((User.username==x.identifier)|(User.email==x.identifier)))
  try: valid=bool(u) and PWD.verify(u.password,x.password)
  except Exception:valid=False
  if not valid:
   count+=1;LOGIN_ATTEMPTS[key]=(count,int(time.time())+min(300,2**count) if count>=5 else 0);log(db,'login_failed',u.sg_id if u else '','invalid credential');db.commit();raise HTTPException(401,'Invalid username/email or password')
  LOGIN_ATTEMPTS.pop(key,None)
  raw=secrets.token_urlsafe(32);db.add(LoginSession(id=secrets.token_hex(12),token_hash=token_hash(raw),user_id=u.id,expires=int(time.time())+1800));log(db,'login_success',u.sg_id,'password session issued');db.commit()
  # In this local prototype the signed presentation credential is restored to the
  # simulated wallet after an authenticated password login. A production wallet
  # would retain it in device-secure storage and never ask this API for it.
  return {'access_token':raw,'token_type':'bearer','expires_in':1800,'smart_grid_id':u.sg_id,'role':u.role,'credential':u.credential}
@app.post('/api/logout')
def logout(authorization:str|None=Header(None)):
 if not authorization or not authorization.startswith('Bearer '):raise HTTPException(401,'Authenticated session required')
 with Session(engine) as db:
  s=db.scalar(select(LoginSession).where(LoginSession.token_hash==token_hash(authorization[7:])))
  if s:s.revoked=True;db.commit()
 return {'logged_out':True}
@app.get('/api/me')
def me(authorization:str|None=Header(None)):
 actor=current_user(authorization)
 with Session(engine) as db:
  u=db.scalar(select(User).where(User.sg_id==actor['sg_id']))
  return {**actor,'credential':u.credential}
@app.post('/api/card-login')
def card_login(x:CardLogin):
 """Demo-only smart-card presentation endpoint; real cards require a holder-held key and PIN."""
 with Session(engine) as db:
  u=db.scalar(select(User).where(User.sg_id==x.smart_grid_id))
  if not u or u.revoked: raise HTTPException(401,'Smart Grid Card is invalid or revoked')
  raw=issue_session(db,u);log(db,'card_login',u.sg_id,'demo smart-card presentation');db.commit();return {'smart_grid_id':u.sg_id,'credential':u.credential,'access_token':raw,'permissions':json.loads(u.permissions)}
@app.post('/api/prepared-demo')
def prepared_demo():
 with Session(engine) as db:
  u=db.scalar(select(User).where(User.sg_id=='SGS-DEMO-ALICE'))
  if not u: raise HTTPException(404,'Register one demo identity first')
  raw=issue_session(db,u);log(db,'demo_card_login',u.sg_id,'one-click classroom demo');db.commit()
  return {'smart_grid_id':u.sg_id,'credential':u.credential,'permissions':json.loads(u.permissions),'access_token':raw,'expires_in':1800}
@app.post('/api/service/{service}/action')
def service_action(service:str,x:ServiceAction,authorization:str|None=Header(None)):
 actor=current_user(authorization)
 if actor['sg_id']!=x.smart_grid_id:raise HTTPException(403,'Cannot operate as another identity')
 if service not in {'p2p','ev','microgrid'}:raise HTTPException(404,'Unknown service')
 with Session(engine) as db:
  u=db.scalar(select(User).where(User.sg_id==x.smart_grid_id))
  if not u or u.revoked:raise HTTPException(403,'Active Smart Grid card required')
  if service not in json.loads(u.permissions):raise HTTPException(403,'No permission for this service')
  session=db.scalar(select(ServiceSession).where(ServiceSession.sg_id==u.sg_id,ServiceSession.service==service,ServiceSession.expires>=int(time.time())).order_by(ServiceSession.expires.desc()))
  if not session:log(db,'service_operation_denied',u.sg_id,f'{service}:no fresh authentication');db.commit();raise HTTPException(401,'Fresh service authentication is required before this operation')
  session.consumed_operations+=1
  r=ServiceRecord(ts=int(time.time()),sg_id=u.sg_id,service=service,record_type=x.record_type,payload=json.dumps(x.payload),status='active');db.add(r);log(db,'service_operation',u.sg_id,f'{service}:{x.record_type}');db.commit();return {'id':r.id,'status':r.status,'record_type':r.record_type,'payload':x.payload}
@app.post('/api/credentials/{sg_id}/revoke')
def revoke_credential(sg_id:str,x:Revoke,authorization:str|None=Header(None)):
 actor=current_user(authorization)
 if actor['sg_id']!=sg_id and actor['role']!='admin':raise HTTPException(403,'Cannot revoke another identity')
 with Session(engine) as db:
  u=db.scalar(select(User).where(User.sg_id==sg_id))
  if not u:raise HTTPException(404,'Smart Grid identity not found')
  u.revoked=True;log(db,'credential_revoked',sg_id,x.reason);db.commit();return {'revoked':True,'reason':x.reason}
@app.post('/api/investigations')
def create_investigation(x:InvestigationCreate):
 with Session(engine) as db:
  if not db.scalar(select(User).where(User.sg_id==x.target_sg_id)):raise HTTPException(404,'Target Smart Grid ID not found')
  if db.scalar(select(Investigation).where(Investigation.incident_id==x.incident_id)):raise HTTPException(409,'Incident ID already exists')
  i=Investigation(incident_id=x.incident_id,target_sg_id=x.target_sg_id,requester=x.requester,reason=x.reason,evidence=x.evidence,created=int(time.time()));db.add(i);log(db,'investigation_created',x.target_sg_id,x.incident_id);db.commit();return {'id':i.id,'status':i.status}
@app.post('/api/investigations/{investigation_id}/decision')
def decide_investigation(investigation_id:int,x:InvestigationDecision):
 with Session(engine) as db:
  i=db.get(Investigation,investigation_id)
  if not i:raise HTTPException(404,'Investigation not found')
  if i.requester==x.approver:raise HTTPException(403,'Requester cannot approve their own investigation')
  i.status='approved' if x.approved else 'rejected';i.approver=x.approver;log(db,'investigation_'+i.status,i.target_sg_id,i.incident_id);db.commit();return {'status':i.status}
@app.post('/api/investigations/{investigation_id}/recover')
def recover_identity(investigation_id:int):
 with Session(engine) as db:
  i=db.get(Investigation,investigation_id)
  if not i or i.status!='approved':raise HTTPException(403,'Approved investigation required')
  v=db.scalar(select(Vault).where(Vault.sg_id==i.target_sg_id))
  if not v:raise HTTPException(404,'Vault mapping not found')
  identity=json.loads(VAULT.decrypt(v.identity.encode()).decode());log(db,'identity_recovered',i.target_sg_id,i.incident_id);db.commit();return {'incident_id':i.incident_id,'target_sg_id':i.target_sg_id,'identity':identity}
@app.get('/api/investigations')
def investigations():
 with Session(engine) as db:
  return [{'id':i.id,'incident_id':i.incident_id,'target_sg_id':i.target_sg_id,'requester':i.requester,'reason':i.reason,'status':i.status,'approver':i.approver}for i in db.scalars(select(Investigation).order_by(Investigation.id.desc()))]
@app.get('/api/service/{service}/history/{sg_id}')
def service_history(service:str,sg_id:str):
 with Session(engine) as db:
  rows=db.scalars(select(ServiceRecord).where(ServiceRecord.service==service,ServiceRecord.sg_id==sg_id).order_by(ServiceRecord.id.desc()).limit(25)).all()
  return [{'id':r.id,'type':r.record_type,'payload':json.loads(r.payload),'status':r.status,'timestamp':r.ts}for r in rows]
@app.get('/api/dashboard/{sg_id}')
def dashboard(sg_id:str):
 with Session(engine) as db:
  u=db.scalar(select(User).where(User.sg_id==sg_id));
  if not u:raise HTTPException(404,'Unknown identity')
  events=db.scalars(select(Audit).where(Audit.sg_id==sg_id).order_by(Audit.id.desc()).limit(20)).all();return {'identity':{'sg_id':u.sg_id,'revoked':u.revoked,'permissions':json.loads(u.permissions),'fingerprint':hashlib.sha256(u.public_key.encode()).hexdigest()[:16]},'events':[{'event':e.event,'timestamp':e.ts,'detail':e.detail}for e in events]}
@app.post('/api/challenges/{sg_id}/{service}/{action}')
def challenge(sg_id:str,service:str,action:str,authorization:str|None=Header(None)):
 actor=current_user(authorization)
 if actor['sg_id']!=sg_id:raise HTTPException(403,'Cannot request a challenge for another identity')
 with Session(engine) as db:
  u=db.scalar(select(User).where(User.sg_id==sg_id));
  if not u or u.revoked:raise HTTPException(403,'Credential revoked or unknown')
  if service not in json.loads(u.permissions):raise HTTPException(403,'Not authorized for this service')
  cid=secrets.token_hex(12);n=secrets.token_urlsafe(32);db.add(Challenge(id=cid,sg_id=sg_id,service=service,action=action,nonce=n,expires=int(time.time())+120));log(db,'challenge_issued',sg_id,f'{service}:{action}');db.commit();return {'challenge_id':cid,'nonce':n,'service':service,'action':action,'expires_in':120}
@app.post('/api/authenticate')
def authenticate(x:Auth):
 claims=verify(x.credential)
 with Session(engine) as db:
  c=db.get(Challenge,x.challenge_id);u=db.scalar(select(User).where(User.sg_id==claims['sg_id']))
  if not c or c.consumed or c.expires<int(time.time()):log(db,'authentication_failed',claims.get('sg_id',''),'replayed/expired');db.commit();raise HTTPException(401,'Challenge expired, missing, or already consumed')
  if claims.get('expires',0)<int(time.time()):raise HTTPException(401,'Credential has expired')
  if not u or u.revoked or c.sg_id!=u.sg_id or c.service not in claims.get('permissions',[]):raise HTTPException(403,'Credential revoked, unscoped, or challenge mismatch')
  data=f'{c.id}|{c.nonce}|{c.service}|{c.action}'.encode()
  try: Ed25519PublicKey.from_public_bytes(base64.urlsafe_b64decode(claims['pub']+'='*(-len(claims['pub'])%4))).verify(base64.urlsafe_b64decode(x.proof+'='*(-len(x.proof)%4)),data)
  except:raise HTTPException(401,'Proof of key possession failed')
  c.consumed=True;session=ServiceSession(id=secrets.token_urlsafe(24),sg_id=u.sg_id,service=c.service,expires=int(time.time())+120);db.add(session);log(db,'authentication_success',u.sg_id,f'{c.service}:{c.action}');db.commit();return {'accepted':True,'service_pseudonym':hashlib.sha256((u.sg_id+c.service).encode()).hexdigest()[:20],'service':c.service,'action':c.action,'operation_authorization_expires_in':120}
@app.post('/api/demo-wallet-proof/{challenge_id}')
def demo_wallet_proof(challenge_id:str):
 """Local demo wallet adapter. A production wallet must hold this key outside the server."""
 with Session(engine) as db:
  c=db.get(Challenge,challenge_id)
  if not c:raise HTTPException(404,'Challenge not found')
  u=db.scalar(select(User).where(User.sg_id==c.sg_id));raw=VAULT.decrypt(u.private_key.encode()).decode();key=Ed25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(raw+'='*(-len(raw)%4)))
  return {'proof':b64(key.sign(f'{c.id}|{c.nonce}|{c.service}|{c.action}'.encode()))}
@app.get('/api/audit')
def audits():
 with Session(engine) as db:return [{'event':x.event,'sg_id':x.sg_id,'detail':x.detail,'timestamp':x.ts}for x in db.scalars(select(Audit).order_by(Audit.id.desc()).limit(100))]
@app.get('/api/audit/export',response_class=PlainTextResponse)
def audit_export():
 with Session(engine) as db:
  rows=db.scalars(select(Audit).order_by(Audit.id.desc()).limit(1000)).all()
  lines=['timestamp,event,smart_grid_id,detail']+[f'{x.ts},{x.event},{x.sg_id},{json.dumps(x.detail)}'for x in rows]
  return '\n'.join(lines)
@app.get('/api/credentials/{sg_id}')
def credential_info(sg_id:str,authorization:str|None=Header(None)):
 actor=current_user(authorization)
 if actor['sg_id']!=sg_id and actor['role']!='admin':raise HTTPException(403,'Credential metadata is private')
 with Session(engine) as db:
  u=db.scalar(select(User).where(User.sg_id==sg_id))
  if not u:raise HTTPException(404,'Identity not found')
  claims=verify(u.credential);return {'sg_id':sg_id,'status':'revoked' if u.revoked else 'active','issuer':'SmartGridShield Demo Issuer','permissions':json.loads(u.permissions),'issued':claims['issued'],'expires':claims['expires'],'fingerprint':hashlib.sha256(u.public_key.encode()).hexdigest()[:16],'credential':u.credential}
def require_admin(key:str):
 if key!=ADMIN_KEY:raise HTTPException(403,'Administrator authorization required')
@app.get('/api/admin/summary')
def admin_summary(x_admin_key:str=Header(...)):
 require_admin(x_admin_key)
 with Session(engine) as db:
  users=db.scalars(select(User)).all();aud=db.scalars(select(Audit)).all();cases=db.scalars(select(Investigation)).all()
  return {'registered_users':len(users),'active_credentials':sum(not x.revoked for x in users),'revoked_credentials':sum(x.revoked for x in users),'authentication_events':sum(x.event=='authentication_success' for x in aud),'security_events':sum('failed' in x.event or 'revoked' in x.event for x in aud),'pending_investigations':sum(x.status=='pending' for x in cases)}
@app.get('/api/admin/users')
def admin_users(x_admin_key:str=Header(...)):
 require_admin(x_admin_key)
 with Session(engine) as db:return [{'sg_id':u.sg_id,'username':u.username,'role':u.role,'permissions':json.loads(u.permissions),'revoked':u.revoked}for u in db.scalars(select(User))]
@app.post('/api/admin/users/{sg_id}/permissions')
def update_permissions(sg_id:str,x:PermissionUpdate,x_admin_key:str=Header(...)):
 require_admin(x_admin_key)
 permitted={'p2p','ev','microgrid'}
 if not set(x.permissions)<=permitted:raise HTTPException(400,'Unknown service permission')
 with Session(engine) as db:
  u=db.scalar(select(User).where(User.sg_id==sg_id))
  if not u:raise HTTPException(404,'Identity not found')
  u.permissions=json.dumps(x.permissions);log(db,'permissions_updated',sg_id,','.join(x.permissions));db.commit();return {'permissions':x.permissions}
