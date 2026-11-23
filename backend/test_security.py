import sys, tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
import main
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

def unique():
 import secrets
 return secrets.token_hex(5)

def register(c):
 u=unique();r=c.post('/api/register',json={'full_name':'Alice Demo','email':u+'@test.local','username':u,'password':'correct-horse-123','government_id_type':'Demo National ID','government_id_number':'DEMO-ALICE-1001','consent':True});assert r.status_code==200;return r.json()

def session_headers(c,sg):
 with Session(main.engine) as db: username=db.scalar(main.select(main.User.username).where(main.User.sg_id==sg))
 token=c.post('/api/login',json={'identifier':username,'password':'correct-horse-123'}).json()['access_token']
 return {'Authorization':'Bearer '+token}
def proof(c,sg,cred,service='p2p',headers=None):
 q=c.post(f'/api/challenges/{sg}/{service}/access',headers=headers).json();p=c.post('/api/demo-wallet-proof/'+q['challenge_id']).json();return q,p

def test_signed_proof_replay_and_revocation():
 c=TestClient(main.app);x=register(c);h=session_headers(c,x['smart_grid_id']);q,p=proof(c,x['smart_grid_id'],x['credential'],headers=h)
 assert c.post('/api/authenticate',json={'credential':x['credential'],'challenge_id':q['challenge_id'],'proof':p['proof']}).status_code==200
 assert c.post('/api/authenticate',json={'credential':x['credential'],'challenge_id':q['challenge_id'],'proof':p['proof']}).status_code==401
 assert c.post('/api/authenticate',json={'credential':x['credential']+'x','challenge_id':'bad','proof':'bad'}).status_code==401
 assert c.post('/api/credentials/'+x['smart_grid_id']+'/revoke',json={'reason':'security demo'},headers=h).status_code==200
 assert c.post(f'/api/challenges/{x["smart_grid_id"]}/p2p/access',headers=h).status_code==401

def test_investigation_requires_other_approver():
 c=TestClient(main.app);x=register(c);sg=x['smart_grid_id'];r=c.post('/api/investigations',json={'incident_id':'INC-'+unique(),'target_sg_id':sg,'requester':'requester@demo','reason':'Fraud simulation','evidence':'Audit anomaly'});assert r.status_code==200;i=r.json()['id']
 assert c.post(f'/api/investigations/{i}/decision',json={'approver':'requester@demo','approved':True}).status_code==403
 assert c.post(f'/api/investigations/{i}/decision',json={'approver':'approver@demo','approved':True}).status_code==200
 assert c.post(f'/api/investigations/{i}/recover').status_code==200

def test_service_operation_requires_fresh_authentication():
 c=TestClient(main.app);x=register(c);sg=x['smart_grid_id'];h=session_headers(c,sg)
 payload={'smart_grid_id':sg,'record_type':'energy_purchase','payload':{'quantity_kwh':2}}
 assert c.post('/api/service/p2p/action',json=payload,headers=h).status_code==401
 q,p=proof(c,sg,x['credential'],headers=h)
 assert c.post('/api/authenticate',json={'credential':x['credential'],'challenge_id':q['challenge_id'],'proof':p['proof']}).status_code==200
 assert c.post('/api/service/p2p/action',json=payload,headers=h).status_code==200

def test_expired_challenge_and_permission_denial():
 c=TestClient(main.app);x=register(c);sg=x['smart_grid_id'];h=session_headers(c,sg);q,p=proof(c,sg,x['credential'],'p2p',h)
 with Session(main.engine) as db:
  db.get(main.Challenge,q['challenge_id']).expires=0;db.commit()
 assert c.post('/api/authenticate',json={'credential':x['credential'],'challenge_id':q['challenge_id'],'proof':p['proof']}).status_code==401
 with Session(main.engine) as db:
  u=db.scalar(main.select(main.User).where(main.User.sg_id==sg));u.permissions='["ev"]';db.commit()
 assert c.post(f'/api/challenges/{sg}/microgrid/access',headers=h).status_code==403

def test_admin_endpoints_are_protected():
 c=TestClient(main.app)
 assert c.get('/api/admin/summary').status_code==422
 assert c.get('/api/admin/summary',headers={'X-Admin-Key':'wrong'}).status_code==403
 assert c.get('/api/admin/summary',headers={'X-Admin-Key':'demo-admin-local-key'}).status_code==200

def test_password_login_and_logout():
 c=TestClient(main.app);x=register(c)
 assert c.post('/api/login',json={'identifier':x['smart_grid_id'],'password':'correct-horse-123'}).status_code==401
 # Locate the username created by register through its database record.
 with Session(main.engine) as db: username=db.scalar(main.select(main.User.username).where(main.User.sg_id==x['smart_grid_id']))
 login=c.post('/api/login',json={'identifier':username,'password':'correct-horse-123'})
 assert login.status_code==200
 token=login.json()['access_token']
 assert c.post('/api/logout',headers={'Authorization':'Bearer '+token}).status_code==200
