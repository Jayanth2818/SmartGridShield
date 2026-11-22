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

def proof(c,sg,cred,service='p2p'):
 q=c.post(f'/api/challenges/{sg}/{service}/access').json();p=c.post('/api/demo-wallet-proof/'+q['challenge_id']).json();return q,p

def test_signed_proof_replay_and_revocation():
 c=TestClient(main.app);x=register(c);q,p=proof(c,x['smart_grid_id'],x['credential'])
 assert c.post('/api/authenticate',json={'credential':x['credential'],'challenge_id':q['challenge_id'],'proof':p['proof']}).status_code==200
 assert c.post('/api/authenticate',json={'credential':x['credential'],'challenge_id':q['challenge_id'],'proof':p['proof']}).status_code==401
 assert c.post('/api/authenticate',json={'credential':x['credential']+'x','challenge_id':'bad','proof':'bad'}).status_code==401
 assert c.post('/api/credentials/'+x['smart_grid_id']+'/revoke',json={'reason':'security demo'}).status_code==200
 assert c.post(f'/api/challenges/{x["smart_grid_id"]}/p2p/access').status_code==403

def test_investigation_requires_other_approver():
 c=TestClient(main.app);x=register(c);sg=x['smart_grid_id'];r=c.post('/api/investigations',json={'incident_id':'INC-'+unique(),'target_sg_id':sg,'requester':'requester@demo','reason':'Fraud simulation','evidence':'Audit anomaly'});assert r.status_code==200;i=r.json()['id']
 assert c.post(f'/api/investigations/{i}/decision',json={'approver':'requester@demo','approved':True}).status_code==403
 assert c.post(f'/api/investigations/{i}/decision',json={'approver':'approver@demo','approved':True}).status_code==200
 assert c.post(f'/api/investigations/{i}/recover').status_code==200

def test_service_operation_requires_fresh_authentication():
 c=TestClient(main.app);x=register(c);sg=x['smart_grid_id']
 payload={'smart_grid_id':sg,'record_type':'energy_purchase','payload':{'quantity_kwh':2}}
 assert c.post('/api/service/p2p/action',json=payload).status_code==401
 q,p=proof(c,sg,x['credential'])
 assert c.post('/api/authenticate',json={'credential':x['credential'],'challenge_id':q['challenge_id'],'proof':p['proof']}).status_code==200
 assert c.post('/api/service/p2p/action',json=payload).status_code==200

def test_expired_challenge_and_permission_denial():
 c=TestClient(main.app);x=register(c);sg=x['smart_grid_id'];q,p=proof(c,sg,x['credential'],'p2p')
 with Session(main.engine) as db:
  db.get(main.Challenge,q['challenge_id']).expires=0;db.commit()
 assert c.post('/api/authenticate',json={'credential':x['credential'],'challenge_id':q['challenge_id'],'proof':p['proof']}).status_code==401
 with Session(main.engine) as db:
  u=db.scalar(main.select(main.User).where(main.User.sg_id==sg));u.permissions='["ev"]';db.commit()
 assert c.post(f'/api/challenges/{sg}/microgrid/access').status_code==403

def test_admin_endpoints_are_protected():
 c=TestClient(main.app)
 assert c.get('/api/admin/summary').status_code==422
 assert c.get('/api/admin/summary',headers={'X-Admin-Key':'wrong'}).status_code==403
 assert c.get('/api/admin/summary',headers={'X-Admin-Key':'demo-admin-local-key'}).status_code==200
