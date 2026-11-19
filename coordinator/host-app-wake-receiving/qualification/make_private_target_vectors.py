from pathlib import Path
import json,hashlib,re
root=Path(__file__).parent
v=json.loads((root/'native-transcript-vectors.json').read_text());o=v['original'];prefix='/v1/push/host-app-wake/';cap='djchw_'+'A'*43;purpose='fixture-api-private-purpose'
canonical=lambda x:json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True)
hashv=lambda x:hashlib.sha256(canonical(x).encode()).hexdigest()
rows=[]
for kind in ['register','wake','status','revoke']:
 operation=o['operation_id'] if kind!='wake' else 'fixture-original-wake-event'
 body={'version':'djc-host-app-wake/1','purpose_id':purpose,'operation_id':operation}
 if kind=='register':body.update({k:o[k] for k in ['generation','revision','token_role','target','apns_environment']});body['apns_token']=v['native_token_hex']
 if kind=='wake':body.update(generation=o['generation'],revision=o['revision'],event='direct_rich_refresh')
 path=prefix+kind;digest=hashv(['DJC-HOST-WAKE-API-REQUEST-V1','POST',path,body]);headers={'Authorization':'Bearer djci_'+'B'*43,'Content-Type':'application/json','X-DJConnect-Host-Wake-Authorization-ID':'fixture-existing-authorization','X-DJConnect-Host-Wake-Core-Purpose-ID':o['core_purpose_id'],'X-DJConnect-Host-Wake-Issuer-Operation-ID':'fixture-original-issuer','X-DJConnect-Host-Wake-Capability':cap}
 if kind in ['register','wake']:headers['X-DJConnect-Host-Wake-Operation-ID']=operation
 reply={'version':'djc-host-app-wake/1','purpose_id':purpose,'operation_id':operation,'state':'withdrawn' if kind=='revoke' else 'registered','generation':o['generation'],'revision':o['revision'],'expires_at_ms':o['original_wake_expires_at_ms'],'transport_expires_at_ms':o['original_wake_issued_at_ms']+30000 if kind=='wake' else None,'operation_state':'provider_accepted' if kind=='wake' else 'registered','provider_status':200 if kind=='wake' else None}
 rows.append({'kind':kind,'path':path,'request':body,'request_headers':headers,'reply':reply,'reply_headers':{'X-DJConnect-Host-Wake-Request-SHA256':digest},'status':200,'request_sha256':digest})
unknown=json.loads(json.dumps(rows[1]));unknown.update(status=202,reply={k:unknown['reply'][k] for k in ['version','purpose_id','operation_id']});unknown['reply']['operation_state']='unknown';rows.append(unknown)
errors=[{'status':401,'body':{'version':'djc-host-app-wake-receiving/1','success':False,'error':'host_wake_core_auth'}},{'status':409,'body':{'version':'djc-host-app-wake-receiving/1','success':False,'error':'host_wake_intent_consumed'}}]
(root/'private-target-ports-vectors.json').write_text(json.dumps({'classification':'INDEPENDENT_PYTHON_SYNTHETIC_DATA_ONLY_NOT_ROLE_NATIVE_KEY_CAPABILITY_OR_PROVIDER_AUTHORITY','original':o,'private_purpose_id':purpose,'cases':rows,'errors':errors},indent=2)+'\n')
obj=lambda props:{'type':'object','additionalProperties':False,'required':list(props),'properties':props}
const=lambda x:{'const':x}
enum=lambda *v:{'enum':list(v)}
id={'type':'string','pattern':'^[A-Za-z0-9_-]{1,128}$'};hashs={'type':'string','pattern':'^[a-f0-9]{64}$'};time={'type':'integer','minimum':0,'maximum':9007199254740991}
target=obj({'host_bundle_id':{'type':'string','maxLength':200,'pattern':'^[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)+$'},'installation_id':id})
base={'version':const('djc-host-app-wake/1'),'purpose_id':id,'operation_id':id}
commonheaders={'Authorization':{'type':'string','pattern':'^Bearer djci_[A-Za-z0-9_-]{43}$'},'Content-Type':const('application/json'),'X-DJConnect-Host-Wake-Authorization-ID':id,'X-DJConnect-Host-Wake-Core-Purpose-ID':id,'X-DJConnect-Host-Wake-Issuer-Operation-ID':id,'X-DJConnect-Host-Wake-Capability':{'type':'string','pattern':'^djchw_[A-Za-z0-9_-]{43}$'}}
branches=[]
for kind in ['register','wake','status','revoke']:
 body=dict(base);headers=dict(commonheaders)
 if kind in ['register','wake']:body.update(generation=id,revision={'type':'integer','minimum':1,'maximum':256});headers['X-DJConnect-Host-Wake-Operation-ID']=id
 if kind=='register':body.update(token_role=const('host_app_wake'),target=target,apns_environment=enum('sandbox','production'),apns_token={'type':'string','pattern':'^(?:[a-f0-9]{2}){16,2048}$'})
 if kind=='wake':body.update(event=const('direct_rich_refresh'))
 fixed={'method':const('POST'),'path':const(prefix+kind)}
 branches.append(obj({**fixed,'direction':const('request'),'headers':obj(headers),'body':obj(body)}))
 success={**base,'state':enum('withdrawn','expired','registered','unregistered'),'generation':{'oneOf':[{'type':'null'},id]},'revision':{'type':'integer','minimum':0,'maximum':256},'expires_at_ms':time,'transport_expires_at_ms':{'oneOf':[{'type':'null'},time]},'operation_state':enum('unknown','registered','conflict','expired','provider_accepted','provider_rejected','not_sent'),'provider_status':{'oneOf':[{'type':'null'},{'type':'integer','minimum':100,'maximum':599}]}}
 normal={'status':const(200),'headers':obj({'X-DJConnect-Host-Wake-Request-SHA256':hashs}),'body':obj(success)}
 unknown={'status':const(202),'headers':obj({'X-DJConnect-Host-Wake-Request-SHA256':hashs}),'body':obj({**base,'operation_state':const('unknown')})}
 for fields in [normal,unknown]:branches.append(obj({**fixed,'direction':const('reply'),**fields}))
 error_source=(root.parent/'server-reply.ts').read_text().split('Object.freeze({',1)[1].split('});',1)[0]
 schema_errors=[{'status':int(status),'body':{'version':const('djc-host-app-wake-receiving/1'),'success':const(False),'error':enum(*re.findall(r"'([^']+)'",codes))}} for status,codes in re.findall(r'(\d+):\[([^\]]*)\]',error_source)]
 for error in schema_errors:branches.append(obj({**fixed,'direction':const('error'),'status':const(error['status']),'body':obj(error['body'])}))
schema={'$schema':'https://json-schema.org/draft/2020-12/schema','$id':'urn:djconnect:host-wake-private-target-ports:1','description':'Structural synthetic DATA envelopes only; actual HTTP bodies/replies are unchanged Source181. Header keys in vector envelopes use canonical display casing; actual HTTP names are case insensitive. Runtime additionally joins exact operation/purpose/original/deadlines and computed correlation header; no role, original parent, native enrollment, clock or provider admission is supplied. Terminal source state precedes historical operation_state. Error examples include401/409; schema includes the full fixed status/code table extracted from server-reply.ts.','oneOf':branches}
(root/'private-target-ports.schema.json').write_text(json.dumps(schema,indent=2)+'\n')
