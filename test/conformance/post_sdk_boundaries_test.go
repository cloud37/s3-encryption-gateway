//go:build conformance

package conformance

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func boundaryExtract(t *testing.T, source, first, last string) string {
	t.Helper()
	start := strings.Index(source, first)
	if start < 0 {
		t.Fatal("fixture helper start missing")
	}
	end := strings.Index(source[start:], last)
	if end < 0 {
		t.Fatal("fixture helper end missing")
	}
	return source[start : start+end]
}

func boundaryRun(t *testing.T, binary, suffix, text string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture"+suffix)
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal("write fixture")
	}
	if err := exec.Command(binary, path).Run(); err != nil {
		t.Fatal("local helper fixture failed; output suppressed")
	}
}

func TestGH353BotoHeadSDKShapedResponse(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	source := (&boto3PresignedPostRunner{}).Script(sdkTestEnv{})
	verify := boundaryExtract(t, source, "    def normalized_user_metadata(", "\n    stage = 'default-post'")
	// The local stub models botocore's parsed headers, including datetime Expires;
	// it is not an installed or executed boto3/botocore SDK.
	fixture := `import hashlib, io, datetime, email.utils
stage='setup'
payload=bytes(i%251 for i in range(32768))
common={'Content-Type':'application/octet-stream','Content-Encoding':'identity','Content-Disposition':'attachment','Cache-Control':'private','Content-Language':'en-GB','Expires':'Mon, 21 Oct 2030 07:28:00 GMT','x-amz-meta-owner':'sdk-post','x-amz-meta-purpose':'boto3'}
date=email.utils.parsedate_to_datetime(common['Expires'])
assert date.weekday()==0 and date.strftime('%a, %d %b %Y %H:%M:%S GMT')==common['Expires']
etag='"'+hashlib.md5(payload).hexdigest()+'"'
head={'ContentLength':len(payload),'ETag':etag,'ContentType':common['Content-Type'],'ContentEncoding':common['Content-Encoding'],'ContentDisposition':common['Content-Disposition'],'CacheControl':common['Cache-Control'],'ContentLanguage':common['Content-Language'],'Expires':date,'Metadata':{'owner':'sdk-post','purpose':'boto3'}}
bucket='fixture'
bad_read=''
class S3:
    def head_object(self, **kw): return head
    def get_object(self, **kw):
        value=dict(head)
        data=payload
        if 'Range' in kw: data=payload[:128]; value['ContentLength']=128; value['ContentRange']='bytes 0-127/32768'
        if bad_read==('range' if 'Range' in kw else 'get'): value['Metadata']={'Owner':'wrong','Purpose':'boto3'}
        value['Body']=io.BytesIO(data)
        return value
s3=S3()
` + strings.ReplaceAll(verify, "    ", " ") + `
verify_readback('fixture',payload,common,True)
assert stage=='default-range'
head['Expires']=date+datetime.timedelta(seconds=1)
try: verify_readback('fixture',payload,common,True)
except AssertionError: assert stage=='head-expires'
else: raise AssertionError('bad expires accepted')
head['Expires']=date
head['Metadata']={'Owner':'sdk-post','Purpose':'boto3'}
verify_readback('fixture',payload,common,True)
for bad, expected_stage in [({'Purpose':'boto3'},'head-owner-missing'),({'Owner':'wrong','Purpose':'boto3'},'head-owner-value'),({'Owner':'sdk-post','owner':'sdk-post','Purpose':'boto3'},'head-owner')]:
    head['Metadata']=bad
    try: verify_readback('fixture',payload,common,True)
    except AssertionError: assert stage==expected_stage
    else: raise AssertionError('bad metadata accepted')
head['Metadata']={'Owner':'sdk-post','Purpose':'wrong'}
try: verify_readback('fixture',payload,common,True)
except AssertionError: assert stage=='head-purpose'
else: raise AssertionError('bad purpose accepted')
head['Metadata']={'Owner':'sdk-post','Purpose':'boto3'}
for bad_read, expected_stage in [('get','default-get'),('range','default-range')]:
    try: verify_readback('fixture',payload,common,True)
    except AssertionError: assert stage==expected_stage
    else: raise AssertionError('bad read metadata accepted')
`
	// Dedent only the function's outer indentation, not its nested blocks.
	fixture = strings.Replace(fixture, strings.ReplaceAll(verify, "    ", " "), dedentPython(verify), 1)
	boundaryRun(t, python, ".py", fixture)
}

func dedentPython(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimPrefix(line, "    ")
	}
	return strings.Join(lines, "\n")
}

func TestGH353AWSJSActualSubmitBuiltinHTTP(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable")
	}
	source := (&awsJSPresignedPostRunner{}).Script(sdkTestEnv{})
	helper := boundaryExtract(t, source, "  async function submit(", "  function errorCode(")
	fixture := `import http from 'node:http';
let stage=''; let requests=0; let serverFailure=false;
const server=http.createServer(async(req,res)=>{
  requests++;
  try {
    if(req.method!=='POST'||req.url!=='/bucket'||!req.headers['content-type']?.startsWith('multipart/form-data; boundary=')) throw Error();
    const response=new Response(req,{headers:{'content-type':req.headers['content-type']}});
    const form=await response.formData();
    const keys=Array.from(form.keys());
    const token=form.get('X-Amz-Security-Token');
    if(keys.at(-1)!=='file'||form.get('X-Amz-Signature')!=='sig'||form.get('Policy')!=='policy'||(requests===1?token!=='token':requests===2?token!=='wrong':token!==null)||form.has('x-amz-security-token')) throw Error();
    const bytes=Buffer.from(await form.get('file').arrayBuffer());
    if(bytes.length!==32768||bytes.some((b,i)=>b!==i%251)) throw Error();
  } catch {serverFailure=true;}
  if(requests===1) {res.writeHead(204,{'ETag':'"etag"'});res.end();}
  else {res.writeHead(403,{'Content-Type':'application/xml'});res.end('<Error><Code>InvalidToken</Code></Error>');}
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
` + helper + `
const fields={Policy:'policy','X-Amz-Signature':'sig','X-Amz-Algorithm':'AWS4-HMAC-SHA256','X-Amz-Credential':'cred','X-Amz-Date':'date','X-Amz-Security-Token':'token'};
const data=Buffer.alloc(32768); for(let i=0;i<data.length;i++) data[i]=i%251;
const result=await submit({url:'http://127.0.0.1:'+server.address().port+'/bucket',fields},data,undefined,true);
if(serverFailure||requests!==1||result.status!==204||result.body!==''||result.headers.get('etag')!=='"etag"'||stage!=='submit-response-read') process.exitCode=1;
const wrong=await submit({url:'http://127.0.0.1:'+server.address().port+'/bucket',fields},data,f=>{f['X-Amz-Security-Token']='wrong';});
const missing=await submit({url:'http://127.0.0.1:'+server.address().port+'/bucket',fields},data,f=>{delete f['X-Amz-Security-Token'];});
if(serverFailure||requests!==3||wrong.status!==403||missing.status!==403||!wrong.body.includes('<Code>InvalidToken</Code>')||!missing.body.includes('<Code>InvalidToken</Code>')) process.exitCode=1;
let priorRejected=false;
const oldSource=submit.toString().replaceAll('X-Amz-Signature','x-amz-signature').replaceAll('X-Amz-Algorithm','x-amz-algorithm').replaceAll('X-Amz-Credential','x-amz-credential').replaceAll('X-Amz-Date','x-amz-date');
try {await (new Function('return '+oldSource))()({url:'http://127.0.0.1:'+server.address().port+'/bucket',fields},data)} catch {priorRejected=true}
if(!priorRejected||requests!==3) process.exitCode=1;
await new Promise(resolve=>server.close(resolve));
`
	boundaryRun(t, node, ".mjs", fixture)
}

func TestGH353AWSJSSessionCoverageAndMutation(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node unavailable")
	}
	browser := (&browserPostRunner{}).Script(sdkTestEnv{})
	coverage := boundaryExtract(t, browser, "function assertBrowserSessionCoverage(", "\nasync function markBrowserStage")
	callback := boundaryExtract(t, browser, "const browserSubmitCallback = ", "\nasync function browserSubmit")
	sdk := (&awsJSPresignedPostRunner{}).Script(sdkTestEnv{})
	jsCoverage := boundaryExtract(t, sdk, "  function assertGeneratedSessionCoverage(", "  async function form(")
	fixture := `function fixedFailure(){throw Error('fixed')}
` + coverage + "\n" + callback + "\n" + jsCoverage + `
const token='token';
const form=conditions=>({Policy:Buffer.from(JSON.stringify({conditions})).toString('base64'),'X-Amz-Security-Token':token});
for(const check of [assertBrowserSessionCoverage,assertGeneratedSessionCoverage]) {
 check(form([{'X-Amz-Security-Token':token}]),token);
 for(const bad of [[],[{'X-Amz-Security-Token':'wrong'}],[['starts-with','$X-Amz-Security-Token',token.slice(0,2)]],[{'x-amz-security-token':token}]]) {
   let failed=false; try{check(form(bad),token)}catch{failed=true} if(!failed) process.exitCode=1;
 }
 let missing=form([{'X-Amz-Security-Token':token}]); delete missing['X-Amz-Security-Token'];
 let failed=false; try{check(missing,token)}catch{failed=true} if(!failed) process.exitCode=1;
}
let priorRejected=false;
const oldCoverage=assertBrowserSessionCoverage.toString().replaceAll('X-Amz-Security-Token','x-amz-security-token');
try {(new Function('fixedFailure','return '+oldCoverage))(fixedFailure)(form([{'X-Amz-Security-Token':token}]),token)} catch {priorRejected=true}
if(!priorRejected) process.exitCode=1;
let sent;
globalThis.fetch=async(_url,opts)=>{sent=opts.body; return {status:403,headers:{get(){return null}},text:async()=>'<Error><Code>InvalidToken</Code></Error>'}};
globalThis.DOMParser=class {parseFromString(){return {documentElement:{localName:'Error'},getElementsByTagName(name){return name==='Code'?[{textContent:'InvalidToken'}]:[]}}}};
for(const mutation of ['wrong-token','missing-token']) {
 await browserSubmitCallback({post:{url:'http://fixture',fields:form([{'X-Amz-Security-Token':token}])},bytes:[1],mode:'session-denial',expected:{mutation}});
 if(mutation==='wrong-token' ? sent.get('X-Amz-Security-Token')!=='invalid-browser-session-token' : sent.has('X-Amz-Security-Token')) process.exitCode=1;
 if(sent.has('x-amz-security-token')) process.exitCode=1;
}
`
	boundaryRun(t, node, ".mjs", fixture)
}
