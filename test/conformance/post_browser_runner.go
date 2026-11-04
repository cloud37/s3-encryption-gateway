package conformance

import (
	"fmt"
	"strings"
	"time"
)

const (
	playwrightBrowserImage = "mcr.microsoft.com/playwright:v1.63.0-noble"
	playwrightVersion      = "1.63.0"
	browserRunnerTimeout   = 30 * time.Minute
)

type browserPostRunner struct{ sessionExpected bool }

func (*browserPostRunner) Name() string                    { return "playwright-browser-post" }
func (*browserPostRunner) Image() string                   { return playwrightBrowserImage }
func (*browserPostRunner) suppressSDKOutput() bool         { return true }
func (*browserPostRunner) containerTimeout() time.Duration { return browserRunnerTimeout }
func (r *browserPostRunner) testMode() string {
	if r.sessionExpected {
		return "session"
	}
	return "static"
}
func (r *browserPostRunner) requiresSessionToken() bool { return r.sessionExpected }

func browserCORSConfiguration(allowedOrigin string) string {
	return fmt.Sprintf(`<CORSConfiguration><CORSRule><ID>gh353-browser</ID><AllowedOrigin>%s</AllowedOrigin><AllowedMethod>POST</AllowedMethod><AllowedMethod>GET</AllowedMethod><AllowedMethod>HEAD</AllowedMethod><AllowedHeader>content-type</AllowedHeader><AllowedHeader>range</AllowedHeader><AllowedHeader>x-gh353-allowed</AllowedHeader><ExposeHeader>ETag</ExposeHeader><ExposeHeader>Content-Range</ExposeHeader><ExposeHeader>Content-Encoding</ExposeHeader><ExposeHeader>Content-Disposition</ExposeHeader><ExposeHeader>x-amz-meta-owner</ExposeHeader><ExposeHeader>x-amz-meta-purpose</ExposeHeader><ExposeHeader>x-amz-meta-browser</ExposeHeader><ExposeHeader>x-amz-version-id</ExposeHeader><MaxAgeSeconds>600</MaxAgeSeconds></CORSRule></CORSConfiguration>`, allowedOrigin)
}

func (*browserPostRunner) Script(sdkTestEnv) string {
	return `set -eu
mkdir -p /tmp/gh353-browser-runner
cd /tmp/gh353-browser-runner
npm install --silent --no-save playwright@` + playwrightVersion + ` @aws-sdk/client-s3@` + awsJSSDKVersion + ` @aws-sdk/s3-presigned-post@` + awsJSSDKVersion + ` @aws-sdk/s3-request-presigner@` + awsJSSDKVersion + ` >/dev/null 2>&1 || { echo 'browser-post:FAILED:install' >&2; exit 90; }
cat > /tmp/gh353-browser-runner/gh353_browser_post.mjs <<'JSEOF'
import process from 'node:process';
import {createHash} from 'node:crypto';
import {S3Client, HeadObjectCommand, GetObjectCommand} from '@aws-sdk/client-s3';
import {createPresignedPost} from '@aws-sdk/s3-presigned-post';
import {getSignedUrl} from '@aws-sdk/s3-request-presigner';
import {chromium} from 'playwright';

let stage='setup';
let browser;
let context;
let client;
function fixedFailure() { throw new Error('browser-stage-failed'); }
async function expectMissing(key) {
  try {
    await client.send(new HeadObjectCommand({Bucket:process.env.GATEWAY_BUCKET,Key:key}));
    fixedFailure();
  } catch (error) {
    if (error?.name === 'browser-stage-failed') throw error;
    const status=error?.$metadata?.httpStatusCode;
    if (status !== 404 && error?.name !== 'NotFound' && error?.name !== 'NoSuchKey') fixedFailure();
  }
}
async function verify(key, bytes) {
  const bucket=process.env.GATEWAY_BUCKET;
  const head=await client.send(new HeadObjectCommand({Bucket:bucket,Key:key}));
  if (head.ContentLength !== bytes.length || !head.ETag) fixedFailure();
  const full=await client.send(new GetObjectCommand({Bucket:bucket,Key:key}));
  const body=Buffer.from(await full.Body.transformToByteArray());
  if (!body.equals(bytes) || full.ETag !== head.ETag) fixedFailure();
  const range=await client.send(new GetObjectCommand({Bucket:bucket,Key:key,Range:'bytes=0-127'}));
  const rangeBody=Buffer.from(await range.Body.transformToByteArray());
  if (!rangeBody.equals(bytes.subarray(0,128)) || range.ContentLength !== 128 || range.ContentRange !== 'bytes 0-127/'+bytes.length || range.ETag !== head.ETag) fixedFailure();
  return head;
}
async function browserRead(page, key, bytes, expectedETag, includeBrowserMetadata=false) {
  const bucket=process.env.GATEWAY_BUCKET;
  const getURL=await getSignedUrl(client,new GetObjectCommand({Bucket:bucket,Key:key}),{expiresIn:600});
  const headURL=await getSignedUrl(client,new HeadObjectCommand({Bucket:bucket,Key:key}),{expiresIn:600});
  const rangeURL=await getSignedUrl(client,new GetObjectCommand({Bucket:bucket,Key:key}),{expiresIn:600});
  const result=await page.evaluate(async ({getURL,headURL,rangeURL,bytes,expectedETag,includeBrowserMetadata})=>{
    try {
      const expected=Uint8Array.from(bytes);
      const get=await fetch(getURL);
      const etag=get.headers.get('etag');
      const length=get.headers.get('content-length');
      const version=get.headers.get('x-amz-version-id');
      const body=new Uint8Array(await get.arrayBuffer());
      if(get.status!==200 || etag!==expectedETag || get.headers.get('x-amz-meta-owner')!=='browser-post' || get.headers.get('x-amz-meta-purpose')!=='browser' || get.headers.get('content-type')!=='application/octet-stream' || get.headers.get('content-encoding')!=='identity' || get.headers.get('content-disposition')!=='inline' || get.headers.get('cache-control')!=='no-cache' || get.headers.get('content-language')!=='en' || get.headers.get('expires')!=='Wed, 21 Oct 2030 07:28:00 GMT' || (includeBrowserMetadata && get.headers.get('x-amz-meta-browser')!=='allowed') || Number(length)!==expected.length || body.length!==expected.length || body.some((v,i)=>v!==expected[i])) throw new Error('readback');
      const head=await fetch(headURL,{method:'HEAD'});
      if(head.status!==200 || head.headers.get('x-amz-meta-owner')!=='browser-post' || head.headers.get('x-amz-meta-purpose')!=='browser' || head.headers.get('content-type')!=='application/octet-stream' || head.headers.get('content-encoding')!=='identity' || head.headers.get('content-disposition')!=='inline' || head.headers.get('cache-control')!=='no-cache' || head.headers.get('content-language')!=='en' || head.headers.get('expires')!=='Wed, 21 Oct 2030 07:28:00 GMT' || (includeBrowserMetadata && head.headers.get('x-amz-meta-browser')!=='allowed') || head.headers.get('etag')!==etag || head.headers.get('x-amz-version-id')!==version || Number(head.headers.get('content-length'))!==expected.length || (await head.arrayBuffer()).byteLength!==0) throw new Error('head');
      const range=await fetch(rangeURL,{headers:{Range:'bytes=0-127'}});
      const rangeBody=new Uint8Array(await range.arrayBuffer());
      if(range.status!==206 || range.headers.get('x-amz-meta-owner')!=='browser-post' || range.headers.get('x-amz-meta-purpose')!=='browser' || range.headers.get('content-type')!=='application/octet-stream' || range.headers.get('content-encoding')!=='identity' || range.headers.get('content-disposition')!=='inline' || range.headers.get('cache-control')!=='no-cache' || range.headers.get('content-language')!=='en' || range.headers.get('expires')!=='Wed, 21 Oct 2030 07:28:00 GMT' || (includeBrowserMetadata && range.headers.get('x-amz-meta-browser')!=='allowed') || range.headers.get('etag')!==etag || range.headers.get('x-amz-version-id')!==version || range.headers.get('content-range')!=='bytes 0-127/'+expected.length || range.headers.get('content-length')!=='128' || rangeBody.length!==128 || rangeBody.some((v,i)=>v!==expected[i])) throw new Error('range');
      return {ok:true};
    } catch { throw new Error('browser-read-assertion-failed'); }
  },{getURL,headURL,rangeURL,bytes:Array.from(bytes),expectedETag,includeBrowserMetadata});
  if(!result.ok) fixedFailure();
}
async function makeForm(key, purpose, custom=false, status='') {
  const fields={'Content-Type':'application/octet-stream','Content-Encoding':'identity','Content-Disposition':'inline','Cache-Control':'no-cache','Content-Language':'en','Expires':'Wed, 21 Oct 2030 07:28:00 GMT','x-amz-meta-owner':'browser-post','x-amz-meta-purpose':purpose,...(custom?{'x-amz-meta-browser':'allowed'}:{}),...(status?{success_action_status:String(status)}:{})};
  const conditions=Object.entries(fields).map(([name,value])=>({[name]:value}));
  conditions.push(['content-length-range',32768,32768]);
  return createPresignedPost(client,{Bucket:process.env.GATEWAY_BUCKET,Key:key,Fields:fields,Conditions:conditions,Expires:600});
}
function assertBrowserSessionCoverage(fields, token) {
  if(fields['X-Amz-Security-Token']!==token || !token || !fields.Policy) fixedFailure();
  const decoded=JSON.parse(Buffer.from(fields.Policy,'base64').toString('utf8'));
  if(!Array.isArray(decoded.conditions) || !decoded.conditions.some(condition=>condition && !Array.isArray(condition) && condition['X-Amz-Security-Token']===token)) fixedFailure();
}
async function markBrowserStage(name) {
  const response=await fetch(process.env.BROWSER_STAGE_URL+'/'+name,{method:'POST'});
  if(!response.ok) fixedFailure();
}
const browserSubmitCallback = async ({post,bytes,mode,expected}) => {
    try {
      const data=Uint8Array.from(bytes);
      const form=new FormData();
      const fields={...post.fields};
      if(expected.mutation==='wrong-token') fields['X-Amz-Security-Token']='invalid-browser-session-token';
      if(expected.mutation==='missing-token') delete fields['X-Amz-Security-Token'];
      for (const [name,value] of Object.entries(fields)) {
        if(name==='Policy' || name==='policy') form.append(name,value);
        else form.append(name,String(value));
      }
      form.append('file',new Blob([data],{type:'application/octet-stream'}),'browser.bin');
      const options={method:'POST',body:form};
      if (mode==='custom-allowed') options.headers={'X-GH353-Allowed':'yes'};
      if (mode==='custom-denied') options.headers={'X-GH353-Denied':'no'};
      const response=await fetch(post.url,options);
      const etag=response.headers.get('etag');
      const body=await response.text();
      if (mode==='unreadable') throw new Error('unexpected-readable-response');
      if (mode==='session-denial') {
        const doc=new DOMParser().parseFromString(body,'application/xml');
        if(response.status!==403 || doc.documentElement?.localName!=='Error' || doc.getElementsByTagName('Code')[0]?.textContent!=='InvalidToken' || doc.getElementsByTagName('parsererror').length) throw new Error('session-response');
        return {ok:true,etag};
      }
      if (mode==='policy-denial') {
        const doc=new DOMParser().parseFromString(body,'application/xml');
        if (response.status!==403 || doc.documentElement?.localName!=='Error' || doc.getElementsByTagName('Code')[0]?.textContent!=='AccessDenied' || doc.getElementsByTagName('parsererror').length) throw new Error('policy-response');
        return {ok:true,etag};
      }
      if (mode==='created') {
        if (response.status!==201 || etag!==expected.etag) throw new Error('created-response');
        const doc=new DOMParser().parseFromString(body,'application/xml');
        const ns='http://s3.amazonaws.com/doc/2006-03-01/';
        const value=name=>doc.getElementsByTagNameNS(ns,name)[0]?.textContent;
        const encodeSegment=part=>Array.from(new TextEncoder().encode(part),byte=>
          (byte>=0x41&&byte<=0x5a)||(byte>=0x61&&byte<=0x7a)||(byte>=0x30&&byte<=0x39)||byte===0x2d||byte===0x5f||byte===0x7e
            ? String.fromCharCode(byte) : '%'+byte.toString(16).toUpperCase().padStart(2,'0')).join('');
        const encodeBucket=value=>encodeURIComponent(value).replace(/[!'()*]/g,char=>'%'+char.charCodeAt(0).toString(16).toUpperCase());
        const expectedLocation=expected.endpoint+expected.endpointPath+'/'+encodeBucket(expected.bucket)+'/'+expected.key.split('/').map(encodeSegment).join('/');
        if (doc.documentElement?.localName!=='PostResponse' || doc.documentElement?.namespaceURI!==ns || doc.getElementsByTagName('parsererror').length || value('Bucket')!==expected.bucket || value('Key')!==expected.key || value('ETag')!==etag || value('Location')!==expectedLocation) throw new Error('created-xml');
        return {ok:true,etag};
      }
      if ((mode==='custom-allowed' || mode==='custom-denied') && response.status!==204) throw new Error('custom-status');
       if (response.status!==204 || body!=='' || etag!==expected.etag) throw new Error('success-response');
      return {ok:true,etag};
    } catch (error) {
      if (mode==='unreadable' && error instanceof TypeError) return {ok:true,unreadable:true};
      if (mode==='custom-denied' && error instanceof TypeError) return {ok:true,preflightDenied:true};
      throw new Error('browser-assertion-failed');
    }
};
async function browserSubmit(page, post, bytes, mode, expected) {
  return page.evaluate(browserSubmitCallback,{post,bytes:Array.from(bytes),mode,expected});
}
try {
  const endpoint=process.env.GATEWAY_ENDPOINT;
  const bucket=process.env.GATEWAY_BUCKET;
  const prefix=process.env.GATEWAY_KEY;
  const allowedPageOrigin=new URL(process.env.BROWSER_PAGE_URL).origin;
  const session=process.env.GH353_SESSION_MODE==='session';
  const token=process.env.AWS_SESSION_TOKEN||'';
   const expectedEndpointPath=new URL(endpoint).pathname.replace(/\/$/,'');
   if (!process.env.BROWSER_PAGE_URL || !process.env.BROWSER_DENIED_PAGE_URL || session!==Boolean(token) ||
       new URL(process.env.BROWSER_PAGE_URL).origin===new URL(process.env.BROWSER_DENIED_PAGE_URL).origin ||
      new URL(process.env.BROWSER_PAGE_URL).origin===new URL(endpoint).origin ||
      new URL(process.env.BROWSER_DENIED_PAGE_URL).origin===new URL(endpoint).origin) fixedFailure();
  client=new S3Client({endpoint,region:process.env.AWS_DEFAULT_REGION,forcePathStyle:true,credentials:{accessKeyId:process.env.AWS_ACCESS_KEY_ID,secretAccessKey:process.env.AWS_SECRET_ACCESS_KEY,...(token?{sessionToken:token}:{})}});
  const payload=Buffer.alloc(32768);
  for(let i=0;i<payload.length;i++) payload[i]=i%251;
  browser=await chromium.launch({headless:true});
  context=await browser.newContext();
  const page=await context.newPage();
  stage='browser-page';
  await page.goto(process.env.BROWSER_PAGE_URL,{waitUntil:'domcontentloaded'});
  const defaultKey=prefix+'-browser-default';
  stage='browser-allowed-post';
   const defaultForm=await makeForm(defaultKey,'browser');
   await markBrowserStage('default');
   const defaultETag='"'+createHash('md5').update(payload).digest('hex')+'"';
   const defaultResult=await browserSubmit(page,defaultForm,payload,'default',{bucket,key:defaultKey,endpoint,etag:defaultETag});
   if(!defaultResult.ok || defaultResult.etag!==defaultETag) fixedFailure();
  const defaultHead=await verify(defaultKey,payload);
   if(defaultResult.etag!==defaultHead.ETag) fixedFailure();
   await markBrowserStage('default-read');
   await browserRead(page,defaultKey,payload,defaultETag);
  console.log('browser-post:ALLOWED_POST_OK');

  stage='browser-policy-denial';
   const deniedPolicy=await makeForm(defaultKey,'must-match');
   const policyFields={...deniedPolicy.fields,'x-amz-meta-purpose':'browser'};
   await markBrowserStage('policy-denial');
  const policyResult=await browserSubmit(page,{...deniedPolicy,fields:policyFields},payload,'policy-denial',{bucket,key:defaultKey,endpoint});
   if(!policyResult.ok || (await verify(defaultKey,payload)).ETag!==defaultHead.ETag) fixedFailure();
  console.log('browser-post:POLICY_DENIAL_OK');

  stage='browser-created-response';
  const createdKey=prefix+'-browser-created';
   const createdForm=await makeForm(createdKey,'browser',false,201);
   await markBrowserStage('created');
   const createdETag='"'+createHash('md5').update(payload).digest('hex')+'"';
   const createdResult=await browserSubmit(page,createdForm,payload,'created',{bucket,key:createdKey,endpoint,endpointPath:expectedEndpointPath,etag:createdETag});
   if(!createdResult.ok || createdResult.etag!==createdETag) fixedFailure();
  const createdHead=await verify(createdKey,payload);
   if(createdResult.etag!==createdHead.ETag) fixedFailure();
   await markBrowserStage('created-read');
   await browserRead(page,createdKey,payload,createdETag);
  console.log('browser-post:CREATED_XML_OK');

  stage='browser-custom-header-preflight';
  const customKey=prefix+'-browser-preflight';
   const customForm=await makeForm(customKey,'browser',true);
   await markBrowserStage('custom-allowed');
   const customETag='"'+createHash('md5').update(payload).digest('hex')+'"';
   const customResult=await browserSubmit(page,customForm,payload,'custom-allowed',{bucket,key:customKey,endpoint,etag:customETag});
   if(!customResult.ok || customResult.etag!==customETag) fixedFailure();
  const customHead=await verify(customKey,payload);
   if(customResult.etag!==customHead.ETag) fixedFailure();
   await markBrowserStage('custom-read');
   await browserRead(page,customKey,payload,customETag,true);
  console.log('browser-post:PREFLIGHT_POST_OK');

  stage='browser-denied-custom-header';
  const deniedHeaderKey=prefix+'-browser-denied-header';
   const deniedHeaderForm=await makeForm(deniedHeaderKey,'browser');
   await markBrowserStage('custom-denied');
  const deniedHeaderResult=await browserSubmit(page,deniedHeaderForm,payload,'custom-denied',{bucket,key:deniedHeaderKey,endpoint});
   if(!deniedHeaderResult.preflightDenied) fixedFailure();
  await expectMissing(deniedHeaderKey);
  console.log('browser-post:DENIED_PREFLIGHT_OK');

  stage='browser-denied-origin';
  await page.goto(process.env.BROWSER_DENIED_PAGE_URL,{waitUntil:'domcontentloaded'});
  const unreadableKey=prefix+'-browser-denied-origin';
   const unreadableForm=await makeForm(unreadableKey,'browser');
   await markBrowserStage('denied-origin');
  const unreadable=await browserSubmit(page,unreadableForm,payload,'unreadable',{bucket,key:unreadableKey,endpoint});
   if(!unreadable.unreadable) fixedFailure();
  await verify(unreadableKey,payload);
  const deniedProbe=await context.newPage();
  await deniedProbe.goto(process.env.BROWSER_DENIED_PAGE_URL,{waitUntil:'domcontentloaded'});
  const deniedReadKey=prefix+'-browser-created';
   const deniedReadForm=await getSignedUrl(client,new GetObjectCommand({Bucket:bucket,Key:deniedReadKey}),{expiresIn:600});
   let deniedRead;
   await markBrowserStage('denied-origin-read');
  try {
    deniedRead=await deniedProbe.evaluate(async url=>{try { const response=await fetch(url); return {readable:true,status:response.status,body:await response.arrayBuffer()}; } catch(error) { return {readable:false,typeError:error instanceof TypeError}; }},deniedReadForm);
  } catch { fixedFailure(); }
  if(deniedRead?.readable || !deniedRead?.typeError) fixedFailure();
  await page.goto(process.env.BROWSER_PAGE_URL,{waitUntil:'domcontentloaded'});
  console.log('browser-post:DENIED_ORIGIN_UNREADABLE_OK');

  if(session) {
    stage='browser-session-post';
    await page.goto(process.env.BROWSER_PAGE_URL,{waitUntil:'domcontentloaded'});
    const sessionKey=prefix+'-browser-session';
    stage='browser-session-form';
    const sessionForm=await makeForm(sessionKey,'browser');
    stage='browser-session-coverage';
    assertBrowserSessionCoverage(sessionForm.fields,token);
     await markBrowserStage('session-upload');
     const sessionETag='"'+createHash('md5').update(payload).digest('hex')+'"';
     stage='browser-session-submit';
     const sessionResult=await browserSubmit(page,sessionForm,payload,'default',{bucket,key:sessionKey,endpoint,etag:sessionETag});
    if(!sessionResult.ok || !sessionResult.etag) fixedFailure();
    stage='browser-session-sdk-read';
    const sessionHead=await verify(sessionKey,payload);
     if(sessionResult.etag!==sessionHead.ETag) fixedFailure();
     if(sessionResult.etag!==sessionETag) fixedFailure();
     await markBrowserStage('session-read');
     stage='browser-session-browser-read';
     await browserRead(page,sessionKey,payload,sessionETag);
     for(const mutation of ['wrong-token','missing-token']) {
       stage='browser-session-token-denial';
       await markBrowserStage(mutation==='wrong-token'?'session-wrong-token':'session-missing-token');
      const denial=await browserSubmit(page,sessionForm,payload,'session-denial',{bucket,key:sessionKey,endpoint,mutation});
      if(!denial.ok || (await verify(sessionKey,payload)).ETag!==sessionHead.ETag) fixedFailure();
    }
    console.log('browser-post:SESSION_UPLOAD_OK');
    console.log('browser-post:SESSION_DENIALS_OK');
  }
  await context.close();
  console.log('browser-post:MODE_'+(session?'SESSION':'STATIC'));
  console.log('browser-post:COMPLETE');
} catch {
  console.log('browser-post:FAILED:'+stage);
  process.exitCode=1;
} finally {
  if(context) { try { await context.close(); } catch {} }
  if(browser) { try { await browser.close(); } catch {} }
  if(client) { try { client.destroy(); } catch {} }
}
JSEOF
node /tmp/gh353-browser-runner/gh353_browser_post.mjs 2>/dev/null || exit 91
`
}

func (r *browserPostRunner) AssertOutput(code int, stdout, stderr string) error {
	required := []string{
		"browser-post:ALLOWED_POST_OK",
		"browser-post:POLICY_DENIAL_OK",
		"browser-post:CREATED_XML_OK",
		"browser-post:PREFLIGHT_POST_OK",
		"browser-post:DENIED_PREFLIGHT_OK",
		"browser-post:DENIED_ORIGIN_UNREADABLE_OK",
	}
	if r.sessionExpected {
		required = append(required, "browser-post:SESSION_UPLOAD_OK", "browser-post:SESSION_DENIALS_OK")
	}
	required = append(required, "browser-post:MODE_"+strings.ToUpper(r.testMode()), "browser-post:COMPLETE")
	return assertPostRunnerOutput("browser-post", r.testMode(), code, stdout, stderr, required...)
}

var _ sdkToolRunner = (*browserPostRunner)(nil)
var _ safeSDKOutputRunner = (*browserPostRunner)(nil)
