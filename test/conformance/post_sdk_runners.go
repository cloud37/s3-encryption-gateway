package conformance

import (
	"fmt"
	"strings"
	"time"
)

const (
	awsJSNodeImage    = "node:24-bookworm-slim"
	awsJSSDKVersion   = "3.1146.0"
	postRunnerTimeout = 30 * time.Minute
)

type boto3PresignedPostRunner struct{ sessionExpected bool }

func (*boto3PresignedPostRunner) Name() string                    { return "boto3-presigned-post" }
func (*boto3PresignedPostRunner) Image() string                   { return pythonImage }
func (*boto3PresignedPostRunner) suppressSDKOutput() bool         { return true }
func (*boto3PresignedPostRunner) containerTimeout() time.Duration { return postRunnerTimeout }
func (r *boto3PresignedPostRunner) testMode() string {
	if r.sessionExpected {
		return "session"
	}
	return "static"
}
func (r *boto3PresignedPostRunner) requiresSessionToken() bool { return r.sessionExpected }

func (*boto3PresignedPostRunner) Script(sdkTestEnv) string {
	return "set -eu\npip install -q boto3==" + boto3Version + " >/dev/null 2>&1 || { echo 'boto3-post:FAILED:install' >&2; exit 90; }\ncd /tmp\ncat > /tmp/gh353_boto3_post.py <<'PYEOF'\n" + `
import os, sys, urllib.error, urllib.request, xml.etree.ElementTree as ET, hashlib, base64, json
import hashlib
import boto3
from botocore.config import Config

stage = 'setup'
try:
    session = boto3.session.Session()
    s3 = session.client('s3', endpoint_url=os.environ['GATEWAY_ENDPOINT'],
        region_name=os.environ['AWS_DEFAULT_REGION'],
        config=Config(signature_version='s3v4', s3={'addressing_style':'path'}))
    bucket, prefix = os.environ['GATEWAY_BUCKET'], os.environ['GATEWAY_KEY']
    payload = bytes((i % 251 for i in range(32768)))
    expected_meta = {'x-amz-meta-owner':'sdk-post', 'x-amz-meta-purpose':'boto3'}
    common = {
        'Content-Type':'application/octet-stream', 'Content-Encoding':'identity',
        'Content-Disposition':'attachment', 'Cache-Control':'private',
        'Content-Language':'en-GB', 'Expires':'Mon, 21 Oct 2030 07:28:00 GMT',
        **expected_meta,
    }

    def make_form(key, status=None, bad_condition=False):
        fields = dict(common)
        conditions = []
        if bad_condition:
            fields['x-amz-meta-purpose'] = 'must-match'
            conditions.append({'x-amz-meta-purpose':'must-match'})
        for name, value in fields.items():
            conditions.append({name:value})
        if status:
            fields['success_action_status'] = str(status)
            conditions.append({'success_action_status':str(status)})
        conditions.append(['content-length-range',32768,32768])
        return s3.generate_presigned_post(Bucket=bucket, Key=key, Fields=fields,
            Conditions=conditions, ExpiresIn=600)

    def assert_generated_session_coverage(form):
        fields = form['fields']
        token = os.environ['AWS_SESSION_TOKEN']
        assert fields.get('x-amz-security-token') == token
        policy = json.loads(base64.b64decode(fields['policy']))
        assert any(isinstance(condition, dict) and condition.get('x-amz-security-token') == token
                   for condition in policy['conditions'])

    def send_form(form, data, mutate=None):
        fields = dict(form['fields'])
        if mutate:
            mutate(fields)
        assert 'policy' in fields and 'x-amz-signature' in fields
        assert fields.get('x-amz-algorithm') == 'AWS4-HMAC-SHA256'
        assert fields.get('x-amz-credential')
        assert fields.get('x-amz-date')
        boundary = 'gh353-sdk-boundary-9d2f'
        chunks = []
        for name, value in fields.items():
            chunks.extend([('--'+boundary+'\r\n').encode(),
                ('Content-Disposition: form-data; name="'+name+'"\r\n\r\n').encode(),
                str(value).encode(), b'\r\n'])
        chunks.extend([('--'+boundary+'\r\n').encode(),
            b'Content-Disposition: form-data; name="file"; filename="sdk.bin"\r\n',
            b'Content-Type: application/octet-stream\r\n\r\n', data, b'\r\n',
            ('--'+boundary+'--\r\n').encode()])
        request = urllib.request.Request(form['url'], data=b''.join(chunks), method='POST',
            headers={'Content-Type':'multipart/form-data; boundary='+boundary})
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, response.read(), response.headers
        except urllib.error.HTTPError as error:
            return error.code, error.read(), error.headers

    def error_code(body):
        try:
            return ET.fromstring(body).findtext('{*}Code')
        except Exception:
            return None

    def normalized_user_metadata(response):
        normalized = {}
        for name, value in response['Metadata'].items():
            name = name.lower()
            assert name not in normalized
            normalized[name] = value
        return normalized

    def verify_readback(key, expected, metadata, diagnostic=False):
        global stage
        if diagnostic: stage = 'default-head'
        head = s3.head_object(Bucket=bucket, Key=key)
        if diagnostic: stage = 'head-length'
        assert head['ContentLength'] == len(expected)
        if diagnostic: stage = 'head-etag'
        assert head['ETag'].strip('"') == hashlib.md5(expected).hexdigest()
        if diagnostic: stage = 'head-ctype'
        assert head['ContentType'] == metadata['Content-Type']
        if diagnostic: stage = 'head-encoding'
        assert head['ContentEncoding'] == metadata['Content-Encoding']
        if diagnostic: stage = 'head-disposition'
        assert head['ContentDisposition'] == metadata['Content-Disposition']
        if diagnostic: stage = 'head-cache'
        assert head['CacheControl'] == metadata['Cache-Control']
        if diagnostic: stage = 'head-language'
        assert head['ContentLanguage'] == metadata['Content-Language']
        if diagnostic: stage = 'head-expires'
        assert head['Expires'].strftime('%a, %d %b %Y %H:%M:%S GMT') == metadata['Expires']
        if diagnostic: stage = 'head-owner'
        head_metadata = normalized_user_metadata(head)
        if diagnostic: stage = 'head-owner-missing'
        assert 'owner' in head_metadata
        if diagnostic: stage = 'head-owner-value'
        assert head_metadata['owner'] == metadata['x-amz-meta-owner']
        if diagnostic: stage = 'head-purpose'
        assert head_metadata['purpose'] == metadata['x-amz-meta-purpose']
        if diagnostic: stage = 'default-get'
        obj = s3.get_object(Bucket=bucket, Key=key)
        try:
            body = obj['Body'].read()
        finally:
            obj['Body'].close()
        assert obj['ETag'] == head['ETag']
        assert body == expected
        assert obj['ContentLength'] == len(expected)
        assert obj['ContentType'] == metadata['Content-Type']
        assert obj['ContentEncoding'] == metadata['Content-Encoding']
        assert obj['ContentDisposition'] == metadata['Content-Disposition']
        assert obj['CacheControl'] == metadata['Cache-Control']
        assert obj['ContentLanguage'] == metadata['Content-Language']
        assert obj['Expires'].strftime('%a, %d %b %Y %H:%M:%S GMT') == metadata['Expires']
        obj_metadata = normalized_user_metadata(obj)
        assert obj_metadata['owner'] == metadata['x-amz-meta-owner']
        assert obj_metadata['purpose'] == metadata['x-amz-meta-purpose']
        assert obj['ETag'] == head['ETag']
        if diagnostic: stage = 'default-range'
        ranged = s3.get_object(Bucket=bucket, Key=key, Range='bytes=0-127')
        try:
            range_body = ranged['Body'].read()
        finally:
            ranged['Body'].close()
        assert range_body == expected[:128]
        assert ranged['ContentLength'] == 128
        assert ranged['ContentRange'] == 'bytes 0-127/'+str(len(expected))
        assert ranged['ContentType'] == metadata['Content-Type']
        assert ranged['ContentEncoding'] == metadata['Content-Encoding']
        assert ranged['ContentDisposition'] == metadata['Content-Disposition']
        assert ranged['CacheControl'] == metadata['Cache-Control']
        assert ranged['ContentLanguage'] == metadata['Content-Language']
        assert ranged['Expires'].strftime('%a, %d %b %Y %H:%M:%S GMT') == metadata['Expires']
        range_metadata = normalized_user_metadata(ranged)
        assert range_metadata['owner'] == metadata['x-amz-meta-owner']
        assert range_metadata['purpose'] == metadata['x-amz-meta-purpose']
        assert ranged['ETag'] == head['ETag']

    stage = 'default-post'
    default_key = prefix+'-boto3-default'
    default_form = make_form(default_key)
    stage = 'default-submit'
    status, response_body, response_headers = send_form(default_form, payload)
    stage = 'default-response'
    if status != 204:
        stage = {400:'default-response-400', 403:'default-response-403', 500:'default-response-500'}.get(status, 'default-response-other')
        if status == 400 and error_code(response_body) == 'MetadataTooLarge': stage = 'default-response-metadata-too-large'
    assert status == 204 and response_body == b''
    verify_readback(default_key, payload, common, diagnostic=True)
    stage = 'default-post-etag'
    assert response_headers.get('ETag') == s3.head_object(Bucket=bucket, Key=default_key)['ETag']
    print('boto3-post:DEFAULT_OK')

    stage = 'signed-policy-denial'
    denied = make_form(default_key, bad_condition=True)
    status, response_body, _ = send_form(denied, payload,
        lambda fields: fields.__setitem__('x-amz-meta-purpose', 'boto3'))
    assert status == 403 and error_code(response_body) == 'AccessDenied'
    verify_readback(default_key, payload, common)
    print('boto3-post:NEGATIVE_OK')

    stage = 'created-response'
    created_key = prefix+'-boto3-created'
    created_form = make_form(created_key, status=201)
    status, response_body, response_headers = send_form(created_form, payload)
    assert status == 201
    root = ET.fromstring(response_body)
    ns = {'s3':'http://s3.amazonaws.com/doc/2006-03-01/'}
    assert root.tag == '{http://s3.amazonaws.com/doc/2006-03-01/}PostResponse'
    assert root.findtext('s3:Bucket', namespaces=ns) == bucket
    assert root.findtext('s3:Key', namespaces=ns) == created_key
    location = root.findtext('s3:Location', namespaces=ns)
    from urllib.parse import urlsplit, unquote
    parsed_location = urlsplit(location or '')
    assert parsed_location.scheme == urlsplit(os.environ['GATEWAY_ENDPOINT']).scheme
    assert parsed_location.netloc == urlsplit(os.environ['GATEWAY_ENDPOINT']).netloc
    assert not parsed_location.query and not parsed_location.fragment
    assert unquote(parsed_location.path) == '/'+bucket+'/'+created_key
    assert not parsed_location.query and not parsed_location.fragment
    created_head = s3.head_object(Bucket=bucket, Key=created_key)
    verify_readback(created_key, payload, common)
    assert root.findtext('s3:ETag', namespaces=ns) == created_head['ETag'] == response_headers.get('ETag')
    print('boto3-post:CREATED_OK')
    print('boto3-post:MODE_'+os.environ.get('GH353_SESSION_MODE','static').upper())

    if os.environ.get('GH353_SESSION_MODE') == 'session' and os.environ.get('AWS_SESSION_TOKEN'):
        stage = 'session-post'
        session_key = prefix+'-boto3-session'
        session_form = make_form(session_key)
        assert_generated_session_coverage(session_form)
        status, response_body, response_headers = send_form(session_form, payload)
        assert status == 204 and response_body == b''
        verify_readback(session_key, payload, common)
        assert response_headers.get('ETag') == s3.head_object(Bucket=bucket, Key=session_key)['ETag']
        print('boto3-post:SESSION_OK')

        stage = 'wrong-session-token-denial'
        wrong_token = __import__('secrets').token_urlsafe(24)
        status, response_body, _ = send_form(session_form, payload,
            lambda fields: fields.__setitem__('x-amz-security-token', wrong_token))
        assert status == 403 and error_code(response_body) == 'InvalidToken'
        verify_readback(session_key, payload, common)
        print('boto3-post:SESSION_DENIAL_OK')
        status, response_body, _ = send_form(session_form, payload,
            lambda fields: fields.pop('x-amz-security-token', None))
        assert status == 403 and error_code(response_body) == 'InvalidToken'
        verify_readback(session_key, payload, common)
        print('boto3-post:SESSION_MISSING_DENIAL_OK')
        print('boto3-post:COMPLETE')
    else:
        if os.environ.get('GH353_SESSION_MODE') == 'session':
            raise RuntimeError('session fixture absent')
        print('boto3-post:STATIC_OK')
        print('boto3-post:COMPLETE')
except Exception:
    print('boto3-post:FAILED:'+stage)
    sys.exit(1)
` + "\nPYEOF\npython3 /tmp/gh353_boto3_post.py 2>/dev/null || exit 91\n"
}

func (r *boto3PresignedPostRunner) AssertOutput(code int, stdout, stderr string) error {
	required := []string{"boto3-post:DEFAULT_OK", "boto3-post:NEGATIVE_OK", "boto3-post:CREATED_OK", "boto3-post:MODE_" + strings.ToUpper(r.testMode())}
	if r.sessionExpected {
		required = append(required, "boto3-post:SESSION_OK", "boto3-post:SESSION_DENIAL_OK", "boto3-post:SESSION_MISSING_DENIAL_OK")
	} else {
		required = append(required, "boto3-post:STATIC_OK")
	}
	required = append(required, "boto3-post:COMPLETE")
	return assertPostRunnerOutput("boto3-post", r.testMode(), code, stdout, stderr, required...)
}

type awsJSPresignedPostRunner struct{ sessionExpected bool }

func (*awsJSPresignedPostRunner) Name() string                    { return "aws-js-presigned-post" }
func (*awsJSPresignedPostRunner) Image() string                   { return awsJSNodeImage }
func (*awsJSPresignedPostRunner) suppressSDKOutput() bool         { return true }
func (*awsJSPresignedPostRunner) containerTimeout() time.Duration { return postRunnerTimeout }
func (r *awsJSPresignedPostRunner) testMode() string {
	if r.sessionExpected {
		return "session"
	}
	return "static"
}
func (r *awsJSPresignedPostRunner) requiresSessionToken() bool { return r.sessionExpected }

func (*awsJSPresignedPostRunner) Script(sdkTestEnv) string {
	return `set -eu
mkdir -p /tmp/gh353-post-runner
cd /tmp/gh353-post-runner
npm install --silent --no-save @aws-sdk/client-s3@` + awsJSSDKVersion + ` @aws-sdk/s3-presigned-post@` + awsJSSDKVersion + ` >/dev/null 2>&1 || { echo 'aws-js-post:FAILED:install' >&2; exit 90; }
cat > /tmp/gh353-post-runner/gh353_aws_js_post.mjs <<'JSEOF'
import process from 'node:process';
import {S3Client, HeadObjectCommand, GetObjectCommand} from '@aws-sdk/client-s3';
import {createPresignedPost} from '@aws-sdk/s3-presigned-post';

let stage = 'setup';
function decodeXMLText(text) {
  const reference = /&(#x[0-9a-fA-F]+|#\d+|amp|lt|gt|quot|apos);/g;
  const withoutReferences = text.replace(reference, '');
  if (withoutReferences.includes('&')) throw new Error('xml-entity');
  const decoded = text.replace(reference, (_, entity) => {
    if (entity === 'amp') return '&';
    if (entity === 'lt') return '<';
    if (entity === 'gt') return '>';
    if (entity === 'quot') return '"';
    if (entity === 'apos') return "'";
    const radix = entity.startsWith('#x') ? 16 : 10;
    const cp = Number.parseInt(entity.slice(radix === 16 ? 2 : 1), radix);
    if (!Number.isInteger(cp) || !(cp === 0x9 || cp === 0xa || cp === 0xd ||
        (cp >= 0x20 && cp <= 0xd7ff) || (cp >= 0xe000 && cp <= 0xfffd) ||
        (cp >= 0x10000 && cp <= 0x10ffff))) throw new Error('xml-character');
    return String.fromCodePoint(cp);
  });
  return decoded;
}
function parsePostResponse(xml) {
  const root = xml.match(/^<\?xml\s+version="1\.0"\s+encoding="UTF-8"\?>\s*<PostResponse\s+xmlns="http:\/\/s3\.amazonaws\.com\/doc\/2006-03-01\/">([\s\S]*)<\/PostResponse>\s*$/);
  if (!root) throw new Error('xml-root');
  const result = {};
  let remainder = root[1];
  for (const tag of ['Location','Bucket','Key','ETag']) {
    const field = remainder.match(new RegExp('^\\s*<'+tag+'>([\\s\\S]*?)</'+tag+'>'));
    if (!field || field[1].includes('<')) throw new Error('xml-field');
    result[tag] = decodeXMLText(field[1]);
    remainder = remainder.slice(field[0].length);
  }
  if (remainder.trim() !== '') throw new Error('xml-field');
  return result;
}
function assertPostLocation(locationValue, endpoint, endpointPath, bucket, key) {
  const target = locationValue.match(/^([A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?$/);
  if (!target || target[3] !== undefined || target[4] !== undefined) throw new Error('location-shape');
  const expected = endpoint.match(/^([A-Za-z][A-Za-z0-9+.-]*:\/\/[^/?#]*)/);
  let targetOrigin, expectedOrigin;
  try {
    targetOrigin = new URL(target[1]);
    expectedOrigin = new URL(endpoint);
  } catch { throw new Error('location-origin'); }
  if (!expected || target[1] !== expected[1] || targetOrigin.username !== '' || targetOrigin.password !== '' ||
      targetOrigin.protocol !== expectedOrigin.protocol || targetOrigin.host !== expectedOrigin.host ||
      expectedOrigin.username !== '' || expectedOrigin.password !== '') throw new Error('location-origin');
  const rawPath = target[2];
  const basePath = endpointPath.replace(/\/$/, '');
  if (!rawPath.startsWith(basePath)) throw new Error('location-path');
  const suffix = rawPath.slice(basePath.length);
  if (!suffix.startsWith('/')) throw new Error('location-path');
  const segments = suffix.slice(1).split('/');
  let decoded;
  try { decoded = segments.map(segment => decodeURIComponent(segment)); }
  catch { throw new Error('location-path-encoding'); }
  if (decoded.length < 2 || decoded.some(segment => segment.includes('/')) ||
      decoded[0] !== bucket || decoded.slice(1).join('/') !== key) throw new Error('location-path');
}
try {
  const endpoint = process.env.GATEWAY_ENDPOINT;
  const bucket = process.env.GATEWAY_BUCKET;
  const prefix = process.env.GATEWAY_KEY;
  const client = new S3Client({endpoint, region:process.env.AWS_DEFAULT_REGION,
    forcePathStyle:true, credentials:{accessKeyId:process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey:process.env.AWS_SECRET_ACCESS_KEY,
      ...(process.env.AWS_SESSION_TOKEN ? {sessionToken:process.env.AWS_SESSION_TOKEN} : {})}});
  const endpointPath = new URL(endpoint).pathname.replace(/\/$/,'');
  const payload = Buffer.alloc(32768);
  for (let i=0; i<payload.length; i++) payload[i] = i % 251;
  const common = {
    'Content-Type':'application/octet-stream', 'Content-Encoding':'identity',
    'Content-Disposition':'attachment', 'Cache-Control':'private',
    'Content-Language':'en-GB', 'Expires':'Mon, 21 Oct 2030 07:28:00 GMT',
    'x-amz-meta-owner':'sdk-post', 'x-amz-meta-purpose':'awsjs'
  };
  function assertGeneratedSessionCoverage(fields, token) {
    if (!token) return;
    if (fields['X-Amz-Security-Token'] !== token || !fields.Policy) throw new Error('session-policy-fields');
    let policy;
    try { policy = JSON.parse(Buffer.from(fields.Policy,'base64').toString('utf8')); }
    catch { throw new Error('session-policy-parse'); }
    if (!Array.isArray(policy.conditions) || !policy.conditions.some(condition =>
        condition && !Array.isArray(condition) && condition['X-Amz-Security-Token'] === token)) throw new Error('session-policy-coverage');
  }
  async function form(key, status, badCondition=false) {
    const fields = {...common, ...(status ? {success_action_status:String(status)} : {})};
    if (badCondition) fields['x-amz-meta-purpose']='must-match';
    const conditions = Object.entries(fields).map(([name,value]) => ({[name]:value}));
    conditions.push(['content-length-range',32768,32768]);
    return await createPresignedPost(client,{Bucket:bucket,Key:key,Fields:fields,Conditions:conditions,Expires:600});
  }
  async function submit(post, fileBytes, mutate, diagnostic=false) {
    if (diagnostic) stage='submit-body';
    const fields = {...post.fields};
    if (mutate) mutate(fields);
    if (!fields.Policy || !fields['X-Amz-Signature'] || fields['X-Amz-Algorithm'] !== 'AWS4-HMAC-SHA256' || !fields['X-Amz-Credential'] || !fields['X-Amz-Date']) throw new Error('form-fields');
    const body = new FormData();
    for (const [name,value] of Object.entries(fields)) body.append(name,String(value));
    body.append('file',new Blob([fileBytes],{type:'application/octet-stream'}),'sdk.bin');
    if (diagnostic) stage='submit-transport';
    const response = await fetch(post.url,{method:'POST',body});
    if (diagnostic) stage='submit-response-read';
    return {status:response.status,body:await response.text(),headers:response.headers};
  }
  function errorCode(text) {
    const match = text.match(/<Code>([^<]+)<\/Code>/);
    return match ? match[1] : '';
  }
  async function verify(key, data, diagnostic=false) {
    if (diagnostic) stage='default-head';
    const head = await client.send(new HeadObjectCommand({Bucket:bucket,Key:key}));
    const expiresMatches = value => value.Expires instanceof Date
      ? value.Expires.toISOString() === '2030-10-21T07:28:00.000Z'
      : value.Expires === common.Expires || value.Expires === '2030-10-21T07:28:00.000Z';
    const checkHeaders = value => value.ContentType === common['Content-Type'] &&
        value.ContentEncoding === common['Content-Encoding'] &&
        value.ContentDisposition === common['Content-Disposition'] &&
        value.CacheControl === common['Cache-Control'] &&
        value.ContentLanguage === common['Content-Language'] &&
        expiresMatches(value) &&
        value.Metadata?.owner === common['x-amz-meta-owner'] && value.Metadata?.purpose === common['x-amz-meta-purpose'];
     if (head.ContentLength !== data.length || !checkHeaders(head)) throw new Error('readback');
    const plaintextMD5 = (await import('node:crypto')).createHash('md5').update(data).digest('hex');
    if (head.ETag?.replaceAll('"','').toLowerCase() !== plaintextMD5) throw new Error('etag');
    if (diagnostic) stage='default-get';
    const get = await client.send(new GetObjectCommand({Bucket:bucket,Key:key}));
    const full = Buffer.from(await get.Body.transformToByteArray());
     if (!full.equals(data) || (get.ContentLength !== undefined && get.ContentLength !== data.length) || get.ContentType !== common['Content-Type'] || get.ContentEncoding !== common['Content-Encoding'] || get.ContentDisposition !== common['Content-Disposition'] || get.CacheControl !== common['Cache-Control'] || get.ContentLanguage !== common['Content-Language'] || !expiresMatches(get) || get.Metadata?.owner !== common['x-amz-meta-owner'] || get.Metadata?.purpose !== common['x-amz-meta-purpose'] || get.ETag !== head.ETag) throw new Error('get');
    if (diagnostic) stage='default-range';
    const ranged = await client.send(new GetObjectCommand({Bucket:bucket,Key:key,Range:'bytes=0-127'}));
    const rangeBody = Buffer.from(await ranged.Body.transformToByteArray());
    if (!rangeBody.equals(data.subarray(0,128)) || ranged.ContentLength !== 128 || ranged.ContentType !== common['Content-Type'] || ranged.ContentEncoding !== common['Content-Encoding'] || ranged.ContentDisposition !== common['Content-Disposition'] || ranged.CacheControl !== common['Cache-Control'] || ranged.ContentLanguage !== common['Content-Language'] || !expiresMatches(ranged) || ranged.Metadata?.owner !== common['x-amz-meta-owner'] || ranged.Metadata?.purpose !== common['x-amz-meta-purpose'] || ranged.ContentRange !== 'bytes 0-127/'+data.length || ranged.ETag !== head.ETag) throw new Error('range');
    return head;
  }

  stage='default-post';
  const defaultKey=prefix+'-awsjs-default';
  const defaultPost=await form(defaultKey);
  stage='default-submit';
  let result=await submit(defaultPost,payload,undefined,true);
    stage='default-response';
    if (result.status !== 204) {
      stage = ({400:'default-response-400',403:'default-response-403',500:'default-response-500'})[result.status] || 'default-response-other';
      if (result.status === 400 && errorCode(result.body) === 'MetadataTooLarge') stage='default-response-metadata-too-large';
    }
    if (result.status !== 204 || result.body !== '') throw new Error('status');
    const defaultHead=await verify(defaultKey,payload,true);
    stage='default-post-etag';
    if (result.headers.get('etag') !== defaultHead.ETag) throw new Error('etag');
  console.log('aws-js-post:DEFAULT_OK');

  stage='signed-policy-denial';
  const denied=await form(defaultKey,undefined,true);
  result=await submit(denied,payload,fields => {fields['x-amz-meta-purpose']='awsjs';});
  if (result.status !== 403 || errorCode(result.body) !== 'AccessDenied') throw new Error('policy');
  await verify(defaultKey,payload);
  console.log('aws-js-post:NEGATIVE_OK');

  stage='created-response';
  const createdKey=prefix+'-awsjs-created';
  const createdPost=await form(createdKey,201);
  result=await submit(createdPost,payload);
  if (result.status !== 201) throw new Error('status');
  const responseXML = parsePostResponse(result.body);
  const createdHead=await verify(createdKey,payload);
  if (!responseXML || responseXML.Bucket !== bucket || responseXML.Key !== createdKey) throw new Error('xml');
  assertPostLocation(responseXML.Location, endpoint, endpointPath, bucket, createdKey);
  if (responseXML.ETag !== result.headers.get('etag') || responseXML.ETag !== createdHead.ETag) throw new Error('xml');
  console.log('aws-js-post:CREATED_OK');
  console.log('aws-js-post:MODE_'+(process.env.GH353_SESSION_MODE || 'static').toUpperCase());

  if (process.env.GH353_SESSION_MODE === 'session' && process.env.AWS_SESSION_TOKEN) {
    stage='session-post';
    const sessionKey=prefix+'-awsjs-session';
    const sessionPost=await form(sessionKey);
    assertGeneratedSessionCoverage(sessionPost.fields, process.env.AWS_SESSION_TOKEN);
    if (!sessionPost.fields['X-Amz-Security-Token'] || sessionPost.fields['X-Amz-Security-Token'] !== process.env.AWS_SESSION_TOKEN) throw new Error('session-field');
    result=await submit(sessionPost,payload);
    if (result.status !== 204 || result.body !== '') throw new Error('status');
    const sessionHead=await verify(sessionKey,payload);
    if (result.headers.get('etag') !== sessionHead.ETag) throw new Error('etag');
    console.log('aws-js-post:SESSION_OK');

    stage='wrong-session-token-denial';
    const wrongToken = (await import('node:crypto')).randomBytes(24).toString('base64url');
    result=await submit(sessionPost,payload,fields => {fields['X-Amz-Security-Token']=wrongToken;});
    if (result.status !== 403 || errorCode(result.body) !== 'InvalidToken') throw new Error('token');
    await verify(sessionKey,payload);
    console.log('aws-js-post:SESSION_DENIAL_OK');
    result=await submit(sessionPost,payload,fields => {delete fields['X-Amz-Security-Token'];});
    if (result.status !== 403 || errorCode(result.body) !== 'InvalidToken') throw new Error('missing-token');
    await verify(sessionKey,payload);
    console.log('aws-js-post:SESSION_MISSING_DENIAL_OK');
    console.log('aws-js-post:COMPLETE');
  } else {
    if (process.env.GH353_SESSION_MODE === 'session') throw new Error('session-fixture');
    console.log('aws-js-post:STATIC_OK');
    console.log('aws-js-post:COMPLETE');
  }
  await client.destroy();
} catch {
  console.log('aws-js-post:FAILED:'+stage);
  process.exitCode=1;
}
JSEOF
node /tmp/gh353-post-runner/gh353_aws_js_post.mjs 2>/dev/null || exit 91
`
}

func (r *awsJSPresignedPostRunner) AssertOutput(code int, stdout, stderr string) error {
	required := []string{"aws-js-post:DEFAULT_OK", "aws-js-post:NEGATIVE_OK", "aws-js-post:CREATED_OK", "aws-js-post:MODE_" + strings.ToUpper(r.testMode())}
	if r.sessionExpected {
		required = append(required, "aws-js-post:SESSION_OK", "aws-js-post:SESSION_DENIAL_OK", "aws-js-post:SESSION_MISSING_DENIAL_OK")
	} else {
		required = append(required, "aws-js-post:STATIC_OK")
	}
	required = append(required, "aws-js-post:COMPLETE")
	return assertPostRunnerOutput("aws-js-post", r.testMode(), code, stdout, stderr, required...)
}

func assertPostRunnerOutput(name, mode string, code int, stdout, stderr string, required ...string) error {
	if code != 0 {
		return fmt.Errorf("%s mode=%s failed with container exit status %d stage=%s", name, mode, code, postRunnerFailureStage(name, stdout, stderr))
	}
	if stderr != "" {
		return fmt.Errorf("%s emitted unexpected diagnostic output", name)
	}
	stdout = strings.ReplaceAll(stdout, "\r\n", "\n")
	if strings.HasSuffix(stdout, "\n") {
		stdout = strings.TrimSuffix(stdout, "\n") // normal stdout stream terminator
	}
	lines := strings.Split(stdout, "\n")
	if len(lines) != len(required) {
		return fmt.Errorf("%s emitted unexpected or duplicate stage evidence", name)
	}
	for i, line := range lines {
		if line == "" || line != required[i] {
			return fmt.Errorf("%s emitted unexpected, duplicate, or out-of-order stage evidence", name)
		}
	}
	return nil
}

// Only literal whole-line stage markers are ever returned, never runner output.
func postRunnerFailureStage(name, stdout, stderr string) string {
	stages := map[string][]string{
		"boto3-post":   {"install", "setup", "default-post", "default-submit", "default-response", "default-response-400", "default-response-403", "default-response-500", "default-response-other", "default-response-metadata-too-large", "default-head", "head-length", "head-etag", "head-ctype", "head-encoding", "head-disposition", "head-cache", "head-language", "head-expires", "head-owner", "head-owner-missing", "head-owner-value", "head-purpose", "default-get", "default-range", "default-post-etag", "signed-policy-denial", "created-response", "session-post", "wrong-session-token-denial"},
		"aws-js-post":  {"install", "setup", "default-post", "default-submit", "submit-body", "submit-transport", "submit-response-read", "default-response", "default-response-400", "default-response-403", "default-response-500", "default-response-other", "default-response-metadata-too-large", "default-head", "default-get", "default-range", "default-post-etag", "signed-policy-denial", "created-response", "session-post", "wrong-session-token-denial"},
		"browser-post": {"install", "setup", "browser-page", "browser-allowed-post", "browser-policy-denial", "browser-created-response", "browser-custom-header-preflight", "browser-denied-custom-header", "browser-denied-origin", "browser-session-post", "browser-session-form", "browser-session-coverage", "browser-session-submit", "browser-session-sdk-read", "browser-session-browser-read", "browser-session-token-denial"},
	}
	for _, text := range []string{stdout, stderr} {
		if len(text) > 65536 {
			continue
		}
		for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
			for _, stage := range stages[name] {
				if line == name+":FAILED:"+stage {
					return stage
				}
			}
		}
	}
	return "unavailable"
}

var _ sdkToolRunner = (*boto3PresignedPostRunner)(nil)
var _ sdkToolRunner = (*awsJSPresignedPostRunner)(nil)
var _ safeSDKOutputRunner = (*boto3PresignedPostRunner)(nil)
var _ safeSDKOutputRunner = (*awsJSPresignedPostRunner)(nil)
