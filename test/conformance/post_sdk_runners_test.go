package conformance

import (
	"encoding/base64"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGH353PostSDKRunner_ScriptsAndPins(t *testing.T) {
	for _, tc := range []struct {
		name, image, pin, entrypoint string
		runner                       sdkToolRunner
	}{
		{"boto3", pythonImage, "boto3==" + boto3Version, "generate_presigned_post", &boto3PresignedPostRunner{sessionExpected: true}},
		{"aws-js", awsJSNodeImage, "@aws-sdk/s3-presigned-post@" + awsJSSDKVersion, "createPresignedPost", &awsJSPresignedPostRunner{sessionExpected: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.runner.Image() != tc.image {
				t.Fatalf("image=%q want %q", tc.runner.Image(), tc.image)
			}
			script := tc.runner.Script(sdkTestEnv{})
			for _, value := range []string{tc.pin, tc.entrypoint, "InvalidToken", "ContentRange", "bytes=0-127"} {
				if !strings.Contains(script, value) {
					t.Errorf("script lacks %q", value)
				}
			}
			if !strings.Contains(strings.ToLower(script), "x-amz-security-token") {
				t.Error("session token field missing")
			}
			if tc.name == "aws-js" {
				for _, value := range []string{"fields.Policy", "body.append('file'", "policy.conditions", "assertPostLocation", "ETag"} {
					if !strings.Contains(script, value) {
						t.Errorf("JS script lacks %q", value)
					}
				}
			}
			if strings.Contains(script, "fixture-secret") || strings.Contains(script, "/dist-es/") {
				t.Fatal("script embeds a test secret or imports an unsupported internal SDK entrypoint")
			}
		})
	}
	if pythonImage != "python:3.15-slim" || awsJSSDKVersion != "3.1146.0" || awsJSNodeImage != "node:24-bookworm-slim" {
		t.Fatal("POST runner package or image pin changed")
	}
}

func TestGH353BrowserRunnerScriptsPinsAndStrictOutput(t *testing.T) {
	runner := &browserPostRunner{}
	if runner.Image() != "mcr.microsoft.com/playwright:v1.63.0-noble" || playwrightVersion != "1.63.0" || awsJSSDKVersion != "3.1146.0" {
		t.Fatal("browser/SDK image or package pin changed")
	}
	script := runner.Script(sdkTestEnv{})
	for _, required := range []string{
		"cd /tmp/gh353-browser-runner",
		"npm install --silent --no-save playwright@1.63.0",
		"@aws-sdk/client-s3@3.1146.0",
		"@aws-sdk/s3-presigned-post@3.1146.0",
		"@aws-sdk/s3-request-presigner@3.1146.0",
		"cat > /tmp/gh353-browser-runner/gh353_browser_post.mjs",
		"node /tmp/gh353-browser-runner/gh353_browser_post.mjs",
		"import {chromium} from 'playwright';",
		"page.evaluate(browserSubmitCallback",
		"new FormData()",
		"form.append('file'",
		"new DOMParser()",
		"getSignedUrl(client",
		"mode==='policy-denial'",
		"mode==='unreadable'",
		"mode==='custom-allowed'",
		"mode==='custom-denied'",
		"AccessDenied",
		"browser-post:COMPLETE",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("browser runner lacks %q", required)
		}
	}
	for _, required := range []string{"getSignedUrl", "new HeadObjectCommand", "new GetObjectCommand", "content-range')", "response.headers.get('etag')", "get.headers.get('x-amz-meta-purpose')", "expectedETag", "mode==='session-denial'", "expected.mutation==='wrong-token'", "browser-post:SESSION_DENIALS_OK", "includeBrowserMetadata", "encodeBucket="} {
		if !strings.Contains(script, required) {
			t.Errorf("browser runner lacks required browser-visible assertion %q", required)
		}
	}
	compatSource, err := os.ReadFile("compat_test.go")
	if err != nil {
		t.Fatal(err)
	}
	ledgerSource, err := os.ReadFile("browser_ledger_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(compatSource), "WithRequestObserver") || !strings.Contains(string(ledgerSource), "post.AllowOrigin != expected.allowOrigin") || !strings.Contains(string(ledgerSource), "!strings.EqualFold(preflight.AccessControlRequestMethod, expected.requestedMethod)") {
		t.Fatal("gateway-arrival CORS observer assertions are missing")
	}
	if !strings.Contains(string(ledgerSource), "AuthorizationPresent") || !strings.Contains(string(ledgerSource), "equalHeaderTokenSet") {
		t.Fatal("request observer ledger is missing credential-presence or exact header-token evidence")
	}
	if strings.Contains(string(ledgerSource), "authorizationMatches = post != nil && post.AuthorizationPresent") {
		t.Fatal("browser ledger incorrectly requires Authorization for form-policy signatures")
	}
	if strings.Contains(script, "console.log(JSON") || strings.Contains(script, "console.log(post") || strings.Contains(script, "console.log(token)") || strings.Contains(script, "response.headers.get('access-control-allow-origin')") {
		t.Fatal("browser runner logs credentials or submitted forms")
	}
	if !strings.Contains((&browserPostRunner{sessionExpected: true}).Script(sdkTestEnv{}), "browser-post:SESSION_UPLOAD_OK") {
		t.Fatal("session runner does not emit its required completion stage")
	}
	if strings.Contains(script, "fetch(post.url") == false || strings.Contains(script, "page.evaluate(browserSubmitCallback") == false {
		t.Fatal("browser submit path does not call fetch from page.evaluate")
	}
	static := "browser-post:ALLOWED_POST_OK\nbrowser-post:POLICY_DENIAL_OK\nbrowser-post:CREATED_XML_OK\nbrowser-post:PREFLIGHT_POST_OK\nbrowser-post:DENIED_PREFLIGHT_OK\nbrowser-post:DENIED_ORIGIN_UNREADABLE_OK\nbrowser-post:MODE_STATIC\nbrowser-post:COMPLETE"
	session := strings.Replace(static, "browser-post:MODE_STATIC", "browser-post:SESSION_UPLOAD_OK\nbrowser-post:SESSION_DENIALS_OK\nbrowser-post:MODE_SESSION", 1)
	for _, tc := range []struct {
		runner *browserPostRunner
		stdout string
	}{{runner, static}, {&browserPostRunner{sessionExpected: true}, session}} {
		if err := tc.runner.AssertOutput(0, tc.stdout+"\r\n", ""); err != nil {
			t.Fatalf("valid browser stage output rejected: %v", err)
		}
		if err := tc.runner.AssertOutput(0, tc.stdout+"\nsecret-form-value", ""); err == nil || strings.Contains(err.Error(), "secret-form-value") {
			t.Fatal("browser runner accepted or disclosed unexpected output")
		}
		if err := tc.runner.AssertOutput(0, strings.Replace(tc.stdout, "\n", "\n"+strings.Split(tc.stdout, "\n")[0]+"\n", 1), ""); err == nil {
			t.Fatal("browser runner accepted duplicate stage evidence")
		}
		if err := tc.runner.AssertOutput(0, tc.stdout, "unexpected diagnostic"); err == nil || strings.Contains(err.Error(), "unexpected diagnostic\n") {
			t.Fatal("browser runner accepted or disclosed stderr")
		}
		if err := tc.runner.AssertOutput(1, tc.stdout, ""); err == nil {
			t.Fatal("browser runner accepted a nonzero container status")
		}
	}
}

func TestGH353BrowserSubmitUsesBrowserFilteredHeaders(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js unavailable; callback fixture not run")
	}
	script := (&browserPostRunner{}).Script(sdkTestEnv{})
	start := strings.Index(script, "const browserSubmitCallback = ")
	if start < 0 {
		t.Fatal("browser callback source not found")
	}
	end := strings.Index(script[start:], "\n};\nasync function browserSubmit")
	if end < 0 {
		t.Fatal("browser callback end not found")
	}
	callback := script[start : start+end+2]
	fixture := `
globalThis.responseMode='success';
globalThis.fetch=async()=>({status:responseMode==='created'?201:responseMode==='denied'?403:204,
  headers:{get(name){return name.toLowerCase()==='etag' && responseMode!=='missing-etag' ? '"plain-md5"' : null;}},
  async text(){return responseMode==='created'?'<PostResponse xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Bucket>b</Bucket><Key>k</Key><ETag>"plain-md5"</ETag><Location>http://gateway/b/k</Location></PostResponse>':responseMode==='denied'?'<Error><Code>AccessDenied</Code></Error>':'';}});
globalThis.DOMParser=class { parseFromString(body){
  const value=name=>body.match(new RegExp('<'+name+'>(.*?)</'+name+'>'))?.[1];
  const ns='http://s3.amazonaws.com/doc/2006-03-01/';
  const root=body.match(/^<([A-Za-z]+)/)?.[1]||'';
  const malformed=body==='<' || body==='<PostResponse>';
  return {documentElement:{localName:root,namespaceURI:root==='PostResponse'?ns:null},getElementsByTagName(name){if(name==='parsererror')return malformed?[{}]:[];const found=value(name);return found===undefined?[]:[{textContent:found}];},getElementsByTagNameNS(_ns,name){const found=value(name);return found===undefined?[]:[{textContent:found}];}};
}};
const post={url:'http://gateway/upload',fields:{Policy:'policy'}};
const bytes=[1,2,3];
const expected={bucket:'b',key:'k',endpoint:'http://gateway',endpointPath:'',etag:'"plain-md5"'};
const success=await browserSubmitCallback({post,bytes,mode:'default',expected});
if(!success.ok || success.etag!==expected.etag) process.exit(1);
if((await fetch('http://gateway')).headers.get('access-control-allow-origin')!==null) process.exit(2);
responseMode='created';
const created=await browserSubmitCallback({post,bytes,mode:'created',expected});
if(!created.ok || created.etag!==expected.etag) process.exit(3);
responseMode='denied';
const denied=await browserSubmitCallback({post,bytes,mode:'policy-denial',expected});
if(!denied.ok) process.exit(4);
responseMode='missing-etag';
let rejected=false;
try { await browserSubmitCallback({post,bytes,mode:'default',expected}); } catch(error) { rejected=error.message==='browser-assertion-failed'; }
if(!rejected) process.exit(5);
responseMode='malformed-created';
globalThis.fetch=async()=>({status:201,headers:{get(name){return name.toLowerCase()==='etag'?'"plain-md5"':null;}},async text(){return '<PostResponse>';}});
rejected=false;
try { await browserSubmitCallback({post,bytes,mode:'created',expected}); } catch(error) { rejected=error.message==='browser-assertion-failed'; }
if(!rejected) process.exit(6);
`
	entry := filepath.Join(t.TempDir(), "browser-callback.mjs")
	if err := os.WriteFile(entry, []byte(callback+fixture), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(node, entry).CombinedOutput()
	if err != nil {
		t.Fatalf("actual browser callback rejected valid filtered responses or accepted missing ETag: %v: %s", err, strings.TrimSpace(string(output)))
	}
}

func TestGH353BrowserEnvironmentCarriesOnlyConfiguredOrigins(t *testing.T) {
	runner := &browserPostRunner{}
	env := sdkContainerEnvironment(sdkTestEnv{
		Endpoint: "http://gateway.invalid", AccessKey: "access-fixture", SecretKey: "secret-fixture",
		BrowserPageURL: "http://127.0.0.1:1234", BrowserDeniedPageURL: "http://127.0.0.1:1235",
	}, runner)
	if env["BROWSER_PAGE_URL"] != "http://127.0.0.1:1234" || env["BROWSER_DENIED_PAGE_URL"] != "http://127.0.0.1:1235" || env["AWS_SECRET_ACCESS_KEY"] != "secret-fixture" {
		t.Fatal("browser test environment omitted its loopback origin or SDK credentials")
	}
	env = sdkContainerEnvironment(sdkTestEnv{BrowserStageURL: "http://127.0.0.1:1234/stage"}, &browserPostRunner{})
	if env["BROWSER_STAGE_URL"] != "http://127.0.0.1:1234/stage" {
		t.Fatal("browser environment omitted safe test-stage control endpoint")
	}
}

func TestGH353BrowserCORSFixtureIsGatewayManagedAndNarrow(t *testing.T) {
	pageOrigin := "http://127.0.0.1:43127"
	cors := browserCORSConfiguration(pageOrigin)
	for _, expected := range []string{
		"<AllowedOrigin>" + pageOrigin + "</AllowedOrigin>",
		"<AllowedMethod>POST</AllowedMethod>",
		"<AllowedMethod>GET</AllowedMethod>",
		"<AllowedMethod>HEAD</AllowedMethod>",
		"<AllowedHeader>content-type</AllowedHeader>",
		"<AllowedHeader>range</AllowedHeader>",
		"<AllowedHeader>x-gh353-allowed</AllowedHeader>",
		"<ExposeHeader>ETag</ExposeHeader>",
		"<ExposeHeader>Content-Range</ExposeHeader>",
		"<ExposeHeader>x-amz-meta-purpose</ExposeHeader>",
		"<ExposeHeader>x-amz-meta-owner</ExposeHeader>",
		"<ExposeHeader>x-amz-meta-browser</ExposeHeader>",
		"<ExposeHeader>x-amz-version-id</ExposeHeader>",
	} {
		if !strings.Contains(cors, expected) {
			t.Errorf("gateway CORS fixture lacks %q", expected)
		}
	}
	if strings.Contains(cors, "*") || strings.Contains(cors, "x-gh353-denied") {
		t.Fatal("gateway CORS fixture is wildcard or admits the deliberately denied header")
	}

	compatSource, err := os.ReadFile("compat_test.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"harness.WithValkeyAddr(vk.Addr)", "harness.WithCORSMode(\"gateway\")", "?cors", "signV4Headers(t, management, manager.AccessKey, manager.SecretKey", "postGateway(t, inst, credential", "http.MethodGet, corsURL", "http.MethodPut, corsURL", "oldXML", "http.MethodDelete"} {
		if !strings.Contains(string(compatSource), required) {
			t.Errorf("browser CORS fixture wiring lacks %q", required)
		}
	}
	runnerSource, err := os.ReadFile("post_browser_runner.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(runnerSource), "func browserCORSConfiguration") || !strings.Contains(string(runnerSource), "<ExposeHeader>ETag</ExposeHeader>") {
		t.Fatal("exact gateway CORS rule and exposed ETag must be wired in the browser fixture")
	}
	suiteSource, err := os.ReadFile("suite_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(suiteSource), `{"Compat_BrowserPost", 0, testCompatBrowserPost}`) {
		t.Fatal("browser CORS scenario is missing its capability-0 registration")
	}
}

func TestGH353PostSDKTokenEnvironment(t *testing.T) {
	base := sdkTestEnv{AccessKey: "access", SecretKey: "secret", Region: "us-east-1", Endpoint: "http://gateway", Bucket: "bucket", Key: "key"}
	env := sdkContainerEnvironment(base, &boto3PresignedPostRunner{sessionExpected: true})
	if _, ok := env["AWS_SESSION_TOKEN"]; ok || env["GH353_SESSION_MODE"] != "session" {
		t.Fatal("empty session token handling is incorrect")
	}
	base.SessionToken = "gateway-session-token"
	base.BackendEndpoint = "http://backend"
	env = sdkContainerEnvironment(base, &boto3PresignedPostRunner{})
	if env["AWS_SESSION_TOKEN"] != base.SessionToken || env["BACKEND_ENDPOINT"] != base.BackendEndpoint || env["AWS_SECRET_ACCESS_KEY"] != base.SecretKey {
		t.Fatal("optional SDK environment values were not propagated")
	}
}

func TestGH353PostSDKAssertOutputStrict(t *testing.T) {
	staticBoto := "boto3-post:DEFAULT_OK\nboto3-post:NEGATIVE_OK\nboto3-post:CREATED_OK\nboto3-post:MODE_STATIC\nboto3-post:STATIC_OK\nboto3-post:COMPLETE"
	staticJS := "aws-js-post:DEFAULT_OK\naws-js-post:NEGATIVE_OK\naws-js-post:CREATED_OK\naws-js-post:MODE_STATIC\naws-js-post:STATIC_OK\naws-js-post:COMPLETE"
	sessionBoto := "boto3-post:DEFAULT_OK\nboto3-post:NEGATIVE_OK\nboto3-post:CREATED_OK\nboto3-post:MODE_SESSION\nboto3-post:SESSION_OK\nboto3-post:SESSION_DENIAL_OK\nboto3-post:SESSION_MISSING_DENIAL_OK\nboto3-post:COMPLETE"
	sessionJS := "aws-js-post:DEFAULT_OK\naws-js-post:NEGATIVE_OK\naws-js-post:CREATED_OK\naws-js-post:MODE_SESSION\naws-js-post:SESSION_OK\naws-js-post:SESSION_DENIAL_OK\naws-js-post:SESSION_MISSING_DENIAL_OK\naws-js-post:COMPLETE"
	for _, tc := range []struct {
		name   string
		assert func(int, string, string) error
		valid  string
	}{
		{"boto-static", (&boto3PresignedPostRunner{}).AssertOutput, staticBoto},
		{"js-static", (&awsJSPresignedPostRunner{}).AssertOutput, staticJS},
		{"boto-session", (&boto3PresignedPostRunner{sessionExpected: true}).AssertOutput, sessionBoto},
		{"js-session", (&awsJSPresignedPostRunner{sessionExpected: true}).AssertOutput, sessionJS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, output := range []string{tc.valid + "\n", strings.ReplaceAll(tc.valid, "\n", "\r\n") + "\r\n"} {
				if err := tc.assert(0, output, ""); err != nil {
					t.Fatalf("valid SDK output rejected: %v", err)
				}
			}
			for label, output := range map[string]string{
				"duplicate": strings.Replace(tc.valid, "\n", "\n"+strings.Split(tc.valid, "\n")[0]+"\n", 1),
				"unknown":   tc.valid + "\nunknown-stage\n",
				"blank":     tc.valid + "\n\n",
			} {
				if err := tc.assert(0, output, ""); err == nil {
					t.Errorf("accepted %s output", label)
				}
			}
			if err := tc.assert(0, tc.valid+"\nfixture-secret-from-stdout", ""); err == nil || strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("unsafe stdout accepted or echoed")
			}
			if err := tc.assert(0, tc.valid, "fixture-secret-from-stderr"); err == nil || strings.Contains(err.Error(), "fixture-secret") {
				t.Fatal("unsafe stderr accepted or echoed")
			}
			if err := tc.assert(1, tc.valid, ""); err == nil {
				t.Fatal("nonzero runner exit accepted")
			}
		})
	}
}

func TestGH353PostRunnerFailureMarkersRedacted(t *testing.T) {
	for _, tc := range []struct {
		name, marker, mode string
		assert             func(int, string, string) error
	}{
		{"boto", "boto3-post:FAILED:default-post", "static", (&boto3PresignedPostRunner{}).AssertOutput},
		{"js", "aws-js-post:FAILED:session-post", "session", (&awsJSPresignedPostRunner{sessionExpected: true}).AssertOutput},
		{"browser", "browser-post:FAILED:browser-session-token-denial", "session", (&browserPostRunner{sessionExpected: true}).AssertOutput},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.assert(91, "private-canary\n"+tc.marker+"\n", "other-secret")
			if err == nil || !strings.Contains(err.Error(), "stage="+strings.Split(tc.marker, ":")[2]) || !strings.Contains(err.Error(), "mode="+tc.mode) || strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), "other-secret") {
				t.Fatal("fixed marker not propagated safely")
			}
			err = tc.assert(91, tc.marker+"-private-canary\n", "private-canary")
			if err == nil || !strings.Contains(err.Error(), "stage=unavailable") || strings.Contains(err.Error(), "canary") {
				t.Fatal("unallowlisted output leaked")
			}
		})
	}
}

func TestGH353PostFineFailureCheckpoints(t *testing.T) {
	for _, tc := range []struct {
		name   string
		runner sdkToolRunner
		stages []string
	}{
		{"boto3-post", &boto3PresignedPostRunner{}, []string{"default-post", "default-submit", "default-response", "default-response-400", "default-response-403", "default-response-500", "default-response-other", "default-response-metadata-too-large", "default-head", "head-length", "head-etag", "head-ctype", "head-encoding", "head-disposition", "head-cache", "head-language", "head-expires", "head-owner", "head-owner-missing", "head-owner-value", "head-purpose", "default-get", "default-range", "default-post-etag"}},
		{"aws-js-post", &awsJSPresignedPostRunner{}, []string{"default-post", "default-submit", "submit-body", "submit-transport", "submit-response-read", "default-response", "default-response-400", "default-response-403", "default-response-500", "default-response-other", "default-response-metadata-too-large", "default-head", "default-get", "default-range", "default-post-etag"}},
		{"browser-post", &browserPostRunner{sessionExpected: true}, []string{"browser-session-post", "browser-session-form", "browser-session-coverage", "browser-session-submit", "browser-session-sdk-read", "browser-session-browser-read"}},
	} {
		script := tc.runner.Script(sdkTestEnv{})
		for _, stage := range tc.stages {
			if !strings.Contains(script, "'"+stage+"'") {
				t.Fatalf("checkpoint missing: %s", stage)
			}
			marker := tc.name + ":FAILED:" + stage
			err := tc.runner.AssertOutput(91, "private-canary\n"+marker+"\n", "secret-canary")
			if err == nil || !strings.Contains(err.Error(), "stage="+stage) || strings.Contains(err.Error(), "canary") {
				t.Fatal("checkpoint not safely propagated")
			}
			err = tc.runner.AssertOutput(91, marker+"-private-canary\n", "")
			if err == nil || !strings.Contains(err.Error(), "stage=unavailable") || strings.Contains(err.Error(), "canary") {
				t.Fatal("partial checkpoint accepted")
			}
		}
		if got := postRunnerFailureStage(tc.name, strings.Repeat("x", 65537)+"\n"+tc.name+":FAILED:"+tc.stages[0], ""); got != "unavailable" {
			t.Fatal("oversized output accepted")
		}
	}
}

func TestGH353AWSJSSubmitXMLAndLocationHelpers(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js unavailable; builtin helper fixture not run")
	}
	script := (&awsJSPresignedPostRunner{}).Script(sdkTestEnv{})
	extract := func(begin, end string) string {
		start := strings.Index(script, begin)
		if start < 0 {
			t.Fatalf("runner helper not found: %s", begin)
		}
		finish := strings.Index(script[start:], end)
		if finish < 0 {
			t.Fatalf("runner helper boundary not found: %s", end)
		}
		return script[start : start+finish]
	}
	xmlHelper := extract("function decodeXMLText(", "\ntry {\n")
	locationHelper := extract("function assertPostLocation(", "\ntry {\n")
	submitStart := strings.Index(script, "  async function submit(")
	if submitStart < 0 {
		t.Fatal("runner submit helper not found")
	}
	submitEnd := strings.Index(script[submitStart:], "  function errorCode(")
	if submitEnd < 0 {
		t.Fatal("runner submit helper boundary not found")
	}
	submitHelper := script[submitStart : submitStart+submitEnd]

	type response struct {
		XMLName                     xml.Name `xml:"PostResponse"`
		XMLNS                       string   `xml:"xmlns,attr"`
		Location, Bucket, Key, ETag string
	}
	key := "café/./../%2F/+/&/last/"
	location := "http://gateway.example/prefix/bucket/caf%C3%A9/%2E/%2E%2E/%252F/%2B/%26/last/"
	body, err := xml.Marshal(response{XMLNS: "http://s3.amazonaws.com/doc/2006-03-01/", Location: location, Bucket: "bucket", Key: key, ETag: `"a&b"`})
	if err != nil {
		t.Fatal(err)
	}
	fixture := base64.StdEncoding.EncodeToString(append([]byte(xml.Header), body...))
	fixtureEnv := []string{
		"GH353_XML=" + fixture,
		"GH353_XML_HELPER=" + base64.StdEncoding.EncodeToString([]byte(xmlHelper)),
		"GH353_LOCATION_HELPER=" + base64.StdEncoding.EncodeToString([]byte(locationHelper)),
		"GH353_SUBMIT_HELPER=" + base64.StdEncoding.EncodeToString([]byte(submitHelper)),
	}
	module := `const xml = Buffer.from(process.env.GH353_XML,'base64').toString();
const parse = new Function(Buffer.from(process.env.GH353_XML_HELPER,'base64').toString()+'; return parsePostResponse;')();
const response = parse(xml);
if(response.ETag !== '"a&b"' || response.Key !== 'café/./../%2F/+/&/last/' || response.Location !== 'http://gateway.example/prefix/bucket/caf%C3%A9/%2E/%2E%2E/%252F/%2B/%26/last/') throw Error('Go XML fixture mismatch');
const checkLocation = new Function('URL',Buffer.from(process.env.GH353_LOCATION_HELPER,'base64').toString()+'; return assertPostLocation;')(URL);
checkLocation(response.Location,'http://gateway.example/prefix','/prefix','bucket',response.Key);
for(const bad of ['http://gateway.example.evil/prefix/bucket/key','https://gateway.example/prefix/bucket/key','http://gateway.example/prefix/bucket/key?x=1','http://gateway.example/prefix/bucket/key#f','http://gateway.example/prefix/bucket/changed','http://gateway.example/prefix/bucket/%2E%2E/key']) { let failed=false; try {checkLocation(bad,'http://gateway.example/prefix','/prefix','bucket',response.Key)} catch {failed=true} if(!failed) throw Error('bad location accepted') }
let appended=[]; globalThis.FormData=class {append(...args){appended.push(args)}}; globalThis.Blob=class {constructor(parts,options){this.parts=parts;this.type=options.type}};
const submitSource=Buffer.from(process.env.GH353_SUBMIT_HELPER,'base64').toString();
const submit=new Function('fetch',submitSource+'; return submit;')(async()=>({status:204,headers:new Map([['etag','"a&b"']]),text:async()=>''}));
const fields={Policy:'policy','X-Amz-Signature':'sig','X-Amz-Algorithm':'AWS4-HMAC-SHA256','X-Amz-Credential':'cred','X-Amz-Date':'date'};
submit({url:'http://gateway.example/',fields},Buffer.from('payload')).then(r=>{if(r.status!==204||r.headers.get('etag')!=='"a&b"'||appended.at(-1)[0]!=='file'||appended.at(-1)[2]!=='sdk.bin')throw Error('submit/file order mismatch')}).catch(e=>{console.error(e.message);process.exitCode=1});
`
	path := filepath.Join(t.TempDir(), "sdk-path-fixture.mjs")
	if err := os.WriteFile(path, []byte(module), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, path)
	cmd.Env = append(os.Environ(), fixtureEnv...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper fixture failed: %v: %s", err, strings.TrimSpace(string(output)))
	}
}

func TestGH353AWSJSBareImportsResolveFromRunnerDirectory(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js unavailable; module fixture not run")
	}
	script := (&awsJSPresignedPostRunner{}).Script(sdkTestEnv{})
	for _, expected := range []string{"cd /tmp/gh353-post-runner", "cat > /tmp/gh353-post-runner/gh353_aws_js_post.mjs", "import {S3Client, HeadObjectCommand, GetObjectCommand} from '@aws-sdk/client-s3';", "import {createPresignedPost} from '@aws-sdk/s3-presigned-post';", "node /tmp/gh353-post-runner/gh353_aws_js_post.mjs"} {
		if !strings.Contains(script, expected) {
			t.Errorf("runner bootstrap lacks %q", expected)
		}
	}
	if strings.Contains(script, "/dist-es/") {
		t.Fatal("runner imports unsupported internal SDK build")
	}
	var imports []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "import {S3Client,") || strings.HasPrefix(line, "import {createPresignedPost}") {
			imports = append(imports, line)
		}
	}
	root := t.TempDir()
	for _, pkg := range []struct{ name, exports string }{{"@aws-sdk/client-s3", "exports.S3Client='client';exports.HeadObjectCommand='head';exports.GetObjectCommand='get';"}, {"@aws-sdk/s3-presigned-post", "exports.createPresignedPost='post';"}} {
		dir := filepath.Join(root, "node_modules", filepath.FromSlash(pkg.name))
		if err := os.MkdirAll(filepath.Join(dir, "dist-cjs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"main":"dist-cjs/index.js","module":"dist-es/index.js"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "dist-cjs/index.js"), []byte(pkg.exports), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "dist-es"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "dist-es/index.js"), []byte("throw Error('wrong module field')"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	module := strings.Join(imports, "\n") + "\nif(S3Client!=='client'||HeadObjectCommand!=='head'||GetObjectCommand!=='get'||createPresignedPost!=='post')process.exit(1);\n"
	entry := filepath.Join(root, "gh353_aws_js_post.mjs")
	if err := os.WriteFile(entry, []byte(module), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(node, entry).CombinedOutput()
	if err != nil {
		t.Fatalf("package main resolution failed: %v: %s", err, strings.TrimSpace(string(output)))
	}
}

func TestGH353BrowserBareImportsResolveFromInstallDirectory(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js unavailable; browser module fixture not run")
	}
	script := (&browserPostRunner{}).Script(sdkTestEnv{})
	var imports []string
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(line, "import {") && strings.Contains(line, " from '") {
			imports = append(imports, line)
		}
	}
	if len(imports) != 5 {
		t.Fatalf("got %d bare browser module imports, want 5", len(imports))
	}
	root := t.TempDir()
	fixtures := []struct {
		name, exports string
	}{
		{"@aws-sdk/client-s3", "exports.S3Client='client';exports.HeadObjectCommand='head';exports.GetObjectCommand='get';"},
		{"@aws-sdk/s3-presigned-post", "exports.createPresignedPost='post';"},
		{"@aws-sdk/s3-request-presigner", "exports.getSignedUrl='sign';"},
		{"playwright", "exports.chromium='chromium';"},
	}
	for _, fixture := range fixtures {
		dir := filepath.Join(root, "node_modules", filepath.FromSlash(fixture.name))
		if err := os.MkdirAll(filepath.Join(dir, "dist-cjs"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"main":"dist-cjs/index.js","module":"dist-es/index.js"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "dist-cjs/index.js"), []byte(fixture.exports), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "dist-es"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "dist-es/index.js"), []byte("throw Error('unsupported module field')"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	module := strings.Join(imports, "\n") + `
if(typeof S3Client!=='function' && S3Client!=='client') process.exit(1);
if(typeof createPresignedPost!=='function' && createPresignedPost!=='post') process.exit(1);
if(typeof getSignedUrl!=='function' && getSignedUrl!=='sign') process.exit(1);
if(typeof chromium!=='function' && chromium!=='chromium') process.exit(1);
`
	entry := filepath.Join(root, "gh353_browser_post.mjs")
	if err := os.WriteFile(entry, []byte(module), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(node, entry).CombinedOutput()
	if err != nil {
		t.Fatalf("browser bare package entrypoint resolution failed: %v: %s", err, strings.TrimSpace(string(output)))
	}
}
