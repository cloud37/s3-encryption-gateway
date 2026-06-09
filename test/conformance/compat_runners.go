package conformance

import (
	"fmt"
	"strings"
)

// ─── AWS SDK Go v2 runner (in-process, no Docker) ───────────────────────────

// awsGoV2Runner exercises the AWS SDK Go v2 directly in the test process.
// No Docker container is needed because the SDK is already a dependency.
type awsGoV2Runner struct{}

func (r *awsGoV2Runner) Name() string  { return "aws-sdk-go-v2" }
func (r *awsGoV2Runner) Image() string { return "" } // in-process
func (r *awsGoV2Runner) Script(env sdkTestEnv) string { return "" }
func (r *awsGoV2Runner) AssertOutput(code int, out, err string) error { return nil }

// ─── boto3 runner (Python container) ────────────────────────────────────────

type boto3Runner struct{}

func (r *boto3Runner) Name() string  { return "boto3" }
func (r *boto3Runner) Image() string { return "python:3.13-slim" }

func (r *boto3Runner) Script(env sdkTestEnv) string {
	return "set -e\npip install -q boto3==1.35.0\n" +
		"cat > /tmp/test_boto3.py << 'PYEOF'\n" +
		"import os, boto3\n" +
		"s3 = boto3.client('s3',\n" +
		"    endpoint_url=os.environ['GATEWAY_ENDPOINT'],\n" +
		"    aws_access_key_id=os.environ['AWS_ACCESS_KEY_ID'],\n" +
		"    aws_secret_access_key=os.environ['AWS_SECRET_ACCESS_KEY'],\n" +
		"    region_name='us-east-1'\n" +
		")\n" +
		"bucket = os.environ['GATEWAY_BUCKET']\n" +
		"key    = os.environ['GATEWAY_KEY']\n" +
		"s3.put_object(Bucket=bucket, Key=key, Body=b'compat-test-data')\n" +
		"h = s3.head_object(Bucket=bucket, Key=key)\n" +
		"assert h['ContentLength'] == len(b'compat-test-data'), 'ContentLength mismatch'\n" +
		"obj = s3.get_object(Bucket=bucket, Key=key)\n" +
		"assert obj['Body'].read() == b'compat-test-data', 'Body mismatch'\n" +
		"r = s3.list_objects_v2(Bucket=bucket, Prefix=key)\n" +
		"assert any(o['Key'] == key for o in r.get('Contents', [])), 'Key not found in list'\n" +
		"s3.delete_object(Bucket=bucket, Key=key)\n" +
		"print('boto3:OK')\n" +
		"PYEOF\n" +
		"python3 /tmp/test_boto3.py"
}

func (r *boto3Runner) AssertOutput(code int, out, _ string) error {
	if code != 0 {
		return fmt.Errorf("boto3 exited %d", code)
	}
	if !strings.Contains(out, "boto3:OK") {
		return fmt.Errorf("boto3: expected OK marker in stdout")
	}
	return nil
}

// ─── awscli runner (amazon/aws-cli container) ───────────────────────────────

type awscliRunner struct{}

func (r *awscliRunner) Name() string  { return "awscli" }
func (r *awscliRunner) Image() string { return "amazon/aws-cli:2.22.0" }

func (r *awscliRunner) Script(env sdkTestEnv) string {
	return fmt.Sprintf("set -e\n"+
		"# PutObject via s3 cp\n"+
		"echo 'compat-test-data' > /tmp/testfile\n"+
		"aws s3 cp /tmp/testfile s3://%[1]s/%[2]s --endpoint-url \"$GATEWAY_ENDPOINT\"\n"+
		"# HeadObject via s3api\n"+
		"aws s3api head-object --bucket %[1]s --key %[2]s --endpoint-url \"$GATEWAY_ENDPOINT\" > /dev/null\n"+
		"# GetObject via s3 cp\n"+
		"aws s3 cp s3://%[1]s/%[2]s /tmp/testfile-dl --endpoint-url \"$GATEWAY_ENDPOINT\"\n"+
		"diff /tmp/testfile /tmp/testfile-dl || { echo 'FATAL: downloaded file differs'; exit 1; }\n"+
		"# ListObjectsV2 via s3 ls\n"+
		"aws s3 ls s3://%[1]s/ --recursive --endpoint-url \"$GATEWAY_ENDPOINT\" | grep -q %[2]s || { echo 'FATAL: key not found in list'; exit 1; }\n"+
		"# DeleteObject via s3 rm\n"+
		"aws s3 rm s3://%[1]s/%[2]s --endpoint-url \"$GATEWAY_ENDPOINT\"\n"+
		"echo 'awscli:OK'\n",
		env.Bucket, env.Key)
}

func (r *awscliRunner) AssertOutput(code int, out, _ string) error {
	if code != 0 {
		return fmt.Errorf("awscli exited %d", code)
	}
	if !strings.Contains(out, "awscli:OK") {
		return fmt.Errorf("awscli: expected OK marker in stdout")
	}
	return nil
}

// ─── s5cmd runner (peak/s5cmd container) ────────────────────────────────────

type s5cmdRunner struct{}

func (r *s5cmdRunner) Name() string  { return "s5cmd" }
func (r *s5cmdRunner) Image() string { return "peakcom/s5cmd:v2.3.0" }

func (r *s5cmdRunner) Script(env sdkTestEnv) string {
	return fmt.Sprintf("set -e\n"+
		"echo 'compat-test-data' > /tmp/testfile\n"+
		"# PutObject via cp\n"+
		"/s5cmd --endpoint-url \"$GATEWAY_ENDPOINT\" cp /tmp/testfile s3://%[1]s/%[2]s\n"+
		"# GetObject via cp\n"+
		"/s5cmd --endpoint-url \"$GATEWAY_ENDPOINT\" cp s3://%[1]s/%[2]s /tmp/testfile-dl\n"+
		"diff /tmp/testfile /tmp/testfile-dl || { echo 'FATAL: downloaded file differs'; exit 1; }\n"+
		"# ListObjects via ls — s5cmd uses delimiter \"/\" by default, so\n"+
		"# ls with the full key path is used to confirm presence.\n"+
		"/s5cmd --endpoint-url \"$GATEWAY_ENDPOINT\" ls \"s3://%[1]s/%[2]s\" || { echo 'FATAL: key not found'; exit 1; }\n"+
		"# DeleteObject via rm\n"+
		"/s5cmd --endpoint-url \"$GATEWAY_ENDPOINT\" rm s3://%[1]s/%[2]s\n"+
		"echo 's5cmd:OK'\n",
		env.Bucket, env.Key)
}

func (r *s5cmdRunner) AssertOutput(code int, out, _ string) error {
	if code != 0 {
		return fmt.Errorf("s5cmd exited %d", code)
	}
	if !strings.Contains(out, "s5cmd:OK") {
		return fmt.Errorf("s5cmd: expected OK marker in stdout")
	}
	return nil
}

// ─── rclone runner (rclone/rclone container) ────────────────────────────────

type rcloneRunner struct{}

func (r *rcloneRunner) Name() string  { return "rclone" }
func (r *rcloneRunner) Image() string { return "rclone/rclone:1.68" }

func (r *rcloneRunner) Script(env sdkTestEnv) string {
	// Use --s3-* flags directly with :s3: remote syntax instead of
	// RCLONE_CONFIG_* env vars. This avoids portability issues with
	// the multi-line config env-var approach (GAP-COMPAT1-2).
	//
	// The shell function `r()` factors out the repeated flag set.
	return fmt.Sprintf("set -e\n"+
		"echo 'compat-test-data' > /tmp/testfile\n"+
		"r() { rclone --s3-provider=Minio --s3-endpoint=\"$GATEWAY_ENDPOINT\" --s3-env-auth=false --s3-access-key-id=\"$AWS_ACCESS_KEY_ID\" --s3-secret-access-key=\"$AWS_SECRET_ACCESS_KEY\" --s3-region=us-east-1 --s3-no-check-bucket=true --s3-copy-cutoff=1 \"$@\"; }\n"+
		"# PutObject via copyto\n"+
		"r copyto /tmp/testfile :s3:%[1]s/%[2]s\n"+
		"# GetObject via copyto (download)\n"+
		"r copyto :s3:%[1]s/%[2]s /tmp/testfile-dl\n"+
		"diff /tmp/testfile /tmp/testfile-dl || { echo 'FATAL: downloaded file differs'; exit 1; }\n"+
		"# ListObjects via ls\n"+
		"r ls :s3:%[1]s/ | grep -q %[2]s || { echo 'FATAL: key not found'; exit 1; }\n"+
		"# DeleteObject via deletefile\n"+
		"r deletefile :s3:%[1]s/%[2]s\n"+
		"echo 'rclone:OK'\n",
		env.Bucket, env.Key)
}

func (r *rcloneRunner) AssertOutput(code int, out, _ string) error {
	if code != 0 {
		return fmt.Errorf("rclone exited %d", code)
	}
	if !strings.Contains(out, "rclone:OK") {
		return fmt.Errorf("rclone: expected OK marker in stdout")
	}
	return nil
}

// ─── minio-py runner (Python container) ─────────────────────────────────────

type minioPyRunner struct{}

func (r *minioPyRunner) Name() string  { return "minio-py" }
func (r *minioPyRunner) Image() string { return "python:3.13-slim" }

func (r *minioPyRunner) Script(env sdkTestEnv) string {
	return "set -e\npip install -q minio==7.2.0\n" +
		"cat > /tmp/test_minio.py << 'PYEOF'\n" +
		"import os, io\n" +
		"from minio import Minio\n" +
		"endpoint = os.environ['GATEWAY_ENDPOINT'].replace('http://', '').replace('https://', '')\n" +
		"client = Minio(\n" +
		"    endpoint,\n" +
		"    access_key=os.environ['AWS_ACCESS_KEY_ID'],\n" +
		"    secret_key=os.environ['AWS_SECRET_ACCESS_KEY'],\n" +
		"    secure=False,\n" +
		"    region='us-east-1'\n" +
		")\n" +
		"bucket = os.environ['GATEWAY_BUCKET']\n" +
		"key    = os.environ['GATEWAY_KEY']\n" +
		"data = b'compat-test-data'\n" +
		"client.put_object(bucket, key, io.BytesIO(data), len(data))\n" +
		"stat = client.stat_object(bucket, key)\n" +
		"assert stat.size == len(data), 'Size mismatch'\n" +
		"resp = client.get_object(bucket, key)\n" +
		"got = resp.read()\n" +
		"assert got == data, 'Body mismatch'\n" +
		"resp.close()\n" +
		"objects = client.list_objects(bucket, prefix=key)\n" +
		"assert any(o.object_name == key for o in objects), 'Key not found in list'\n" +
		"client.remove_object(bucket, key)\n" +
		"print('minio-py:OK')\n" +
		"PYEOF\n" +
		"python3 /tmp/test_minio.py"
}

func (r *minioPyRunner) AssertOutput(code int, out, _ string) error {
	if code != 0 {
		return fmt.Errorf("minio-py exited %d: %s", code, out)
	}
	if !strings.Contains(out, "minio-py:OK") {
		return fmt.Errorf("minio-py: expected OK marker in stdout")
	}
	return nil
}
