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

// ─── rcloneSyncCheckRunner ────────────────────────────────────────────────────
//
// rcloneSyncCheckRunner reproduces the exact failure reported in issues #204
// and #207: rclone sync followed by rclone check --size-only against an
// encrypted gateway whose ListObjects returns ciphertext sizes.
//
// The test:
//  1. Creates 15 local files of varying sizes (> 10 so the listing is handled
//     by the general Valkey cache-lookup path, not the Docker Distribution
//     maxKeys<=10 fast path that issues per-object HEAD calls regardless).
//  2. rclone sync → gateway (PUT via gateway, warms Valkey size cache).
//  3. rclone check --size-only --one-way: compares local sizes against the
//     gateway listing. With a warm cache the gateway returns plaintext sizes;
//     without the fix it returns ciphertext sizes and rclone reports
//     "sizes differ" for every object.
//  4. rclone lsl (listing with sizes visible): logged for diagnostics.
//
// The runner requires a gateway started with WithValkeyAddr so the size cache
// is active (CapSizeTranslation).
//
// ⚠  The check sub-command exits non-zero if any size mismatches are found.
// That is exactly what we assert: if the fix is working, exit 0.

type rcloneSyncCheckRunner struct{}

func (r *rcloneSyncCheckRunner) Name() string  { return "rclone-sync-check" }
func (r *rcloneSyncCheckRunner) Image() string { return "rclone/rclone:1.68" }

func (r *rcloneSyncCheckRunner) Script(env sdkTestEnv) string {
	// env.Key is used as the remote prefix so parallel tests don't collide.
	//
	// 15 files are created — deliberately more than the maxKeys=10 threshold
	// used by the Docker Distribution fast-path in handleListObjects. Below
	// that threshold the gateway issues per-object HEAD calls regardless of
	// the cache, so the test would pass even without the Valkey fix. Above it,
	// the gateway must resolve sizes from the cache (or return ciphertext sizes
	// if the cache is misconfigured).
	//
	// File sizes are chosen to cover distinct AEAD-overhead cases:
	//   files 00-09:  varying sub-chunk sizes (100 B … 9 900 B, step 1 000)
	//   file     10:  exactly 65 536 B (one full 64 KiB chunk boundary)
	//   file     11:  65 537 B (one full chunk + 1 byte → 2 AEAD tags)
	//   file     12: 131 072 B (two full 64 KiB chunks)
	//   file     13: 131 073 B (two full chunks + 1 byte → 3 AEAD tags)
	//   file     14:  17 B     (minimal, non-zero plaintext)
	//
	// If rclone check reports "sizes differ" for any file, it exits 1 and
	// AssertOutput fails the test.
	return fmt.Sprintf(`set -e
r() { rclone \
  --s3-provider=Minio \
  --s3-endpoint="$GATEWAY_ENDPOINT" \
  --s3-env-auth=false \
  --s3-access-key-id="$AWS_ACCESS_KEY_ID" \
  --s3-secret-access-key="$AWS_SECRET_ACCESS_KEY" \
  --s3-region=us-east-1 \
  --s3-no-check-bucket=true \
  "$@"; }

PREFIX="%[1]s"
BUCKET="%[2]s"
REMOTE=":s3:${BUCKET}/${PREFIX}"

# ── Create 15 local test files of varying sizes ─────────────────────────────
# 15 files > 10 (maxKeys threshold) so the general Valkey cache-lookup path
# is exercised, not the Docker Distribution per-object HEAD fast path.
mkdir -p /tmp/rclone-src

# files 00-09: sub-chunk sizes 100 B … 9 900 B (step 1 000 B)
i=0
for size in 100 1100 2100 3100 4100 5100 6100 7100 8100 9100; do
  dd if=/dev/urandom bs="$size" count=1 of="$(printf '/tmp/rclone-src/file-%02d.bin' $i)" 2>/dev/null
  i=$((i+1))
done

# file 10: exactly 65 536 B — one full 64 KiB AES-GCM chunk boundary
dd if=/dev/urandom bs=65536  count=1 of=/tmp/rclone-src/file-10.bin 2>/dev/null

# file 11: 65 537 B — one full chunk + 1 byte (two AEAD tags)
dd if=/dev/urandom bs=65537  count=1 of=/tmp/rclone-src/file-11.bin 2>/dev/null

# file 12: 131 072 B — two full 64 KiB chunks
dd if=/dev/urandom bs=131072 count=1 of=/tmp/rclone-src/file-12.bin 2>/dev/null

# file 13: 131 073 B — two full chunks + 1 byte (three AEAD tags)
dd if=/dev/urandom bs=131073 count=1 of=/tmp/rclone-src/file-13.bin 2>/dev/null

# file 14: 17 B — minimal non-zero plaintext
printf 'small-file-payload' > /tmp/rclone-src/file-14.txt

echo "=== local files ($(ls /tmp/rclone-src | wc -l) total) ==="
ls -la /tmp/rclone-src/

# ── Sync local → gateway ─────────────────────────────────────────────────────
# Each PUT warms the Valkey size cache entry for that key.
echo "=== rclone sync → gateway ==="
r sync /tmp/rclone-src/ "${REMOTE}/" -v

# ── List remote with sizes for diagnostics ───────────────────────────────────
echo "=== rclone lsl (listing sizes from gateway) ==="
r lsl "${REMOTE}/"

# ── rclone check --size-only ─────────────────────────────────────────────────
# This is the exact command that fails in issues #204/#207.
# rclone compares each local file size against the size returned by
# ListObjects. If the gateway returns ciphertext sizes in the listing,
# rclone reports "sizes differ" for every encrypted object and exits 1.
# With a warm Valkey size cache the gateway returns plaintext sizes → exit 0.
echo "=== rclone check --size-only ($(ls /tmp/rclone-src | wc -l) files) ==="
r check /tmp/rclone-src/ "${REMOTE}/" --size-only --one-way

echo "rclone-sync-check:OK"
`,
		env.Key,
		env.Bucket,
	)
}

func (r *rcloneSyncCheckRunner) AssertOutput(code int, out, _ string) error {
	if code != 0 {
		return fmt.Errorf("rclone-sync-check exited %d (rclone check reported size mismatches — gateway may be returning ciphertext sizes in listings)", code)
	}
	if !strings.Contains(out, "rclone-sync-check:OK") {
		return fmt.Errorf("rclone-sync-check: expected OK marker in stdout")
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

// ─── restic runner (restic/restic container) ─────────────────────────────────
//
// Two runners share a common script generator but differ in which endpoint
// their scripts target for init/backup vs. restore.
//
// Both runners exercise a real restic repository on S3 through the gateway,
// which requires bypass_encryption for the bucket (restic encrypts at-rest
// itself, and uses multipart uploads that the gateway would otherwise wrap).

// resticImage is the official image tag used by both restic runners. Pinned at
// build time to keep conformance reproducible; bump via Renovate outside the
// suite.
const resticImage = "restic/restic:0.18.1"

// resticPassword is the repository-encryption password injected into the
// container. Restic always encrypts at-rest using this password, regardless
// of the gateway's bypass policy — this is what the conformance test is
// proving still works end-to-end.
const resticPassword = "conformance-restic-repo-pass"

// resticUniqueRepoPath is shared by both runners: it lives at env.Key so the
// repo prefix is unique per test invocation, preventing cross-bucket key
// collisions with concurrent providers running in parallel.
func resticUniqueRepoPath(env sdkTestEnv) string {
	return env.Key // e.g. "restic/.../<n>-<ts>"
}

// resticRoundTripRunner runs the entire init+backup+restore cycle through the
// gateway endpoint (env.Endpoint). It is the simplest end-to-end proof that
// restic works against a bypass-enabled gateway.
type resticRoundTripRunner struct{}

func (r *resticRoundTripRunner) Name() string  { return "restic" }
func (r *resticRoundTripRunner) Image() string { return resticImage }

func (r *resticRoundTripRunner) Script(env sdkTestEnv) string {
	return resticScript(resticScriptOpts{
		RepoPath:      resticUniqueRepoPath(env),
		BackupVia:     "$GATEWAY_ENDPOINT",
		RestoreVia:    "$GATEWAY_ENDPOINT",
		BackupFiles:   "/tmp/backup",
		RestoredFiles: "/tmp/restore",
		OKMarker:      "restic:roundtrip:OK",
	})
}

func (r *resticRoundTripRunner) AssertOutput(code int, out, _ string) error {
	if code != 0 {
		return fmt.Errorf("restic round-trip exited %d: %s", code, out)
	}
	if !strings.Contains(out, "restic:roundtrip:OK") {
		return fmt.Errorf("restic: expected 'restic:roundtrip:OK' marker in stdout, got: %s", out)
	}
	return nil
}

// resticBackupGatewayRestoreDirectRunner initials and backs up the repo
// through the gateway, then re-points restic at BACKEND_ENDPOINT (the raw S3
// backend, bypassing the gateway entirely) and restores from there. This
// reproduces issue #198's deployment shape: backup via gateway + direct S3
// restore.
type resticBackupGatewayRestoreDirectRunner struct{}

func (r *resticBackupGatewayRestoreDirectRunner) Name() string  { return "restic-hybrid" }
func (r *resticBackupGatewayRestoreDirectRunner) Image() string { return resticImage }

func (r *resticBackupGatewayRestoreDirectRunner) Script(env sdkTestEnv) string {
	return resticScript(resticScriptOpts{
		RepoPath:      resticUniqueRepoPath(env),
		BackupVia:     "$GATEWAY_ENDPOINT",
		RestoreVia:    "$BACKEND_ENDPOINT",
		BackupFiles:   "/tmp/backup",
		RestoredFiles: "/tmp/restore",
		OKMarker:      "restic:hybrid:OK",
	})
}

func (r *resticBackupGatewayRestoreDirectRunner) AssertOutput(code int, out, _ string) error {
	if code != 0 {
		return fmt.Errorf("restic hybrid exited %d: %s", code, out)
	}
	if !strings.Contains(out, "restic:hybrid:OK") {
		return fmt.Errorf("restic-hybrid: expected 'restic:hybrid:OK' marker in stdout, got: %s", out)
	}
	return nil
}

// resticScriptOpts parameterises the shared restic script body so the two
// runners above only differ in the backup/restore endpoint and OK marker.
type resticScriptOpts struct {
	RepoPath      string // S3 prefix under the bucket for the restic repository
	BackupVia     string // shell-evaluated endpoint URL for init+backup
	RestoreVia    string // shell-evaluated endpoint URL for restore
	BackupFiles   string // host-side dir created with sample content to back up
	RestoredFiles string // host-side dir contents are restored into
	OKMarker      string // success marker printed last
}

// resticScript generates the inline /bin/sh script that runs inside the
// restic container. The script:
//  1. Creates a small directory of files to back up.
//  2. Initialises a restic repository at s3:<BackupVia>/<Bucket>/<RepoPath>.
//  3. Snapshots the directory through restic backup.
//  4. Lists the snapshot to capture its ID.
//  5. Restores the latest snapshot into a separate directory using RestoreVia.
//  6. Diff's original vs. restored and prints the OK marker.
//
// Both endpoint args are escaped into the script text verbatim (callers pass
// "$GATEWAY_ENDPOINT" / "$BACKEND_ENDPOINT" which the shell resolves at run
// time via the env injected by runToolContainer).
func resticScript(o resticScriptOpts) string {
	// Restic's S3 backend builds the repository URL as
	//   s3:<endpoint>/<bucket>/<prefix>
	// We therefore need the endpoint WITHOUT a trailing slash, and the
	// bucket/prefix concatenated. We assemble this shell-side using $GATEWAY_
	// BUCKET so per-test buckets resolve correctly.
	//
	// The script does NOT rely on restic's exact on-disk restore layout
	// (whether absolute source paths turn into <target>/<original-path> or
	// <target>/...); it locates every restored file by basename and verifies
	// the expected content. This makes the test robust across restic
	// versions; the goal is to verify the S3 round-trip, not restic's tree
	// reconstruction semantics.
	return fmt.Sprintf(`set -eu

# ---- Prepare sample content ---------------------------------------------
mkdir -p %[1]s/sub
echo "hello-restic-conformance" > %[1]s/hello.txt
echo "payload-2"                  > %[1]s/second.txt
echo "nested-payload"             > %[1]s/sub/nested.txt

# ---- Restic init + backup via %[2]s --------------------------------------
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
export RESTIC_PASSWORD=%[6]q
REPO_PREFIX="%[7]s"
REPO_BACKUP="s3:%[2]s/$GATEWAY_BUCKET/$REPO_PREFIX"
echo "init:   $REPO_BACKUP"
restic -r "$REPO_BACKUP" init || { echo "FATAL: restic init failed"; exit 1; }

echo "backup: $REPO_BACKUP"
restic -r "$REPO_BACKUP" backup %[1]s --tag conformance \
  || { echo "FATAL: restic backup failed"; exit 1; }

# Capture and print the snapshot list for diagnostics.
restic -r "$REPO_BACKUP" snapshots

# ---- Restore via %[3]s --------------------------------------------------
REPO_RESTORE="s3:%[3]s/$GATEWAY_BUCKET/$REPO_PREFIX"
mkdir -p %[4]s
echo "restore: $REPO_RESTORE"
restic -r "$REPO_RESTORE" restore latest --target %[4]s \
  || { echo "FATAL: restic restore failed"; exit 1; }

# ---- Verify restored content (basename-agnostic to restic version) -------
verify_file() {
  name="$1"; want="$2"
  path=$(find %[4]s -name "$name" -print -quit)
  if [ -z "$path" ]; then
    echo "FATAL: $name not found in restored tree"; exit 1
  fi
  if ! grep -q "$want" "$path"; then
    echo "FATAL: $name content mismatch — want '$want'"; exit 1
  fi
}
verify_file hello.txt   "hello-restic-conformance"
verify_file second.txt  "payload-2"
verify_file nested.txt  "nested-payload"

echo "%[5]s"
`,
		o.BackupFiles,
		o.BackupVia,
		o.RestoreVia,
		o.RestoredFiles,
		o.OKMarker,
		resticPassword,
		o.RepoPath,
	)
}
