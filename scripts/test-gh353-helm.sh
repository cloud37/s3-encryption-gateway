#!/usr/bin/env bash
set -euo pipefail

TestChart_GH353SessionCredentials() {
  local script_dir repo_root chart_dir helm_bin work_dir started
  started=$SECONDS
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
  repo_root="$(cd -- "$script_dir/.." && pwd -P)"
  chart_dir="$repo_root/helm/s3-encryption-gateway"
  helm_bin="$(command -v helm || true)"
  if [[ -z "$helm_bin" ]]; then
    printf 'BLOCKED: Helm is required for TestChart_GH353SessionCredentials; install Helm locally and rerun.\n' >&2
    return 2
  fi
  if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import yaml' >/dev/null 2>&1; then
    printf 'BLOCKED: python3 with PyYAML is required to inspect rendered Helm YAML.\n' >&2
    return 2
  fi
  work_dir="$(mktemp -d "/tmp/opencode/gh353-helm.XXXXXXXX")"
  trap 'rm -rf -- "$work_dir"' RETURN
  printf 'TestChart_GH353SessionCredentials: %s\n' "$("$helm_bin" version --short)"

  python3 - "$chart_dir/values.yaml" "$work_dir/base.yaml" <<'PY'
import sys, yaml
v = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
yaml.safe_dump(v, open(sys.argv[2], "w", encoding="utf-8"), sort_keys=False)
PY

  cat >"$work_dir/fixture.py" <<'PY'
import copy, sys, yaml
v = copy.deepcopy(yaml.safe_load(open(sys.argv[1], encoding="utf-8")))
c = v["config"]["auth"]["credentials"][0]
case = sys.argv[2]
if case == "default":
    pass
elif case == "inline":
    c["sessionToken"] = {"value": "fixture-gateway-token", "valueFrom": {}}
    c["expiresAt"] = "2027-01-15T12:00:00Z"
elif case == "secret-ref":
    c["sessionToken"] = {"value": "stale-inline-token", "valueFrom": {"secretKeyRef": {"name": "fixture-secret", "key": "session-token"}}}
    c["expiresAt"] = "2027-01-15T12:00:00Z"
elif case == "configmap-ref":
    c["sessionToken"] = {"value": "stale-inline-token", "valueFrom": {"configMapKeyRef": {"name": "fixture-config", "key": "session-token"}}}
    c["expiresAt"] = "2027-01-15T12:00:00Z"
elif case == "backend-inline":
    v["config"]["backend"]["sessionToken"] = {"value": "fixture-backend-token", "valueFrom": {}}
elif case == "backend-ref":
    v["config"]["backend"]["sessionToken"] = {"value": "stale-backend-token", "valueFrom": {"secretKeyRef": {"name": "fixture-backend", "key": "session-token"}}}
elif case == "empty-clear":
    c["sessionToken"] = {"value": "", "valueFrom": {}}
    c["expiresAt"] = ""
elif case == "existing-secret":
    v["config"]["auth"]["existingCredentialsSecret"] = {"name": "fixture-full", "key": "credentials.yaml"}
    c["sessionToken"] = {"value": "must-not-render", "valueFrom": {}}
    c["expiresAt"] = "2027-01-15T12:00:00Z"
    v["config"]["backend"]["sessionToken"] = {"value": "fixture-backend-token", "valueFrom": {}}
elif case == "negative-non-gmt":
    c["sessionToken"] = {"value": "fixture-token", "valueFrom": {}}
    c["expiresAt"] = "2027-01-15T12:00:00+01:00"
elif case == "negative-malformed-time":
    c["sessionToken"] = {"value": "fixture-token", "valueFrom": {}}
    c["expiresAt"] = "tomorrow"
elif case == "negative-token-no-deadline":
    c["sessionToken"] = {"value": "fixture-token", "valueFrom": {}}
elif case == "negative-static-deadline":
    c["expiresAt"] = "2027-01-15T12:00:00Z"
elif case == "negative-empty-token-deadline":
    c["sessionToken"] = {"value": "", "valueFrom": {}}
    c["expiresAt"] = "2027-01-15T12:00:00Z"
elif case == "negative-empty-reference-deadline":
    c["sessionToken"] = {"valueFrom": {}}
    c["expiresAt"] = "2027-01-15T12:00:00Z"
elif case == "negative-token-type":
    c["sessionToken"] = {"value": 123}
    c["expiresAt"] = "2027-01-15T12:00:00Z"
elif case == "negative-token-control":
    c["sessionToken"] = {"value": "fixture\n-token", "valueFrom": {}}
    c["expiresAt"] = "2027-01-15T12:00:00Z"
elif case == "negative-unknown-property":
    c["unexpectedGH353Field"] = "fixture"
elif case == "negative-deadline-type":
    c["sessionToken"] = {"value": "fixture-token", "valueFrom": {}}
    c["expiresAt"] = 20270115
else:
    raise SystemExit("unknown fixture")
yaml.safe_dump(v, open(sys.argv[3], "w", encoding="utf-8"), sort_keys=False)
PY

  local positive_count=0 negative_count=0 case overlay rendered
  render_positive() {
    case="$1"
    overlay="$work_dir/$case.yaml"
    rendered="$work_dir/$case.rendered.yaml"
    python3 "$work_dir/fixture.py" "$work_dir/base.yaml" "$case" "$overlay"
    if ! "$helm_bin" lint "$chart_dir" -f "$overlay" >"$work_dir/$case.lint.log" 2>&1; then
      printf 'FAIL: positive Helm lint case %s failed (details withheld; see %s).\n' "$case" "$work_dir/$case.lint.log" >&2
      return 1
    fi
    if ! "$helm_bin" template gh353-fixture "$chart_dir" -f "$overlay" >"$rendered" 2>"$work_dir/$case.render.err"; then
      printf 'FAIL: positive Helm render case %s failed (details withheld; see %s).\n' "$case" "$work_dir/$case.render.err" >&2
      return 1
    fi
    python3 - "$rendered" "$case" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if isinstance(d, dict)]
d = next(x for x in docs if x.get("kind") == "Deployment")
spec = d["spec"]["template"]["spec"]
c = next(x for x in spec["containers"] if x["name"] == "gateway")
items = c.get("env", [])
env = {x["name"]: x for x in items}
assert len(env) == len(items), "duplicate env var"
case = sys.argv[2]
gateway = [n for n in env if n.startswith("GW_CRED_")]
if case == "default":
    assert "GW_CRED_0_SESSION_TOKEN" not in env and "GW_CRED_0_EXPIRES_AT" not in env
    assert env["BACKEND_SESSION_TOKEN"].get("value") == ""
elif case == "inline":
    assert env["GW_CRED_0_SESSION_TOKEN"].get("value") == "fixture-gateway-token"
    assert env["GW_CRED_0_EXPIRES_AT"].get("value") == "2027-01-15T12:00:00Z"
elif case in ("secret-ref", "configmap-ref"):
    key = "secretKeyRef" if case == "secret-ref" else "configMapKeyRef"
    assert env["GW_CRED_0_SESSION_TOKEN"].get("valueFrom", {}).get(key, {}).get("key") == "session-token"
    assert "value" not in env["GW_CRED_0_SESSION_TOKEN"]
    assert env["GW_CRED_0_EXPIRES_AT"].get("value") == "2027-01-15T12:00:00Z"
elif case == "backend-inline":
    assert env["BACKEND_SESSION_TOKEN"].get("value") == "fixture-backend-token"
    assert "GW_CRED_0_SESSION_TOKEN" not in env
elif case == "backend-ref":
    assert env["BACKEND_SESSION_TOKEN"].get("valueFrom", {}).get("secretKeyRef", {}).get("key") == "session-token"
    assert "value" not in env["BACKEND_SESSION_TOKEN"]
elif case == "empty-clear":
    assert env["GW_CRED_0_SESSION_TOKEN"].get("value") == ""
    assert env["GW_CRED_0_EXPIRES_AT"].get("value") == ""
elif case == "existing-secret":
    assert env["AUTH_CREDENTIALS_FILE"].get("value", "").endswith("/credentials.yaml")
    assert not gateway, "mounted credentials Secret must suppress all indexed credential env"
    assert env["BACKEND_SESSION_TOKEN"].get("value") == "fixture-backend-token"
    assert any(x.get("name") == "gateway-auth-credentials" for x in spec.get("volumes", []))
else:
    raise AssertionError("unexpected positive fixture")
PY
    positive_count=$((positive_count + 1))
  }

  render_positive default
  render_positive inline
  render_positive secret-ref
  render_positive configmap-ref
  render_positive backend-inline
  render_positive backend-ref
  render_positive empty-clear
  render_positive existing-secret

  for case in negative-non-gmt negative-malformed-time negative-token-no-deadline \
    negative-static-deadline negative-empty-token-deadline negative-empty-reference-deadline negative-token-type \
    negative-token-control negative-unknown-property negative-deadline-type; do
    overlay="$work_dir/$case.yaml"
    python3 "$work_dir/fixture.py" "$work_dir/base.yaml" "$case" "$overlay"
    local render_status=0 lint_status=0
    "$helm_bin" template gh353-fixture "$chart_dir" -f "$overlay" >"$work_dir/$case.render.out" 2>"$work_dir/$case.render.err" || render_status=$?
    "$helm_bin" lint "$chart_dir" -f "$overlay" >"$work_dir/$case.lint.out" 2>"$work_dir/$case.lint.err" || lint_status=$?
    if (( render_status == 0 || lint_status == 0 )); then
      printf 'FAIL: negative schema case %s was not rejected by both helm template and helm lint.\n' "$case" >&2
      return 1
    fi
    if ! grep -Eqi 'sessionToken|expiresAt|unexpectedGH353Field|credentials' "$work_dir/$case.render.err" "$work_dir/$case.lint.out" "$work_dir/$case.lint.err"; then
      printf 'FAIL: negative case %s failed without a related credential-schema diagnostic (details withheld).\n' "$case" >&2
      return 1
    fi
    negative_count=$((negative_count + 1))
  done
  printf 'PASS: TestChart_GH353SessionCredentials (%d positive render/lint cases; %d negative render+lint schema cases; %ds).\n' "$positive_count" "$negative_count" "$((SECONDS - started))"
}

TestChart_GH353SessionCredentials
