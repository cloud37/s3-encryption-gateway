#!/usr/bin/env bash
set -euo pipefail

out_dir=${1:-/tmp/opencode/sec38-coverage-audit}
mkdir -p "$out_dir"

go test ./internal/api -coverprofile="$out_dir/api.out" -count=1
go test ./internal/mpu -coverprofile="$out_dir/mpu.out" -count=1

printf 'SEC-38 changed security-critical symbol coverage\n'
printf 'Profiles: %s/api.out %s/mpu.out\n\n' "$out_dir" "$out_dir"

audit_symbol() {
	local profile=$1 file=$2 symbol=$3
	local start end path
	path="github.com/cloud37/s3-encryption-gateway/$file"
	start=$(grep -n -E "^func .*${symbol}(\(|[[:space:]]*=)" "$file" | head -1 | cut -d: -f1)
	end=$(awk -v n="$start" 'NR > n && /^func / { print NR - 1; exit } END { if (!x) print NR }' x=1 "$file")
	local total=0 covered=0 first last
	while IFS= read -r block; do
		local range n count a b
		range=${block%% *}; n=${block#* }; n=${n%% *}; count=${block##* }
		a=${range##*:}; a=${a%%.*}; b=${range#*,}; b=${b%%.*}
		if (( a >= start && b <= end )); then
			total=$((total + n));
			if (( count > 0 )); then covered=$((covered + n)); fi
			[[ -z "${first:-}" ]] && first=$a
			last=$b
		fi
	done < <(grep "^${path}:" "$profile")
	if (( total == 0 )); then
		printf '%s %s:%s-%s 0/0 (not instrumented)\n' "$symbol" "$file" "$start" "$end"
	else
		printf '%s %s:%s-%s %d/%d (%s%%)\n' "$symbol" "$file" "$start" "$end" "$covered" "$total" "$(awk -v c="$covered" -v t="$total" 'BEGIN { printf "%.1f", 100*c/t }')"
	fi
}

# These are the changed SEC-38 protocol/helper boundaries. Generic handler
# transport, provider plumbing, constructors, List/Delete, and key-loading
# branches are intentionally outside this audit because they are unchanged
# or not security-critical SEC-38 branches.
audit_symbol "$out_dir/mpu.out" internal/mpu/state.go Create
audit_symbol "$out_dir/mpu.out" internal/mpu/state.go ReservePart
audit_symbol "$out_dir/mpu.out" internal/mpu/state.go CommitPart
audit_symbol "$out_dir/mpu.out" internal/mpu/state.go syncControlMeta
audit_symbol "$out_dir/mpu.out" internal/mpu/state.go ReleasePart
audit_symbol "$out_dir/mpu.out" internal/mpu/state.go BeginComplete
audit_symbol "$out_dir/mpu.out" internal/mpu/state.go Reopen
audit_symbol "$out_dir/mpu.out" internal/mpu/state.go FinalizeComplete
audit_symbol "$out_dir/mpu.out" internal/mpu/state.go BeginAbort
audit_symbol "$out_dir/mpu.out" internal/mpu/state.go FinalizeAbort
audit_symbol "$out_dir/mpu.out" internal/mpu/state.go atomicLifecycle
audit_symbol "$out_dir/api.out" internal/api/handlers.go reserveEncryptedMPUPart
audit_symbol "$out_dir/api.out" internal/api/handlers.go beginEncryptedMPUComplete
audit_symbol "$out_dir/api.out" internal/api/upload_part_copy.go copyPartClaimError
audit_symbol "$out_dir/api.out" internal/api/upload_part_copy.go uploadPartCopyReencryptMPU
audit_symbol "$out_dir/api.out" internal/api/upload_part_copy.go decodeMPUPlaintextRange
