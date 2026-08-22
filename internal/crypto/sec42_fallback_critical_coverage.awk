# Run: awk -f this-file critical.tsv coverage.out
# Every TSV row is an inclusive critical range; all rows are evaluated.
BEGIN { FS="[ \t]+" }
/^#/ { next }
FNR == NR { n[$1]++; lo[$1,n[$1]]=$2; hi[$1,n[$1]]=$3; next }
/^mode:/ { next }
{
  split($1, p, "/"); file=p[length(p)]; sub(/:.*/, "", file)
  text=$1; sub(/^.*:/, "", text); split(text, z, ",")
  split(z[1], a, /\./); split(z[2], b, /\./); matched=0
  # Every critical range begins and ends on Go statement boundaries. Require a
  # profile block to be fully contained, so adjacent non-critical statements
  # are not attributed to this SEC-42 gate.
  for (i=1; i<=n[file]; i++) if (a[1] >= lo[file,i] && b[1] <= hi[file,i]) matched=1
  # Go coverage profiles encode start/end, number of statements, and hit
  # count. Count statements, not execution hits (which differ by cover mode).
  if (matched) { total += $2; if ($3 > 0) covered += $2 }
}
END {
  if (!total) { print "critical statements: 0"; exit 1 }
  printf "critical statements: %d/%d (%.1f%%)\n", covered, total, 100*covered/total
  if (covered * 100 < total * 85) exit 1
}
