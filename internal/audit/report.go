package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// EnvelopeReport describes the on-backend encryption envelope for a single object.
type EnvelopeReport struct {
	Bucket            string            `json:"bucket"`
	Key               string            `json:"key"`
	Encrypted         bool              `json:"encrypted"`
	Algorithm         string            `json:"algorithm,omitempty"`
	Class             string            `json:"class"`
	AADScheme         string            `json:"aad_scheme"`
	KMSProvider       string            `json:"kms_provider,omitempty"`
	KMSKeyID          string            `json:"kms_key_id,omitempty"`
	KeyVersion        string            `json:"key_version,omitempty"`
	KDFParams         string            `json:"kdf_params,omitempty"`
	Chunked           bool              `json:"chunked"`
	Fallback          bool              `json:"fallback"`
	SaltHex           string            `json:"salt_hex,omitempty"`
	IVHex             string            `json:"iv_hex,omitempty"`
	CiphertextHeadHex string            `json:"ciphertext_head_hex,omitempty"`
	EncryptionHeaders map[string]string `json:"encryption_headers"`
}

// VerifyKeyReport describes the key-version verification result.
type VerifyKeyReport struct {
	Bucket     string `json:"bucket"`
	Key        string `json:"key"`
	Recorded   string `json:"recorded_key_version"`
	Want       string `json:"want_key_version,omitempty"`
	Match      bool   `json:"match"`
	Verified   string `json:"verified,omitempty"` // "full" or "metadata-only"
	Class      string `json:"class"`
}

// AlgorithmReportItem is a single entry in the algorithm distribution.
type AlgorithmReportItem struct {
	Algorithm string  `json:"algorithm"`
	Count     int64   `json:"count"`
	Percent   float64 `json:"percent"`
}

// AlgorithmReport describes the distribution of encryption algorithms in a bucket.
type AlgorithmReport struct {
	Bucket      string                          `json:"bucket"`
	Prefix      string                          `json:"prefix"`
	Total       int64                           `json:"total"`
	ByAlgorithm []AlgorithmReportItem           `json:"by_algorithm"`
	ByClass     map[string]int64                `json:"by_class,omitempty"`
}

// WriteText writes the EnvelopeReport as a human-readable table to w.
func (r *EnvelopeReport) WriteText(w io.Writer) {
	fmt.Fprintf(w, "Bucket:          %s\n", r.Bucket)
	fmt.Fprintf(w, "Key:             %s\n", r.Key)
	fmt.Fprintf(w, "Encrypted:       %t\n", r.Encrypted)
	fmt.Fprintf(w, "Class:           %s\n", r.Class)
	fmt.Fprintf(w, "AAD Scheme:      %s\n", r.AADScheme)
	if r.Algorithm != "" {
		fmt.Fprintf(w, "Algorithm:       %s\n", r.Algorithm)
	}
	if r.KMSProvider != "" {
		fmt.Fprintf(w, "KMS Provider:    %s\n", r.KMSProvider)
	}
	if r.KMSKeyID != "" {
		fmt.Fprintf(w, "KMS Key ID:      %s\n", r.KMSKeyID)
	}
	if r.KeyVersion != "" {
		fmt.Fprintf(w, "Key Version:     %s\n", r.KeyVersion)
	}
	if r.KDFParams != "" {
		fmt.Fprintf(w, "KDF Params:      %s\n", r.KDFParams)
	}
	fmt.Fprintf(w, "Chunked:         %t\n", r.Chunked)
	fmt.Fprintf(w, "Fallback:        %t\n", r.Fallback)
	if r.SaltHex != "" {
		fmt.Fprintf(w, "Salt (hex):      %s\n", r.SaltHex)
	}
	if r.IVHex != "" {
		fmt.Fprintf(w, "IV (hex):        %s\n", r.IVHex)
	}
	if r.CiphertextHeadHex != "" {
		fmt.Fprintf(w, "Ciphertext head: %s\n", r.CiphertextHeadHex)
	}
	if len(r.EncryptionHeaders) > 0 {
		fmt.Fprintf(w, "Encryption headers:\n")
		for k, v := range r.EncryptionHeaders {
			fmt.Fprintf(w, "  %s: %s\n", k, v)
		}
	}
}

// WriteJSON writes the EnvelopeReport as indented JSON to w.
func (r *EnvelopeReport) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes the VerifyKeyReport as human-readable text to w.
func (r *VerifyKeyReport) WriteText(w io.Writer) {
	fmt.Fprintf(w, "Bucket:    %s\n", r.Bucket)
	fmt.Fprintf(w, "Key:       %s\n", r.Key)
	fmt.Fprintf(w, "Class:     %s\n", r.Class)
	fmt.Fprintf(w, "Recorded:  %s\n", r.Recorded)
	if r.Want != "" {
		fmt.Fprintf(w, "Requested: %s\n", r.Want)
	}
	fmt.Fprintf(w, "Match:     %t\n", r.Match)
	if r.Verified != "" {
		fmt.Fprintf(w, "Verified:  %s\n", r.Verified)
	}
}

// WriteJSON writes the VerifyKeyReport as indented JSON to w.
func (r *VerifyKeyReport) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// WriteText writes the AlgorithmReport as a formatted table to w.
func (r *AlgorithmReport) WriteText(w io.Writer) {
	fmt.Fprintf(w, "Bucket:   %s\n", r.Bucket)
	if r.Prefix != "" {
		fmt.Fprintf(w, "Prefix:   %s\n", r.Prefix)
	}
	fmt.Fprintf(w, "Total:    %d\n\n", r.Total)

	if len(r.ByAlgorithm) > 0 {
		fmt.Fprintf(w, "By Algorithm:\n")
		fmt.Fprintf(w, "  %-30s %10s %8s\n", "Algorithm", "Count", "Percent")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 52))
		for _, item := range r.ByAlgorithm {
			fmt.Fprintf(w, "  %-30s %10d %7.2f%%\n", item.Algorithm, item.Count, item.Percent)
		}
		fmt.Fprintln(w)
	}

	if len(r.ByClass) > 0 {
		total := int64(0)
		for _, v := range r.ByClass {
			total += v
		}
		fmt.Fprintf(w, "By Class:\n")
		fmt.Fprintf(w, "  %-30s %10s %8s\n", "Class", "Count", "Percent")
		fmt.Fprintf(w, "  %s\n", strings.Repeat("-", 52))
		for k, v := range r.ByClass {
			pct := 0.0
			if total > 0 {
				pct = float64(v) / float64(total) * 100
			}
			fmt.Fprintf(w, "  %-30s %10d %7.2f%%\n", k, v, pct)
		}
	}
}

// WriteJSON writes the AlgorithmReport as indented JSON to w.
func (r *AlgorithmReport) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
