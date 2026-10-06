package api

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	awstypes "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/require"
)

const corsTestXML = `<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><CORSRule><ID>web</ID><AllowedOrigin>https://app.example.com</AllowedOrigin><AllowedMethod>PUT</AllowedMethod><AllowedHeader>content-type</AllowedHeader><ExposeHeader>ETag</ExposeHeader><MaxAgeSeconds>3600</MaxAgeSeconds></CORSRule></CORSConfiguration>`

func TestParseCORSXML_ValidRoundTrip(t *testing.T) {
	cfg, err := parseCORSXML([]byte(corsTestXML))
	require.NoError(t, err)
	require.Equal(t, "web", cfg.Rules[0].ID)
	require.Equal(t, 3600, *cfg.Rules[0].MaxAgeSeconds)
	wire, err := marshalCORSXML(cfg)
	require.NoError(t, err)
	require.Contains(t, string(wire), `xmlns="`+corsXMLNamespace+`"`)
	parsed, err := parseCORSXML(wire)
	require.NoError(t, err)
	require.Equal(t, cfg, parsed)
}

func TestCORSOriginParserPreservesHostPort(t *testing.T) {
	for _, origin := range []string{"https://example.com", "https://example.com:8443"} {
		_, host, ok := splitCORSOrigin(origin)
		u, err := url.Parse(origin)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, u.Host, host)
	}
}

func TestParseCORSXML_StrictExtensionsAndDuplicateScalars(t *testing.T) {
	for _, body := range []string{
		`<?xml-stylesheet href="x"?><CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`,
		`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration><!--trailing--><?evil value?>`,
		`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><ID>a</ID><ID>b</ID></CORSRule></CORSConfiguration>`,
		`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><MaxAgeSeconds>1</MaxAgeSeconds><MaxAgeSeconds>2</MaxAgeSeconds></CORSRule></CORSConfiguration>`,
		`<CORSConfiguration xmlns="urn:wrong"><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`,
	} {
		_, err := parseCORSXML([]byte(body))
		require.Error(t, err, body)
	}
	for _, body := range []string{
		`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration><?xml version="1.0"?>`,
		`<?xml version="1.0"?><?xml version="1.0"?><CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`,
		`<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><CORSRule xmlns=""><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`,
	} {
		_, err := parseCORSXML([]byte(body))
		require.Error(t, err, body)
	}
	_, err := parseCORSXML([]byte(`<?xml version="1.0"?><CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`))
	require.NoError(t, err, "a single leading XML declaration is valid")
	for _, declaration := range []string{
		`<?xml version=garbage?>`,
		`<?xml version="2.0"?>`,
		`<?xml encoding="UTF-8" version="1.0"?>`,
		`<?xml version="1.0" version="1.1"?>`,
		`<?xml version="1.0" foo="bar"?>`,
		`<?xml version="1.0" standalone="maybe"?>`,
		`<?xml version="1.0" standalone="yes" encoding="UTF-8"?>`,
		`<?XML version="1.0"?>`,
	} {
		body := declaration + `<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`
		_, err := parseCORSXML([]byte(body))
		require.Error(t, err, body)
	}
	for _, declaration := range []string{`<?xml version="1.0"?>`, `<?xml version='1.0' encoding='UTF-8' standalone='yes'?>`} {
		body := declaration + `<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`
		_, err := parseCORSXML([]byte(body))
		require.NoError(t, err, body)
	}
	_, err = parseCORSXML([]byte(`<?xml version="1.1"?><CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`))
	require.Error(t, err, "only XML 1.0 declaration supported by encoding/xml is accepted")
	for _, body := range []string{
		`<CORSConfiguration><CORSRule><AllowedOrigin>https://ok.example` + "\t" + `</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`,
		`<CORSConfiguration><CORSRule><AllowedOrigin>https://ok.example` + "\x01" + `</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`,
	} {
		_, err := parseCORSXML([]byte(body))
		require.Error(t, err, body)
	}
}

func TestParseCORSXML_AWSSDKSerializedOrder(t *testing.T) {
	// aws-sdk-go-v2/service/s3 v1.114.0 serializes fields in this order.
	// Repeated list elements retain their own order; known fields are accepted
	// in any permutation while CORSRule order remains meaningful.
	body := `<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><CORSRule><AllowedHeader>content-type</AllowedHeader><AllowedMethod>PUT</AllowedMethod><AllowedOrigin>https://app.example.com</AllowedOrigin><ExposeHeader>ETag</ExposeHeader><ID>sdk</ID><MaxAgeSeconds>3600</MaxAgeSeconds></CORSRule></CORSConfiguration>`
	cfg, err := parseCORSXML([]byte(body))
	require.NoError(t, err)
	require.Equal(t, "sdk", cfg.Rules[0].ID)
	require.Equal(t, []string{"content-type"}, cfg.Rules[0].AllowedHeaders)
	require.Equal(t, []string{"PUT"}, cfg.Rules[0].AllowedMethods)
}

func TestParseCORSXML_AWSSDKPutBucketCorsSerialization(t *testing.T) {
	var serialized []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serialized, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	client := awss3.New(awss3.Options{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), UsePathStyle: true})
	input := &awss3.PutBucketCorsInput{Bucket: aws.String("bucket"), CORSConfiguration: &awstypes.CORSConfiguration{CORSRules: []awstypes.CORSRule{
		{
			AllowedHeaders: []string{"content-type", "x-amz-*"},
			AllowedMethods: []string{"PUT", "POST"},
			AllowedOrigins: []string{"https://app.example.com", "https://admin.example.com"},
			ExposeHeaders:  []string{"ETag", "X-Trace"},
			ID:             aws.String("sdk-first"),
			MaxAgeSeconds:  aws.Int32(3600),
		},
		{
			AllowedHeaders: []string{"authorization", "content-type"},
			AllowedMethods: []string{"GET", "HEAD"},
			AllowedOrigins: []string{"https://read.example.com"},
			ExposeHeaders:  []string{"ETag"},
			ID:             aws.String("sdk-second"),
		},
	}}}
	_, err := client.PutBucketCors(context.Background(), input)
	require.NoError(t, err)
	cfg, err := parseCORSXML(serialized)
	require.NoError(t, err, string(serialized))
	wire, err := marshalCORSXML(cfg)
	require.NoError(t, err)
	roundTrip, err := parseCORSXML(wire)
	require.NoError(t, err)
	require.Equal(t, cfg, roundTrip)
	require.Equal(t, []string{"sdk-first", "sdk-second"}, []string{roundTrip.Rules[0].ID, roundTrip.Rules[1].ID})
	require.Equal(t, []string{"PUT", "POST"}, roundTrip.Rules[0].AllowedMethods)
	require.Equal(t, []string{"https://app.example.com", "https://admin.example.com"}, roundTrip.Rules[0].AllowedOrigins)
}

func TestParseCORSXML_RejectsMalformedAndOversized(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod><Unknown>x</Unknown></CORSRule></CORSConfiguration>`),
		[]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration><extra/>`),
		[]byte(`<!DOCTYPE x [<!ENTITY a "x">]><CORSConfiguration/>`),
		[]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>null</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`),
		[]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>https://host]</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`),
		[]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>https://ho"st</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`),
		[]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>https://ho&lt;st</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`),
		[]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>https://ho&gt;st</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`),
		[]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>https://:8443</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`),
		[]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>https://ok.example</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration><extra/>`),
		bytes.Repeat([]byte("x"), maxCORSXMLBytes+1),
	} {
		_, err := parseCORSXML(data)
		require.Error(t, err)
	}
	_, err := parseCORSXML(bytes.Repeat([]byte(" "), maxCORSXMLBytes+1))
	require.ErrorIs(t, err, ErrCORSTooLarge)
}

func TestMatchCORSRule_FirstRuleAndAllHeaders(t *testing.T) {
	cfg, err := parseCORSXML([]byte(`<CORSConfiguration><CORSRule><ID>first</ID><AllowedOrigin>https://*.example.com</AllowedOrigin><AllowedMethod>PUT</AllowedMethod><AllowedHeader>content-type</AllowedHeader></CORSRule><CORSRule><ID>second</ID><AllowedOrigin>*</AllowedOrigin><AllowedMethod>PUT</AllowedMethod><AllowedHeader>*</AllowedHeader></CORSRule></CORSConfiguration>`))
	require.NoError(t, err)
	rule, ok := matchCORSRule(cfg, "https://app.example.com", "PUT", []string{"Content-Type"})
	require.True(t, ok)
	require.Equal(t, "first", rule.ID)
	_, ok = matchCORSRule(cfg, "https://app.example.com", "PUT", []string{"content-type", "x-custom"})
	require.True(t, ok)
	// The first rule doesn't match every header, so the second is selected.
	rule, _ = matchCORSRule(cfg, "https://app.example.com", "PUT", []string{"content-type", "x-custom"})
	require.Equal(t, "second", rule.ID)
}

func TestMatchCORSRule_RejectsOriginInjection(t *testing.T) {
	cfg, err := parseCORSXML([]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>*</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`))
	require.NoError(t, err)
	for _, origin := range []string{"https://ok.example\r\nX-Evil: yes", "https://a.example,https://b.example", "null", "*", "https://", "https://host:", "https://host:65536", "https://user@host", "https://host/path", "\thttps://host", "https://host]", "https://ho\"st", "https://ho<st", "https://ho>st", "https://bad_host", "https://-bad.example", "https://bad-.example", "https://[not-ipv6]", "https://[2001:db8::1", "https://2001:db8::1", "https://[2001:db8::1]x"} {
		_, ok := matchCORSRule(cfg, origin, "GET", nil)
		require.False(t, ok, origin)
	}
}

func TestValidateConcreteCORSOrigin_ValidDNSIPv4IPv6AndPorts(t *testing.T) {
	for _, origin := range []string{"http://example.com", "https://sub-domain.example.com.", "https://127.0.0.1", "https://[2001:db8::1]", "https://[2001:db8::1]:8443", "https://[::ffff:192.0.2.1]", "https://example.com:65535"} {
		require.NoError(t, validateConcreteCORSOrigin(origin), origin)
	}
}

func TestMatchCORSRule_WildcardStaysWithinHostAndPort(t *testing.T) {
	cfg, err := parseCORSXML([]byte(`<CORSConfiguration><CORSRule><AllowedOrigin>https://*.example.com</AllowedOrigin><AllowedMethod>GET</AllowedMethod></CORSRule></CORSConfiguration>`))
	require.NoError(t, err)
	for _, origin := range []string{"https://app.example.com", "https://app.example.com:8443", "https://app.other-example.com", "https://example.com.evil"} {
		_, matched := matchCORSRule(cfg, origin, "GET", nil)
		if origin == "https://app.example.com" {
			require.True(t, matched)
		} else {
			require.False(t, matched, origin)
		}
	}
}

func FuzzParseCORSXML_NoPanic(f *testing.F) {
	f.Add([]byte(corsTestXML))
	f.Add([]byte(`<CORSConfiguration/>`))
	f.Fuzz(func(t *testing.T, body []byte) { _, _ = parseCORSXML(body) })
}
