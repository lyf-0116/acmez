// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package acmez implements the higher-level flow of the ACME specification,
// RFC 8555: https://tools.ietf.org/html/rfc8555, specifically the sequence
// in Section 7.1 (page 21).
//
// It makes it easy to obtain certificates with various challenge types
// using pluggable challenge solvers, and provides some handy utilities for
// implementing solvers and using the certificates. It DOES NOT manage
// certificates, it only gets them from the ACME server.
//
// NOTE: This package's primary purpose is to get a certificate, not manage it.
// Most users actually want to *manage* certificates over the lifetime of
// long-running programs such as HTTPS or TLS servers, and should use CertMagic
// instead: https://github.com/caddyserver/certmagic.
//
// COMPATIBILITY: Exported identifiers that are related to draft specifications
// are subject to change or removal without a major version bump.
package acmez

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"net"
	"net/url"
	"testing"

	"github.com/mholt/acmez/v3/acme"
)

// marshalOtherName marshals an otherName field with the given oid and value and
// returns the raw bytes to use.
func marshalOtherName(t *testing.T, oid asn1.ObjectIdentifier, value interface{}) asn1.RawValue {
	t.Helper()
	valueBytes, err := asn1.MarshalWithParams(value, "explicit,tag:0")
	if err != nil {
		t.Fatal(err)
	}
	b, err := asn1.MarshalWithParams(otherName{
		TypeID: oid,
		Value:  asn1.RawValue{FullBytes: valueBytes},
	}, "tag:0")
	if err != nil {
		t.Fatal(err)
	}
	return asn1.RawValue{FullBytes: b}
}

func mustParseURL(t *testing.T, rawURL string) *url.URL {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func mustMarshal(t *testing.T, val any) []byte {
	t.Helper()
	data, err := asn1.Marshal(val)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func Test_validateOrderIdentifiers(t *testing.T) {
	type args struct {
		order *acme.Order
		csr   *x509.CertificateRequest
	}
	tests := []struct {
		name   string
		args   args
		expErr error
	}{
		{
			name: "ok/single-dns",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "single-dns.example.com"},
					},
				},
				csr: &x509.CertificateRequest{
					DNSNames: []string{"single-dns.example.com"},
				},
			},
		},
		{
			name: "ok/single-ip",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "ip", Value: "127.0.0.1"},
					},
				},
				csr: &x509.CertificateRequest{
					IPAddresses: []net.IP{
						net.ParseIP("127.0.0.1"),
					},
				},
			},
		},
		{
			name: "ok/single-permanent-identifier",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "permanent-identifier", Value: "7e34c159-b532-43f0-9014-0f038a50bf0d"},
					},
				},
				csr: &x509.CertificateRequest{
					Extensions: []pkix.Extension{
						{
							Id: oidExtensionSubjectAltName,
							Value: mustMarshal(t, []asn1.RawValue{
								marshalOtherName(t, oidPermanentIdentifier, permanentIdentifier{
									IdentifierValue: "7e34c159-b532-43f0-9014-0f038a50bf0d",
								}),
							}),
						},
					},
				},
			},
		},
		{
			name: "ok/single-hardware-module",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "hardware-module", Value: "1234"},
					},
				},
				csr: &x509.CertificateRequest{
					Extensions: []pkix.Extension{
						{
							Id: oidExtensionSubjectAltName,
							Value: mustMarshal(t, []asn1.RawValue{
								marshalOtherName(t, oidHardwareModuleName, hardwareModuleName{
									Type:         oidHardwareModuleName,
									SerialNumber: []byte("1234"),
								}),
							}),
						},
					},
				},
			},
		},
		{
			name: "ok/dns-and-permanent-identifier-with-same-value",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "7e34c159-b532-43f0-9014-0f038a50bf0d"},
						{Type: "permanent-identifier", Value: "7e34c159-b532-43f0-9014-0f038a50bf0d"},
					},
				},
				csr: &x509.CertificateRequest{
					DNSNames: []string{"7e34c159-b532-43f0-9014-0f038a50bf0d"},
					Extensions: []pkix.Extension{
						{
							Id: oidExtensionSubjectAltName,
							Value: mustMarshal(t, []asn1.RawValue{
								marshalOtherName(t, oidPermanentIdentifier, permanentIdentifier{
									IdentifierValue: "7e34c159-b532-43f0-9014-0f038a50bf0d",
								}),
							}),
						},
					},
				},
			},
		},
		{
			name: "ok/single-uri",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "uri", Value: "spiffe://example.com/service"},
					},
				},
				csr: &x509.CertificateRequest{
					URIs: []*url.URL{
						mustParseURL(t, "spiffe://example.com/service"),
					},
				},
			},
		},
		{
			name: "fail/uri-not-in-order",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "a-dns.example.com"},
					},
				},
				csr: &x509.CertificateRequest{
					DNSNames: []string{"a-dns.example.com"},
					URIs: []*url.URL{
						mustParseURL(t, "spiffe://example.com/service"),
					},
				},
			},
			expErr: errors.New("number of identifiers in Order [{dns a-dns.example.com}] (1) does not match the number of identifiers extracted from CSR [{dns a-dns.example.com} {uri spiffe://example.com/service}] (2)"),
		},
		{
			name: "fail/uri-different-from-order",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "uri", Value: "spiffe://example.com/service"},
					},
				},
				csr: &x509.CertificateRequest{
					URIs: []*url.URL{
						mustParseURL(t, "spiffe://example.com/other-service"),
					},
				},
			},
			expErr: errors.New("identifiers in Order [{uri spiffe://example.com/service}] do not match the identifiers extracted from CSR [{uri spiffe://example.com/other-service}]"),
		},
		{
			name: "fail/duplicate-in-order-masks-mismatch",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "a-dns.example.com"},
						{Type: "dns", Value: "a-dns.example.com"},
					},
				},
				csr: &x509.CertificateRequest{
					DNSNames: []string{"a-dns.example.com", "another-dns.example.com"},
				},
			},
			expErr: errors.New("identifiers in Order [{dns a-dns.example.com} {dns a-dns.example.com}] do not match the identifiers extracted from CSR [{dns a-dns.example.com} {dns another-dns.example.com}]"),
		},
		{
			name: "fail/duplicate-in-csr-masks-mismatch",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "a-dns.example.com"},
						{Type: "dns", Value: "another-dns.example.com"},
					},
				},
				csr: &x509.CertificateRequest{
					DNSNames: []string{"a-dns.example.com", "a-dns.example.com"},
				},
			},
			expErr: errors.New("identifiers in Order [{dns a-dns.example.com} {dns another-dns.example.com}] do not match the identifiers extracted from CSR [{dns a-dns.example.com} {dns a-dns.example.com}]"),
		},
		{
			name: "ok/matching-duplicates",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "a-dns.example.com"},
						{Type: "dns", Value: "a-dns.example.com"},
					},
				},
				csr: &x509.CertificateRequest{
					DNSNames: []string{"a-dns.example.com", "a-dns.example.com"},
				},
			},
		},
		{
			name: "fail/extract-from-csr",
			args: args{
				csr: &x509.CertificateRequest{
					Extensions: []pkix.Extension{
						{
							Id:    oidExtensionSubjectAltName,
							Value: []byte{1, 2, 3, 4},
						},
					},
				},
			},
			expErr: errors.New("extracting identifiers from CSR: invalid subject alternative name extension"),
		},
		{
			name: "fail/less-identifiers-in-csr",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "a-dns.example.com"},
						{Type: "dns", Value: "another-dns.example.com"},
					},
				},
				csr: &x509.CertificateRequest{
					DNSNames: []string{"a-dns.example.com"},
				},
			},
			expErr: errors.New("number of identifiers in Order [{dns a-dns.example.com} {dns another-dns.example.com}] (2) does not match the number of identifiers extracted from CSR [{dns a-dns.example.com}] (1)"),
		},
		{
			name: "fail/less-identifiers-in-order",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "a-dns.example.com"},
					},
				},
				csr: &x509.CertificateRequest{
					DNSNames: []string{"a-dns.example.com"},
					IPAddresses: []net.IP{
						net.ParseIP("127.0.0.1"),
					},
				},
			},
			expErr: errors.New("number of identifiers in Order [{dns a-dns.example.com}] (1) does not match the number of identifiers extracted from CSR [{dns a-dns.example.com} {ip 127.0.0.1}] (2)"),
		},
		{
			name: "fail/duplicates-different-number-of-identifiers", // duplicates are not filtered by this package
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "a-dns.example.com"},
						{Type: "dns", Value: "a-dns.example.com"},
					},
				},
				csr: &x509.CertificateRequest{
					DNSNames: []string{"a-dns.example.com"},
				},
			},
			expErr: errors.New("number of identifiers in Order [{dns a-dns.example.com} {dns a-dns.example.com}] (2) does not match the number of identifiers extracted from CSR [{dns a-dns.example.com}] (1)"),
		},
		{
			name: "fail/different-identifiers",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "a-dns.example.com"},
					},
				},
				csr: &x509.CertificateRequest{
					DNSNames: []string{"another-dns.example.com"},
				},
			},
			expErr: errors.New("identifiers in Order [{dns a-dns.example.com}] do not match the identifiers extracted from CSR [{dns another-dns.example.com}]"),
		},
		{
			name: "fail/types-switched",
			args: args{
				order: &acme.Order{
					Identifiers: []acme.Identifier{
						{Type: "dns", Value: "7e34c159-b532-43f0-9014-0f038a50bf0d"},
						{Type: "permanent-identifier", Value: "a-dns.example.com"},
					},
				},
				csr: &x509.CertificateRequest{
					DNSNames: []string{"a-dns.example.com"},
					Extensions: []pkix.Extension{
						{
							Id: oidExtensionSubjectAltName,
							Value: mustMarshal(t, []asn1.RawValue{
								marshalOtherName(t, oidPermanentIdentifier, permanentIdentifier{
									IdentifierValue: "7e34c159-b532-43f0-9014-0f038a50bf0d",
								}),
							}),
						},
					},
				},
			},
			expErr: errors.New("identifiers in Order [{dns 7e34c159-b532-43f0-9014-0f038a50bf0d} {permanent-identifier a-dns.example.com}] do not match the identifiers extracted from CSR [{dns a-dns.example.com} {permanent-identifier 7e34c159-b532-43f0-9014-0f038a50bf0d}]"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOrderIdentifiers(tt.args.order, tt.args.csr)
			if tt.expErr != nil {
				switch {
				case err == nil:
					t.Error("validateOrderIdentifiers() expected error, but got none")
				case err.Error() != tt.expErr.Error():
					t.Errorf("validateOrderIdentifiers() error = %v, wantErr %v", err, tt.expErr)
				}
				return
			}

			if err != nil {
				t.Errorf("validateOrderIdentifiers() unexpected error = %v", err)
			}
		})
	}
}

func Test_challengeHistory_successRatio(t *testing.T) {
	untried := challengeHistory{typeName: "untried"}
	if got := untried.successRatio(); got != 0.5 {
		t.Errorf("untried challenge type should have neutral smoothed ratio 0.5, got %f", got)
	}

	proven := challengeHistory{typeName: "proven", successes: 999, total: 1000}
	if got := proven.successRatio(); got <= 0.5 {
		t.Errorf("proven challenge type should outrank an untried one, got %f", got)
	}

	oneFailure := challengeHistory{typeName: "oneFailure", total: 1}
	if got := oneFailure.successRatio(); got >= 0.5 {
		t.Errorf("failed-once challenge type should rank below an untried one, got %f", got)
	}

	// a single failure must not sink a well-proven type to the bottom
	proven.total++
	if got := proven.successRatio(); got <= oneFailure.successRatio() {
		t.Errorf("one failure should not rank a proven type below a failed-once type, got %f", got)
	}
}

func Test_challengeStatsScopeIsolation(t *testing.T) {
	// statistics for one CA/account scope must not leak into another
	scopeA := challengeStatsScope{directory: "https://ca-a.example/dir", account: "acct-1"}
	scopeB := challengeStatsScope{directory: "https://ca-b.example/dir", account: "acct-1"}
	scopeC := challengeStatsScope{directory: "https://ca-a.example/dir", account: "acct-2"}

	preferredChallengesMu.Lock()
	defer preferredChallengesMu.Unlock()
	preferredChallenges = make(map[challengeStatsScope]challengeTypes)

	statsA := challengeTypes{{typeName: "http-01"}, {typeName: "dns-01"}}
	statsA.increment("http-01", false)
	preferredChallenges[scopeA] = statsA

	for _, scope := range []challengeStatsScope{scopeB, scopeC} {
		for _, ch := range preferredChallenges[scope] {
			if ch.total != 0 {
				t.Errorf("scope %+v should be unaffected by failures in another scope, got %+v", scope, ch)
			}
		}
	}
	for _, ch := range preferredChallenges[scopeA] {
		if ch.typeName == "http-01" && ch.total != 1 {
			t.Errorf("failure should be recorded in its own scope, got %+v", ch)
		}
	}
}

func Test_problemMayBeCausedByChallengeType(t *testing.T) {
	retryable := []string{
		acme.ProblemTypeIncorrectResponse,
		acme.ProblemTypeConnection,
		acme.ProblemTypeDNS,
		acme.ProblemTypeTLS,
		acme.ProblemTypeUnauthorized,
		acme.ProblemTypeServerInternal,
		"urn:ietf:params:acme:error:someFutureError",
	}
	for _, pt := range retryable {
		if !problemMayBeCausedByChallengeType(pt) {
			t.Errorf("problem type %s should be retryable with another challenge type", pt)
		}
	}

	notRetryable := []string{
		acme.ProblemTypeRateLimited,
		acme.ProblemTypeRejectedIdentifier,
		acme.ProblemTypeCAA,
		acme.ProblemTypeMalformed,
		acme.ProblemTypeBadCSR,
	}
	for _, pt := range notRetryable {
		if problemMayBeCausedByChallengeType(pt) {
			t.Errorf("problem type %s should not be retryable with another challenge type", pt)
		}
	}
}
