package acme

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestReplayNonceGuardRejectsMissingHeader(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &Client{
		dir:    Directory{NewNonce: srv.URL + "/new-nonce"},
		nonces: new(stack),
	}

	_, err := client.nonce(context.Background())
	if !errors.Is(err, errNonceRequired) {
		t.Fatalf("nonce() error = %v; want errors.Is(_, errNonceRequired)", err)
	}
}

func TestReplayNonceGuardStopsJWSPOSTBeforeNetworkSend(t *testing.T) {
	var postRequests atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/new-nonce", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/endpoint", func(w http.ResponseWriter, _ *http.Request) {
		postRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := &Client{dir: Directory{NewNonce: srv.URL + "/new-nonce"}}

	_, err := client.httpPostJWS(
		context.Background(),
		testKeyEC,
		"",
		srv.URL+"/endpoint",
		map[string]string{"hello": "world"},
		nil,
	)
	if !errors.Is(err, errNonceRequired) {
		t.Fatalf("httpPostJWS() error = %v; want errors.Is(_, errNonceRequired)", err)
	}
	if got := postRequests.Load(); got != 0 {
		t.Fatalf("endpoint received %d POST request(s); want 0", got)
	}
}

func TestReplayNonceGuardJWSJSONRejectsEmptyValue(t *testing.T) {
	_, err := jwsEncodeJSON(
		struct{ Hello string }{"world"},
		testKeyEC,
		noKeyID,
		"",
		"https://example.invalid/endpoint",
	)
	if !errors.Is(err, errNonceRequired) {
		t.Fatalf("jwsEncodeJSON() error = %v; want errors.Is(_, errNonceRequired)", err)
	}
}

func TestReplayNonceGuardJWSHeadRejectsEmptyValue(t *testing.T) {
	_, err := jwsHead("ES256", "", "https://example.invalid/endpoint", noKeyID, testKeyEC)
	if !errors.Is(err, errNonceRequired) {
		t.Fatalf("jwsHead() error = %v; want errors.Is(_, errNonceRequired)", err)
	}
}

func TestReplayNonceGuardKeyChangeInnerJWSRemainsExempt(t *testing.T) {
	raw, err := jwsEncodeJSONWithoutNonce(
		keyChangeRequest{Account: "https://example.invalid/account"},
		testKeyEC,
		noKeyID,
		"https://example.invalid/key-change",
	)
	if err != nil {
		t.Fatalf("jwsEncodeJSONWithoutNonce() error = %v", err)
	}

	var jws struct {
		Protected string `json:"protected"`
	}
	if err := json.Unmarshal(raw, &jws); err != nil {
		t.Fatalf("unmarshaling JWS: %v", err)
	}
	protected, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		t.Fatalf("decoding protected header: %v", err)
	}

	var head struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(protected, &head); err != nil {
		t.Fatalf("unmarshaling protected header: %v", err)
	}
	if head.Nonce != "" {
		t.Fatalf("inner JWS nonce = %q; want omitted/empty", head.Nonce)
	}
}
