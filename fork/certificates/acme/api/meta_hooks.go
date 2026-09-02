package api

import (
	"crypto/x509"
	"net/http"
)

// RequestMetaHook lets the enclosing binary observe ACME API requests
// (client IP, kind, detail, and the CSR or cert serial when present).
// The smallstep fork cannot import the proxy's packages directly, so the
// enclosing binary wires this in via init(). It is safe to leave nil.
//
// kind is one of "new-order", "finalize", "revoke".
var RequestMetaHook func(r *http.Request, kind, detail string, csr *x509.CertificateRequest, serial string)

// RequestACLHook, when set, gates every ACME API request: returning false
// rejects the request with 403. It lets the enclosing binary enforce a
// file-based client allow-list without touching this module. Safe to leave
// nil (all requests allowed).
var RequestACLHook func(r *http.Request) bool
