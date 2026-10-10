package main

// The portal is also the OAuth 2.1 authorization server (RFC 8414, 7591 dynamic registration, PKCE S256,
// RFC 8707 resource indicators, RFC 9728 protected-resource metadata). Tokens are opaque and bound to ONE
// resource (audience) and one session with an absolute end, so sign-out takes effect on the very next call.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type otp struct {
	code  string
	exp   time.Time
	tries int
}
type client struct {
	ID       string
	Name     string
	Redirect []string
}
type authzReq struct {
	client                          *client
	redirect, state, challenge, res string
	role, subject                   string
	ok                              bool
	exp                             time.Time
}
type authCode struct {
	req *authzReq
	exp time.Time
}
type session struct {
	SID, Role, Subject, Client string
	Ends                       time.Time
	Revoked                    bool
}
type token struct {
	Access, Role, Subject, Aud, SID, Client string
	Exp                                     time.Time
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func baseURL() string {
	return strings.TrimRight(getenv("PUBLIC_BASE_URL", "http://localhost:8080"), "/")
}
func resourceURL(role string) string { return baseURL() + "/mcp/" + role }

var sessionLen = map[string]time.Duration{"citizen": 2 * time.Hour, "officer": 8 * time.Hour}
var accessLen = map[string]time.Duration{"citizen": 20 * time.Minute, "officer": 30 * time.Minute}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	h, _, _ := net.SplitHostPort(r.RemoteAddr)
	return h
}

// ---- throttling and OTP (s.mu NOT held by callers) ----
func (s *Store) throttled(key string, max int, window time.Duration) bool {
	cut := time.Now().Add(-window)
	var keep []time.Time
	for _, t := range s.fails[key] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	s.fails[key] = keep
	return len(keep) >= max
}
func (s *Store) failed(key string) { s.fails[key] = append(s.fails[key], time.Now()) }

func (s *Store) issueOTP(mobile string) bool { // lock held
	cut := time.Now().Add(-time.Hour)
	var keep []time.Time
	for _, t := range s.otpReq[mobile] {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= 20 {
		return false
	}
	s.otpReq[mobile] = append(keep, time.Now())
	b := randBytes(4)
	code := fmt.Sprintf("%06d", (uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]))%1000000)
	s.otps[mobile] = &otp{code: code, exp: time.Now().Add(5 * time.Minute)}
	s.sms(mobile, "Your Sewa Setu OTP is "+code+". Valid for 5 minutes.")
	s.save()
	return true
}

func (s *Store) checkOTP(mobile, code string) string { // lock held; single use, 5 wrong guesses lock it
	o := s.otps[mobile]
	if o == nil || time.Now().After(o.exp) {
		return "expired"
	}
	if o.tries >= 5 {
		return "locked"
	}
	if strings.TrimSpace(code) != o.code {
		o.tries++
		return "wrong"
	}
	delete(s.otps, mobile)
	return "ok"
}

// ---- metadata ----
func (a *Server) metadata(w http.ResponseWriter, r *http.Request) {
	b := baseURL()
	writeJSON(w, 200, map[string]any{"issuer": b, "authorization_endpoint": b + "/oauth/authorize", "token_endpoint": b + "/oauth/token",
		"registration_endpoint": b + "/oauth/register", "revocation_endpoint": b + "/oauth/revoke",
		"response_types_supported": []string{"code"}, "grant_types_supported": []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported": []string{"S256"}, "token_endpoint_auth_methods_supported": []string{"none"},
		"scopes_supported": []string{"citizen", "officer"}})
}

func (a *Server) prm(role string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"resource": resourceURL(role), "authorization_servers": []string{baseURL()},
			"scopes_supported": []string{role}, "bearer_methods_supported": []string{"header"},
			"resource_name": "Sewa Setu " + role + " assistant"})
	}
}

func (a *Server) register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in) != nil || len(in.RedirectURIs) == 0 {
		writeJSON(w, 400, map[string]string{"error": "invalid_client_metadata"})
		return
	}
	for _, u := range in.RedirectURIs {
		p, err := url.Parse(u)
		if err != nil || (p.Scheme != "https" && !(p.Scheme == "http" && isLoopback(p.Hostname()))) {
			writeJSON(w, 400, map[string]string{"error": "invalid_redirect_uri", "error_description": "https, or http on a loopback address"})
			return
		}
	}
	c := &client{ID: "c_" + randHex(10), Name: in.ClientName, Redirect: in.RedirectURIs}
	a.s.mu.Lock()
	a.s.clients[c.ID] = c
	a.s.mu.Unlock()
	writeJSON(w, 201, map[string]any{"client_id": c.ID, "client_name": c.Name, "redirect_uris": c.Redirect,
		"token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}})
}

func isLoopback(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || h == "[::1]"
}

func redirectOK(registered []string, uri string) bool {
	for _, r := range registered {
		if r == uri {
			return true
		}
	}
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" || !isLoopback(u.Hostname()) {
		return false
	}
	for _, r := range registered { // RFC 8252: loopback redirects may use any port
		p, err := url.Parse(r)
		if err == nil && p.Scheme == "http" && p.Hostname() == u.Hostname() && p.Path == u.Path {
			return true
		}
	}
	return false
}

func (a *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a.s.mu.Lock()
	c := a.s.clients[q.Get("client_id")]
	a.s.mu.Unlock()
	if c == nil || !redirectOK(c.Redirect, q.Get("redirect_uri")) {
		http.Error(w, "unknown client or redirect_uri", 400)
		return
	}
	fail := func(e string) {
		u, _ := url.Parse(q.Get("redirect_uri"))
		v := u.Query()
		v.Set("error", e)
		v.Set("state", q.Get("state"))
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), 302)
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		fail("invalid_request")
		return
	}
	role, res := q.Get("scope"), q.Get("resource")
	if res != "" {
		switch strings.TrimRight(res, "/") {
		case resourceURL("citizen"):
			role = "citizen"
		case resourceURL("officer"):
			role = "officer"
		default:
			fail("invalid_target")
			return
		}
	}
	role = strings.Fields(role + " ")[0]
	if role != "citizen" && role != "officer" {
		fail("invalid_scope")
		return
	}
	rid := randHex(12)
	a.s.mu.Lock()
	a.s.authz[rid] = &authzReq{client: c, redirect: q.Get("redirect_uri"), state: q.Get("state"), challenge: q.Get("code_challenge"),
		res: resourceURL(role), role: role, exp: time.Now().Add(15 * time.Minute)}
	a.s.mu.Unlock()
	http.Redirect(w, r, "/oauth/login?rid="+rid, 302)
}

const loginCSS = `<style>body{font:17px/1.5 system-ui;background:#0b1020;color:#e8ecf8;display:grid;place-items:center;min-height:100vh;margin:0}
.c{background:#151c36;border:1px solid #2a3560;border-radius:16px;padding:28px;max-width:420px;width:calc(100% - 32px)}h1{font-size:22px;margin:0 0 6px}
input,button{font:inherit;width:100%;box-sizing:border-box;padding:14px;border-radius:10px;border:1px solid #3a4780;background:#0e1430;color:#fff;margin:8px 0}
button{background:linear-gradient(90deg,#ff9a3c,#ff5e7e);border:0;font-weight:700;cursor:pointer}.m{color:#9fb0e8;font-size:14px}.e{color:#ff8a8a}a{color:#ffb86b}</style>`

func (a *Server) login(w http.ResponseWriter, r *http.Request) {
	rid := r.FormValue("rid")
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	req := a.s.authz[rid]
	if req == nil || time.Now().After(req.exp) {
		http.Error(w, "this sign-in link has expired; start again from your assistant", 400)
		return
	}
	page := func(body, errm string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		e := ""
		if errm != "" {
			e = `<p class="e">` + html.EscapeString(errm) + `</p>`
		}
		fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Sewa Setu sign-in</title>%s<div class=c><h1>Sewa Setu sign-in</h1><p class=m>%s wants to act for you as <b>%s</b>. It never sees your OTP or password.</p>%s%s</div>`,
			loginCSS, html.EscapeString(req.client.Name), req.role, e, body)
	}
	ip := clientIP(r)
	if req.role == "officer" {
		form := `<form method=post><input type=hidden name=rid value="` + rid + `"><input name=username placeholder="officer username" value="admin" autocomplete=username><input name=password type=password placeholder="password" autocomplete=current-password autofocus><button>Sign in</button></form>`
		if r.Method == "POST" {
			user := strings.TrimSpace(r.FormValue("username"))
			key := "off|" + ip + "|" + user
			if a.s.throttled(key, 5, 10*time.Minute) {
				page(form, "Too many wrong attempts. Wait ten minutes.")
				return
			}
			if user == "" || r.FormValue("password") != a.adminPassword || user != "admin" {
				a.s.failed(key)
				page(form, "Wrong username or password.")
				return
			}
			req.subject, req.ok = user, true
			http.Redirect(w, r, "/oauth/consent?rid="+rid, 302)
			return
		}
		page(form, "")
		return
	}
	// citizen: mobile -> OTP
	if r.Method == "POST" && r.FormValue("otp") != "" {
		mobile := req.subject
		key := "otp|" + ip + "|" + mobile
		if mobile == "" || a.s.throttled(key, 10, 10*time.Minute) {
			page("", "Please start again.")
			return
		}
		switch a.s.checkOTP(mobile, r.FormValue("otp")) {
		case "ok":
			req.ok = true
			http.Redirect(w, r, "/oauth/consent?rid="+rid, 302)
		case "wrong":
			a.s.failed(key)
			page(otpForm(rid), "That OTP is not right.")
		default:
			page(mobileForm(rid), "That OTP expired or was locked. Ask for a new one.")
		}
		return
	}
	if r.Method == "POST" && r.FormValue("mobile") != "" {
		m := strings.TrimSpace(r.FormValue("mobile"))
		if !mobileRe.MatchString(m) {
			page(mobileForm(rid), "Enter a 10-digit mobile number.")
			return
		}
		if !a.s.issueOTP(m) {
			page(mobileForm(rid), "Too many OTP requests for this number. Try again in an hour.")
			return
		}
		req.subject, req.ok = m, false
		page(otpForm(rid), "")
		return
	}
	page(mobileForm(rid), "")
}

func mobileForm(rid string) string {
	return `<form method=post><input type=hidden name=rid value="` + rid + `"><input name=mobile inputmode=numeric maxlength=10 placeholder="your 10-digit mobile number" autofocus><button>Send OTP</button></form><p class=m>Demo: the SMS appears at <a href="/inbox" target=_blank>/inbox</a>.</p>`
}
func otpForm(rid string) string {
	return `<form method=post><input type=hidden name=rid value="` + rid + `"><input name=otp inputmode=numeric maxlength=6 placeholder="6-digit OTP" autofocus><button>Verify</button></form><p class=m>Demo: read the OTP at <a href="/inbox" target=_blank>/inbox</a>.</p>`
}

func (a *Server) consent(w http.ResponseWriter, r *http.Request) {
	rid := r.FormValue("rid")
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	req := a.s.authz[rid]
	if req == nil || !req.ok || time.Now().After(req.exp) {
		http.Error(w, "sign-in expired", 400)
		return
	}
	if r.Method == "POST" {
		delete(a.s.authz, rid)
		u, _ := url.Parse(req.redirect)
		v := u.Query()
		v.Set("state", req.state)
		if r.FormValue("decision") != "allow" {
			v.Set("error", "access_denied")
		} else {
			code := randHex(16)
			a.s.codes[code] = &authCode{req: req, exp: time.Now().Add(2 * time.Minute)}
			v.Set("code", code)
		}
		u.RawQuery = v.Encode()
		http.Redirect(w, r, u.String(), 302)
		return
	}
	who := req.subject
	if req.role == "citizen" {
		who = "mobile " + who
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1">%s<div class=c><h1>Allow access?</h1><p class=m><b>%s</b> will act for <b>%s</b> (%s). The sign-in ends automatically after %s, and you can end it any time by asking the assistant to sign you out.</p><form method=post><input type=hidden name=rid value="%s"><button name=decision value=allow>Allow</button><button name=decision value=deny style="background:#333">Deny</button></form></div>`,
		loginCSS, html.EscapeString(req.client.Name), html.EscapeString(who), req.role, sessionLen[req.role], rid)
}

func (a *Server) tokenEP(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	bad := func(e string) { writeJSON(w, 400, map[string]string{"error": e}) }
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	issue := func(sess *session, aud, cid string) {
		acc := &token{Access: "sst_" + randHex(24), Role: sess.Role, Subject: sess.Subject, Aud: aud, SID: sess.SID, Client: cid,
			Exp: minTime(time.Now().Add(accessLen[sess.Role]), sess.Ends)}
		ref := &token{Access: "ssr_" + randHex(24), Role: sess.Role, Subject: sess.Subject, Aud: aud, SID: sess.SID, Client: cid, Exp: sess.Ends}
		a.s.tokens[acc.Access] = acc
		a.s.refresh[ref.Access] = ref
		writeJSON(w, 200, map[string]any{"access_token": acc.Access, "token_type": "Bearer", "expires_in": int(time.Until(acc.Exp).Seconds()),
			"refresh_token": ref.Access, "scope": sess.Role, "session_ends": sess.Ends.In(IST).Format(time.RFC3339)})
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		ac := a.s.codes[r.FormValue("code")]
		delete(a.s.codes, r.FormValue("code"))
		if ac == nil || time.Now().After(ac.exp) || ac.req.client.ID != r.FormValue("client_id") || ac.req.redirect != r.FormValue("redirect_uri") {
			bad("invalid_grant")
			return
		}
		h := sha256.Sum256([]byte(r.FormValue("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(h[:]) != ac.req.challenge {
			bad("invalid_grant")
			return
		}
		if res := strings.TrimRight(r.FormValue("resource"), "/"); res != "" && res != ac.req.res {
			bad("invalid_target")
			return
		}
		sess := &session{SID: randHex(10), Role: ac.req.role, Subject: ac.req.subject, Client: ac.req.client.Name, Ends: time.Now().Add(sessionLen[ac.req.role])}
		a.s.sessions[sess.SID] = sess
		issue(sess, ac.req.res, ac.req.client.ID)
	case "refresh_token":
		old := a.s.refresh[r.FormValue("refresh_token")]
		delete(a.s.refresh, r.FormValue("refresh_token"))
		if old == nil {
			bad("invalid_grant")
			return
		}
		sess := a.s.sessions[old.SID]
		if sess == nil || sess.Revoked || time.Now().After(sess.Ends) || old.Client != r.FormValue("client_id") {
			bad("invalid_grant")
			return
		}
		issue(sess, old.Aud, old.Client)
	default:
		bad("unsupported_grant_type")
	}
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// bearer returns the verified token for this role's endpoint, or an error string. s.mu NOT held.
func (a *Server) bearer(r *http.Request, role string) *token {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return nil
	}
	a.s.mu.Lock()
	defer a.s.mu.Unlock()
	t := a.s.tokens[strings.TrimPrefix(h, "Bearer ")]
	if t == nil || time.Now().After(t.Exp) || t.Aud != resourceURL(role) || t.Role != role {
		return nil
	}
	sess := a.s.sessions[t.SID]
	if sess == nil || sess.Revoked || time.Now().After(sess.Ends) {
		return nil
	}
	return t
}

func (s *Store) endSession(sid string) { // lock held
	if x := s.sessions[sid]; x != nil {
		x.Revoked = true
	}
	for k, t := range s.refresh {
		if t.SID == sid {
			delete(s.refresh, k)
		}
	}
}

func (a *Server) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	a.s.mu.Lock()
	if t := a.s.tokens[r.FormValue("token")]; t != nil {
		a.s.endSession(t.SID)
	}
	if t := a.s.refresh[r.FormValue("token")]; t != nil {
		a.s.endSession(t.SID)
	}
	a.s.mu.Unlock()
	w.WriteHeader(200)
}
