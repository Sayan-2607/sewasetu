package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"sync"
	"time"
)

var IST = func() *time.Location {
	if l, err := time.LoadLocation("Asia/Kolkata"); err == nil {
		return l
	}
	return time.FixedZone("IST", 5*3600+1800)
}()

func now() time.Time { return time.Now().In(IST) }

type Audit struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	Actor  string    `json:"actor"`
	Note   string    `json:"note"`
}

type App struct {
	No          string     `json:"no"`
	Mobile      string     `json:"mobile"`
	Name        string     `json:"name"`
	DOB         string     `json:"dob"` // DD/MM/YYYY
	Gender      string     `json:"gender"`
	Marital     string     `json:"marital"`
	Husband     string     `json:"husband"`
	Village     string     `json:"village"`
	Block       string     `json:"block"`
	Account     string     `json:"account"`
	IFSC        string     `json:"ifsc"`
	Proof       string     `json:"proof"` // stored file path ("" = legacy record)
	Status      string     `json:"status"`
	SubmittedAt time.Time  `json:"submitted_at"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	DecidedBy   string     `json:"decided_by,omitempty"`
	Reason      string     `json:"reason,omitempty"`
	Via         string     `json:"via"`
	Audit       []Audit    `json:"audit"`
}

type Msg struct {
	At   time.Time `json:"at"`
	To   string    `json:"to"`
	Text string    `json:"text"`
	ID   int       `json:"id"`
}

type Store struct {
	mu       sync.Mutex
	path     string
	Apps     map[string]*App `json:"apps"`
	Msgs     []Msg           `json:"msgs"`
	Evals    []*EvalRun      `json:"evals"`
	seq      int
	otps     map[string]*otp
	otpReq   map[string][]time.Time
	previews map[string]*preview
	uploads  map[string]*upload
	clients  map[string]*client
	codes    map[string]*authCode
	tokens   map[string]*token
	refresh  map[string]*token
	sessions map[string]*session
	fails    map[string][]time.Time
	authz    map[string]*authzReq
	subs     map[chan string]bool
	secret   []byte
}

func NewStore(path string) *Store {
	s := &Store{path: path, Apps: map[string]*App{}, otps: map[string]*otp{}, otpReq: map[string][]time.Time{},
		previews: map[string]*preview{}, uploads: map[string]*upload{}, clients: map[string]*client{},
		codes: map[string]*authCode{}, tokens: map[string]*token{}, refresh: map[string]*token{},
		sessions: map[string]*session{}, fails: map[string][]time.Time{}, authz: map[string]*authzReq{}, subs: map[chan string]bool{}, secret: randBytes(32)}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, s)
		for _, m := range s.Msgs {
			if m.ID > s.seq {
				s.seq = m.ID
			}
		}
	}
	return s
}

func randBytes(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }
func randHex(n int) string   { return hex.EncodeToString(randBytes(n)) }

const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randCode(n int) string {
	b := randBytes(n)
	out := make([]byte, n)
	for i := range b {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out)
}

// save must be called with s.mu held.
func (s *Store) save() {
	b, err := json.MarshalIndent(map[string]any{"apps": s.Apps, "msgs": s.Msgs, "evals": s.Evals}, "", " ")
	if err == nil {
		tmp := s.path + ".tmp"
		if os.WriteFile(tmp, b, 0o644) == nil {
			_ = os.Rename(tmp, s.path)
		}
	}
}

// ---- live event feed (Server-Sent Events) ----
func (s *Store) publish(kind, text string) { // call with or without lock: uses its own channel set copy
	payload, _ := json.Marshal(map[string]any{"kind": kind, "text": text, "at": now().Format("15:04:05"), "counts": s.countsLocked()})
	for ch := range s.subs {
		select {
		case ch <- string(payload):
		default:
		}
	}
}

func (s *Store) countsLocked() map[string]int {
	c := map[string]int{"PENDING": 0, "APPROVED": 0, "DEEMED_APPROVED": 0, "REJECTED": 0, "WITHDRAWN": 0}
	for _, a := range s.Apps {
		c[a.Status]++
	}
	return c
}

func (s *Store) sms(to, text string) { // lock held
	s.seq++
	s.Msgs = append(s.Msgs, Msg{At: now(), To: to, Text: text, ID: s.seq})
	if len(s.Msgs) > 500 {
		s.Msgs = s.Msgs[len(s.Msgs)-500:]
	}
}

func sortedApps(m map[string]*App, less func(a, b *App) bool) []*App {
	out := make([]*App, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return less(out[i], out[j]) })
	return out
}
