package main

// The scheme's rules live HERE and only here. The web form, the citizen's assistant and the officer's
// assistant all call these same functions, so an assistant can never get anyone what the counter would refuse.

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const (
	MinAge        = 60
	MaxAge        = 110
	MonthlyAmount = 250
	SLADays       = 15
)

var Blocks = []string{"Sonari", "Rajapara", "Dhemaji Pathar", "Borgaon", "Namti", "Khelua"}
var ifscRe = regexp.MustCompile(`^[A-Z]{4}0[A-Z0-9]{6}$`)
var digitsRe = regexp.MustCompile(`^[0-9]{9,18}$`)
var mobileRe = regexp.MustCompile(`^[6-9][0-9]{9}$`)
var villageRe = regexp.MustCompile(`^[\p{L}\p{M}0-9 .,'\-/()]{2,100}$`)

type Input struct {
	Name, DOB, Gender, Marital, Husband, Village, Block, Account, IFSC string
}

func windowCloses() time.Time {
	t, err := time.ParseInLocation("2006-01-02", getenv("WINDOW_CLOSES", "2027-03-31"), IST)
	if err != nil {
		return time.Date(2027, 3, 31, 23, 59, 0, 0, IST)
	}
	return t.Add(24*time.Hour - time.Minute)
}

func parseDOB(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if m := regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})$`).FindStringSubmatch(s); m != nil {
		s = m[3] + "/" + m[2] + "/" + m[1]
	}
	return time.ParseInLocation("02/01/2006", s, IST)
}

func ageOn(dob, ref time.Time) int {
	y := ref.Year() - dob.Year()
	if ref.Month() < dob.Month() || (ref.Month() == dob.Month() && ref.Day() < dob.Day()) {
		y--
	}
	return y
}

func inList(v string, l []string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func okName(s string) bool {
	n := 0
	for _, r := range s {
		if !(unicode.IsLetter(r) || unicode.IsMark(r) || r == ' ' || r == '.' || r == '\'' || r == '-') {
			return false
		}
		n++
	}
	return n >= 2 && n <= 80
}

// Normalise trims and canonicalises, then Validate returns the plain-language problems (empty = valid).
func (in *Input) Normalise() {
	t := strings.TrimSpace
	in.Name, in.Village, in.Husband = strings.Join(strings.Fields(in.Name), " "), strings.Join(strings.Fields(in.Village), " "), strings.Join(strings.Fields(in.Husband), " ")
	in.Account, in.IFSC = strings.ReplaceAll(t(in.Account), " ", ""), strings.ToUpper(strings.ReplaceAll(t(in.IFSC), " ", ""))
	in.Gender, in.Marital, in.Block = t(in.Gender), t(in.Marital), t(in.Block)
	if d, err := parseDOB(in.DOB); err == nil {
		in.DOB = d.Format("02/01/2006")
	}
	if in.Marital != "Widowed" {
		in.Husband = ""
	}
}

func Validate(in Input, t time.Time) []string {
	var e []string
	if !okName(in.Name) {
		e = append(e, "name must be 2-80 letters (any script), spaces, . ' -")
	}
	dob, err := parseDOB(in.DOB)
	switch {
	case err != nil:
		e = append(e, "date of birth must be DD/MM/YYYY")
	case dob.After(t):
		e = append(e, "date of birth cannot be in the future")
	default:
		age := ageOn(dob, t)
		if age > MaxAge {
			e = append(e, "date of birth looks wrong (older than 110 years)")
		} else if age < MinAge {
			e = append(e, fmt.Sprintf("the applicant must be %d or older on the day of application (age today: %d; turns %d on %s)", MinAge, age, MinAge, dob.AddDate(MinAge, 0, 0).Format("02/01/2006")))
		}
	}
	if !villageRe.MatchString(in.Village) {
		e = append(e, "village must be 2-100 characters: letters, digits, spaces and . , ' - / ( )")
	}
	if !inList(in.Block, Blocks) {
		e = append(e, "block must be one of: "+strings.Join(Blocks, ", "))
	}
	if !digitsRe.MatchString(in.Account) {
		e = append(e, "bank account must be 9 to 18 digits (0-9)")
	}
	if in.IFSC != "" && !ifscRe.MatchString(in.IFSC) {
		e = append(e, "IFSC must be 11 characters, e.g. SBIN0003077")
	}
	if in.Gender != "" && !inList(in.Gender, []string{"Male", "Female", "Other"}) {
		e = append(e, "gender must be Male, Female or Other")
	}
	if in.Marital != "" && !inList(in.Marital, []string{"Married", "Unmarried", "Widowed"}) {
		e = append(e, "marital status must be Married, Unmarried or Widowed")
	}
	if in.Husband != "" && !okName(in.Husband) {
		e = append(e, "late husband's name must be letters only")
	}
	if t.After(windowCloses()) {
		e = append(e, "the application window has closed")
	}
	return e
}

func live(a *App) bool {
	return a.Status == "PENDING" || a.Status == "APPROVED" || a.Status == "DEEMED_APPROVED"
}

type SubmitResult struct {
	Result string // created | invalid | duplicate
	Errors []string
	App    *App
}

// submit is the ONE place an application is created. s.mu must be held.
func (s *Store) submit(mobile string, in Input, proofPath, via, actor string) SubmitResult {
	in.Normalise()
	if !mobileRe.MatchString(mobile) {
		return SubmitResult{Result: "invalid", Errors: []string{"mobile must be 10 digits"}}
	}
	errs := Validate(in, now())
	if proofPath == "" {
		errs = append(errs, "an age-proof document (birth certificate, school leaving certificate or Voter ID) is required")
	}
	if len(errs) > 0 {
		return SubmitResult{Result: "invalid", Errors: errs}
	}
	for _, a := range s.Apps { // one live application per mobile (the lock makes this race-free)
		if a.Mobile == mobile && live(a) {
			return SubmitResult{Result: "duplicate", App: a}
		}
	}
	no := ""
	for {
		r := randBytes(4)
		n := (uint32(r[0])<<24 | uint32(r[1])<<16 | uint32(r[2])<<8 | uint32(r[3])) % 1000000
		no = fmt.Sprintf("SSP%s%06d", now().Format("06"), n)
		if _, dup := s.Apps[no]; !dup {
			break
		}
	}
	a := &App{No: no, Mobile: mobile, Name: in.Name, DOB: in.DOB, Gender: in.Gender, Marital: in.Marital, Husband: in.Husband,
		Village: in.Village, Block: in.Block, Account: in.Account, IFSC: in.IFSC, Proof: proofPath, Status: "PENDING",
		SubmittedAt: now(), Via: via}
	a.Audit = append(a.Audit, Audit{now(), "SUBMIT", actor, "via " + via})
	s.Apps[no] = a
	s.sms(mobile, fmt.Sprintf("Sewa Setu: application %s received. Track it at the status page with your mobile number and date of birth (DDMMYYYY).", no))
	s.save()
	s.publish("submit", fmt.Sprintf("New application %s from %s (%s) via %s", no, in.Village, in.Block, via))
	return SubmitResult{Result: "created", App: a}
}

func (s *Store) withdraw(mobile, no, via string) (bool, string) {
	a := s.Apps[strings.ToUpper(strings.TrimSpace(no))]
	if a == nil || a.Mobile != mobile {
		return false, "no such application on this mobile number"
	}
	if a.Status != "PENDING" {
		return false, "only a PENDING application can be withdrawn (this one is " + a.Status + ")"
	}
	a.Status = "WITHDRAWN"
	a.Audit = append(a.Audit, Audit{now(), "WITHDRAWN", "applicant:" + mobile, "via " + via})
	s.save()
	s.publish("withdraw", "Application "+a.No+" withdrawn by the applicant")
	return true, ""
}

func (a *App) ageAtSubmission() int {
	d, err := parseDOB(a.DOB)
	if err != nil {
		return -1
	}
	return ageOn(d, a.SubmittedAt)
}

type Flag struct {
	Code     string `json:"code"`
	Blocking bool   `json:"blocking"`
	Detail   string `json:"detail"`
}

func (s *Store) flags(a *App) []Flag {
	f := []Flag{}
	if a.ageAtSubmission() < MinAge {
		f = append(f, Flag{"UNDER_AGE_AT_SUBMISSION", true, fmt.Sprintf("applicant was %d on the day of application; the scheme requires %d. Approval is not allowed; reject instead.", a.ageAtSubmission(), MinAge)})
	}
	if a.Status == "PENDING" {
		days := autoApprovalDate(a).Sub(now()).Hours() / 24
		if days < 0 {
			f = append(f, Flag{"SLA_OVERDUE", false, "past the 15-day limit"})
		} else if days <= 3 {
			f = append(f, Flag{"SLA_WITHIN_3_DAYS", false, "automatic approval within 3 days if nobody decides"})
		}
	}
	if a.Proof == "" {
		f = append(f, Flag{"NO_AGE_PROOF_ON_FILE", false, "legacy record without a stored age-proof document"})
	}
	for _, o := range s.Apps {
		if o.No != a.No && o.Account == a.Account && o.Mobile != a.Mobile && live(o) {
			f = append(f, Flag{"SHARED_BANK_ACCOUNT", false, "the same bank account is on another applicant's application " + o.No})
			break
		}
	}
	return f
}

func autoApprovalDate(a *App) time.Time { return a.SubmittedAt.AddDate(0, 0, SLADays) }

// decide records an officer's decision. s.mu must be held. via is the channel ("web" or "assistant: <client>").
func (s *Store) decide(no, decision, reason, officer, via string) (string, string) {
	a := s.Apps[strings.ToUpper(strings.TrimSpace(no))]
	if a == nil {
		return "error", "no such application"
	}
	reason = strings.TrimSpace(reason)
	if n := len([]rune(reason)); n < 8 || n > 400 {
		return "error", "a reason of 8-400 characters is required: it is recorded against the officer's name"
	}
	if decision != "APPROVED" && decision != "REJECTED" {
		return "error", "decision must be APPROVED or REJECTED"
	}
	if a.Status != "PENDING" {
		return "not_pending", fmt.Sprintf("application %s is already %s", a.No, a.Status)
	}
	if decision == "APPROVED" && a.ageAtSubmission() < MinAge {
		return "blocked", "UNDER_AGE_AT_SUBMISSION: the applicant was under 60 on the day of application; the counter would refuse this, so approval is not allowed"
	}
	t := now()
	a.Status, a.DecidedAt, a.DecidedBy, a.Reason = decision, &t, "officer:"+officer, reason
	a.Audit = append(a.Audit, Audit{t, decision, "officer:" + officer, "[via " + via + "] " + reason})
	txt := "Sewa Setu: your pension application " + a.No + " is approved."
	if decision == "REJECTED" {
		txt = "Sewa Setu: your pension application " + a.No + " was not approved. Reason: " + reason
	}
	s.sms(a.Mobile, txt)
	s.save()
	s.publish("decision", fmt.Sprintf("%s %s by officer %s", a.No, decision, officer))
	return "recorded", ""
}

// runDeemedApproval: the nightly job (here hourly + on demand). Anyone under 60 on the day is HELD, never deemed approved.
func (s *Store) runDeemedApproval() (approved, held int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := now().AddDate(0, 0, -SLADays)
	for _, a := range s.Apps {
		if a.Status != "PENDING" || !a.SubmittedAt.Before(cutoff) {
			continue
		}
		if a.ageAtSubmission() >= MinAge {
			t := now()
			a.Status, a.DecidedAt, a.DecidedBy = "DEEMED_APPROVED", &t, "RTPS-AUTO"
			a.Audit = append(a.Audit, Audit{t, "DEEMED_APPROVED", "system:rtps-job", "not processed within SLA"})
			s.sms(a.Mobile, "Sewa Setu: your pension application "+a.No+" stands approved under the RTPS Act.")
			approved++
			s.publish("deemed", a.No+" deemed approved after 15 days")
		} else {
			heldBefore := false
			for _, e := range a.Audit {
				heldBefore = heldBefore || e.Action == "SLA_HELD"
			}
			if !heldBefore {
				a.Audit = append(a.Audit, Audit{now(), "SLA_HELD", "system:rtps-job", "past SLA but under 60 on day of application: not deemed approved; needs an officer decision"})
				held++
			}
		}
	}
	if approved+held > 0 {
		s.save()
	}
	return
}
