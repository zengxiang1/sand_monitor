package panel

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInvalidLoginUsernames(t *testing.T) {
	f := setup(t)
	form, cookie := f.loginForm(t)
	form.Set("password", "wrong")
	form.Set("user", "absent")
	reference := f.submitLogin(form, cookie, "192.0.2.1", nil)
	if reference.Code != 401 {
		t.Fatal(reference.Code)
	}
	for i, name := range []string{"", "-invalid", "two words", "<script>", strings.Repeat("a", 8000)} {
		form.Set("user", name)
		w := f.submitLogin(form, cookie, fmt.Sprintf("192.0.2.%d", i+2), nil)
		if w.Code != reference.Code || w.Body.String() != reference.Body.String() {
			t.Fatal("invalid username response differs", w.Code)
		}
		if _, ok := f.h.users[name]; ok {
			t.Fatal("invalid username retained")
		}
	}
	if len(f.h.users) != 1 || f.h.users["absent"].count != 1 {
		t.Fatal("invalid usernames affected per-user limiter")
	}
}
func TestIPLimitedLoginSkipsWork(t *testing.T) {
	f := setup(t)
	form, cookie := f.loginForm(t)
	f.h.ips["192.0.2.1"] = failures{count: 5, since: f.now.Unix()}
	f.h.users["admin"] = failures{count: 7, since: f.now.Unix()}
	before := f.h.users["admin"]
	if err := f.s.Close(); err != nil {
		t.Fatal(err)
	}
	passwordHashes <- struct{}{}
	passwordHashes <- struct{}{}
	defer func() { <-passwordHashes; <-passwordHashes }()
	for _, user := range []string{"admin", "new-user"} {
		form.Set("user", user)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		r := httptest.NewRequest("POST", "https://panel.example.com/login", strings.NewReader(form.Encode())).WithContext(ctx)
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://panel.example.com")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		f.h.ServeHTTP(w, r)
		if w.Code != 429 || !strings.Contains(w.Body.String(), loginError) {
			t.Fatal("limited login touched database or waited for hash", w.Code, w.Body)
		}
	}
	if len(f.h.users) != 1 || f.h.users["admin"] != before || f.h.ips["192.0.2.1"].count != 5 {
		t.Fatal("limited request changed counters")
	}
}
func TestLoginLimiterCapacity(t *testing.T) {
	for _, limiter := range []string{"ip", "user"} {
		t.Run(limiter, func(t *testing.T) {
			f := setup(t)
			form, cookie := f.loginForm(t)
			entries := f.h.ips
			if limiter == "user" {
				entries = f.h.users
			}
			for i := range loginLimitEntries {
				entries[fmt.Sprintf("entry-%d", i)] = failures{since: f.now.Unix()}
			}
			if err := f.s.Close(); err != nil {
				t.Fatal(err)
			}
			w := f.submitLogin(form, cookie, "192.0.2.1", nil)
			if w.Code != 429 || !strings.Contains(w.Body.String(), loginError) {
				t.Fatal(w.Code, w.Body)
			}
			if len(entries) != loginLimitEntries {
				t.Fatal("map grew beyond cap")
			}
			if _, ok := f.h.ips["192.0.2.1"]; ok {
				t.Fatal("new IP admitted while full")
			}
			if _, ok := f.h.users["admin"]; ok {
				t.Fatal("new user admitted while full")
			}
		})
		t.Run(limiter+" prunes expired", func(t *testing.T) {
			f := setup(t)
			form, cookie := f.loginForm(t)
			form.Set("password", "wrong")
			entries := f.h.ips
			if limiter == "user" {
				entries = f.h.users
			}
			for i := range loginLimitEntries {
				entries[fmt.Sprintf("entry-%d", i)] = failures{since: f.now.Unix()}
			}
			entries["entry-0"] = failures{count: 5, since: f.now.Unix() - 900}
			w := f.submitLogin(form, cookie, "192.0.2.1", nil)
			if w.Code != 401 {
				t.Fatal("expired entries were not pruned", w.Code, w.Body)
			}
			if len(entries) != loginLimitEntries {
				t.Fatal("capacity not reused")
			}
			if _, ok := entries["entry-0"]; ok {
				t.Fatal("expired entry retained")
			}
		})
	}
}
func TestPasswordHashWaitCancellation(t *testing.T) {
	f := setup(t)
	form, cookie := f.loginForm(t)
	passwordHashes <- struct{}{}
	passwordHashes <- struct{}{}
	defer func() { <-passwordHashes; <-passwordHashes }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest("POST", "https://panel.example.com/login", strings.NewReader(form.Encode())).WithContext(ctx)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://panel.example.com")
	r.AddCookie(cookie)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); f.h.ServeHTTP(w, r); done <- w }()
	cancel()
	select {
	case w := <-done:
		if w.Code != 408 {
			t.Fatal("canceled hash waiter continued", w.Code, w.Body)
		}
	case <-time.After(time.Second):
		t.Fatal("hash waiter ignored request cancellation")
	}
	if cap(passwordHashes) != 2 || len(passwordHashes) != 2 {
		t.Fatal("hash concurrency budget changed")
	}
}
