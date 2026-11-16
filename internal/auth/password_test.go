package auth

import (
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestHashVerify(t *testing.T) {
	h, err := Hash("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=1,p=2$") || !IsHash(h) {
		t.Fatalf("unexpected PHC string %q", h)
	}
	if err := Verify(h, "correct horse"); err != nil {
		t.Fatalf("right password: %v", err)
	}
	if err := Verify(h, "wrong horse!"); err != ErrMismatch {
		t.Fatalf("wrong password: %v", err)
	}
	h2, _ := Hash("correct horse")
	if h == h2 {
		t.Fatal("two hashes of the same password share a salt")
	}
}

// A hash produced by alexedwards/argon2id DefaultParams (what ngm uses) must
// verify, so a user record can move between the two tools.
func TestVerifyForeignArgon2id(t *testing.T) {
	const h = "$argon2id$v=19$m=65536,t=1,p=4$TE4nr6RtBPCLgW9WDIAe5A$wW6xudtUHHNb3PkHJBOuglCVULg7PwnT73qbWPVPv/A"
	if err := Verify(h, "pa$$word"); err != nil {
		t.Fatalf("alexedwards hash: %v", err)
	}
	if err := Verify(h, "pa$$wordX"); err != ErrMismatch {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestVerifyBcrypt(t *testing.T) {
	b, _ := bcrypt.GenerateFromPassword([]byte("s3cretpass"), bcrypt.MinCost)
	if err := Verify(string(b), "s3cretpass"); err != nil {
		t.Fatal(err)
	}
	if err := Verify(string(b), "nope-nope"); err != ErrMismatch {
		t.Fatal(err)
	}
}

func TestPolicyAndMalformed(t *testing.T) {
	if _, err := Hash("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if _, err := Hash(strings.Repeat("x", 73)); err == nil {
		t.Fatal("over-long password accepted")
	}
	for _, bad := range []string{
		"", "plain", "$argon2id$v=19$m=65536,t=1,p=2$c2FsdA$",
		"$argon2id$v=19$m=99999999,t=1,p=2$MDEyMzQ1Njc4OWFiY2RlZg$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY",
	} {
		if err := Verify(bad, "whatever1"); err == nil || err == ErrMismatch {
			t.Fatalf("malformed %q: want a format error, got %v", bad, err)
		}
		if IsHash(bad) {
			t.Fatalf("IsHash(%q) = true", bad)
		}
	}
}

// Extra PHC parameters must be refused, not parsed and silently ignored.
func TestParseIsExact(t *testing.T) {
	h, _ := Hash("correct horse")
	parts := strings.Split(h, "$")
	parts[3] += ",keyid=abc"
	if IsHash(strings.Join(parts, "$")) {
		t.Fatal("trailing PHC parameter accepted")
	}
}

func TestBusyWhenSlotsTaken(t *testing.T) {
	for i := 0; i < maxConcurrentHashes; i++ {
		hashSem <- struct{}{}
	}
	defer func() {
		for i := 0; i < maxConcurrentHashes; i++ {
			<-hashSem
		}
	}()
	old := hashWait
	hashWait = 20 * time.Millisecond
	defer func() { hashWait = old }()
	if _, err := Hash("correct horse"); err != ErrBusy {
		t.Fatalf("Hash: want ErrBusy, got %v", err)
	}
	b, _ := bcrypt.GenerateFromPassword([]byte("s3cretpass"), bcrypt.MinCost)
	if err := Verify(string(b), "s3cretpass"); err != nil {
		t.Fatalf("bcrypt doesn't use the argon2 slots: %v", err)
	}
	if err := Burn("x"); err != ErrBusy {
		t.Fatalf("Burn: want ErrBusy, got %v", err)
	}
}
