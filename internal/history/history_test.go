package history

import "testing"

func TestDiff(t *testing.T) {
	old := "a.myip.gr. 60 IN A 1.1.1.1\nb.myip.gr. 60 IN A 2.2.2.2\nmyip.gr. 60 IN MX 10 m.myip.gr.\n"
	neu := "a.myip.gr. 60 IN A 1.1.1.1\nb.myip.gr. 60 IN A 3.3.3.3\nmyip.gr. 60 IN MX 10 m.myip.gr.\n"

	added, removed := Diff(old, neu)
	if len(added) != 1 || added[0] != "b.myip.gr. 60 IN A 3.3.3.3" {
		t.Fatalf("added = %v", added)
	}
	if len(removed) != 1 || removed[0] != "b.myip.gr. 60 IN A 2.2.2.2" {
		t.Fatalf("removed = %v", removed)
	}

	if a, r := Diff(old, old); len(a) != 0 || len(r) != 0 {
		t.Fatalf("identical snapshots should diff empty: +%v -%v", a, r)
	}

	// blank lines are ignored, not reported as changes
	if a, r := Diff("x\n\n", "x\n"); len(a) != 0 || len(r) != 0 {
		t.Fatalf("blank-line noise leaked: +%v -%v", a, r)
	}
}
