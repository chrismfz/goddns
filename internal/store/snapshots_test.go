package store

import "testing"

func TestSnapshots(t *testing.T) {
	st, err := Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	if _, ok, err := st.SnapshotLatest("myip.gr"); err != nil || ok {
		t.Fatalf("expected no snapshot yet: ok=%v err=%v", ok, err)
	}

	// keep=2 must prune to the newest two per zone.
	for i, serial := range []uint32{1, 2, 3} {
		if _, err := st.SnapshotPut("myip.gr.", serial, "content"+string(rune('a'+i)), 2); err != nil {
			t.Fatal(err)
		}
	}

	// case- and trailing-dot-insensitive lookup.
	latest, ok, err := st.SnapshotLatest("MYIP.GR")
	if err != nil || !ok || latest.Serial != 3 {
		t.Fatalf("latest = %+v ok=%v err=%v", latest, ok, err)
	}

	list, err := st.SnapshotList("myip.gr", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 rows after prune(keep=2), got %d", len(list))
	}
	if list[0].Serial != 3 || list[1].Serial != 2 {
		t.Fatalf("expected newest-first [3 2], got [%d %d]", list[0].Serial, list[1].Serial)
	}

	// content is fetched by id (list omits it).
	full, ok, err := st.SnapshotByID(latest.ID)
	if err != nil || !ok || full.Content != "contentc" {
		t.Fatalf("content = %q ok=%v err=%v", full.Content, ok, err)
	}
}
