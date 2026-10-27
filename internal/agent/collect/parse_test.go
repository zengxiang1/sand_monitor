package collect

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, e := os.ReadFile("testdata/" + name)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
func TestProcFixtures(t *testing.T) {
	cpu, e := ParseCPU(fixture(t, "stat"))
	if e != nil || cpu != (CPU{620, 450}) {
		t.Fatalf("cpu %+v %v", cpu, e)
	}
	if CPUPercent(CPU{100, 50}, CPU{200, 100}) != 50 || CPUPercent(cpu, cpu) != 0 || CPUPercent(cpu, CPU{}) != 0 {
		t.Fatal("cpu delta")
	}
	mem, swap, e := ParseMem(fixture(t, "meminfo"))
	if e != nil || mem != ([2]float64{812, 2048}) || swap != ([2]float64{128, 512}) {
		t.Fatalf("memory %v %v %v", mem, swap, e)
	}
	load, e := ParseLoad(fixture(t, "loadavg"))
	if e != nil || load != ([3]float64{.21, .18, .12}) {
		t.Fatal(load, e)
	}
	up, e := ParseUptime(fixture(t, "uptime"))
	if e != nil || up != 864000.25 {
		t.Fatal(up, e)
	}
	net, e := ParseNet(fixture(t, "net_dev"))
	if e != nil || net != ([2]uint64{1532, 8841}) {
		t.Fatal(net, e)
	}
	if NetRate([2]uint64{100, 200}, [2]uint64{150, 400}, 5) != ([2]float64{10, 40}) || NetRate(net, [2]uint64{}, 5) != ([2]float64{}) || NetRate(net, net, 0) != ([2]float64{}) {
		t.Fatal("net rate/reset")
	}
	for _, file := range []string{"tcp", "tcp6", "udp", "udp6"} {
		count, e := ParseConnections(fixture(t, file))
		want := uint64(2)
		if strings.HasSuffix(file, "6") {
			want = 1
		}
		if e != nil || count != want {
			t.Fatal(file, count, e)
		}
	}
}
func TestMalformedProc(t *testing.T) {
	for _, s := range []string{"", "cpu 1 2", "cpu x 1 2 3"} {
		if _, e := ParseCPU(s); e == nil {
			t.Fatal("cpu", s)
		}
	}
	for _, s := range []string{"", "MemTotal: nope kB", strings.Replace(fixture(t, "meminfo"), "1265664", "999999999", 1), strings.Replace(fixture(t, "meminfo"), "kB", "MB", 1)} {
		if _, _, e := ParseMem(s); e == nil {
			t.Fatal("mem", s)
		}
	}
	for _, s := range []string{"", "x 1 2", "-1 1 2"} {
		if _, e := ParseLoad(s); e == nil {
			t.Fatal("load", s)
		}
	}
	for _, s := range []string{"", "x", "-1"} {
		if _, e := ParseUptime(s); e == nil {
			t.Fatal("uptime", s)
		}
	}
	for _, s := range []string{"eth0: 1 2", strings.Replace(fixture(t, "net_dev"), "8000", "oops", 1)} {
		if _, e := ParseNet(s); e == nil {
			t.Fatal("net", s)
		}
	}
	for _, s := range []string{"", "sl local_address\nbad", "sl local_address\n0: 01:01 01:01 zz"} {
		if _, e := ParseConnections(s); e == nil {
			t.Fatal("connections", s)
		}
	}
}
func TestWTMP(t *testing.T) {
	raw := string(wtmpFixture())
	logins, e := ParseWTMP(strings.NewReader(raw), 0)
	if e != nil || len(logins) != 3 || logins[0].User != "root" || logins[1].From != "2001:db8::1" {
		t.Fatal(logins, e)
	}
	newer, e := ParseWTMP(strings.NewReader(raw), 1761551990)
	if e != nil || len(newer) != 3 {
		t.Fatal(newer, e)
	}
	none, e := ParseWTMP(strings.NewReader(raw+"partial"), 1761551991)
	if e != nil || len(none) != 2 {
		t.Fatal(none, e)
	}
	b := []byte(raw[:wtmpRecordSize])
	clear(b[76:332])
	addr := 348
	if wtmpRecordSize == 400 {
		addr = 360
	}
	copy(b[addr:addr+4], []byte{203, 0, 113, 9})
	got, e := ParseWTMP(bytes.NewReader(b), 0)
	if e != nil || len(got) != 1 || got[0].From != "203.0.113.9" {
		t.Fatal(got, e)
	}
}
func TestCollectorFlow(t *testing.T) {
	c := New("sha256:" + strings.Repeat("a", 64))
	r, e := c.Sample()
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Validate(); e != nil {
		t.Fatal(e)
	}
	if e = c.Acknowledge("primary"); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Sample(); e != nil {
		t.Fatal(e)
	}
}

func wtmpFixture() []byte {
	first := loginRecord("root", 1761551990)
	second := loginRecord("alice", 1761551991)
	clear(second[76:332])
	copy(second[76:332], "2001:db8::1")
	third := loginRecord("bob", 1761551991)
	return bytes.Join([][]byte{first, second, third, third}, nil)
}
