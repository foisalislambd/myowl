package collect

import (
	"encoding/binary"
	"testing"
)

const sampleTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0A00000A:0016 1901A8C0:D2F0 01 00000000:00000000 02:000A7D8F 00000000     0        0 23456 4 0000000000000000 20 4 30 10 -1
   2: 0100007F:1F90 0100007F:B1C2 06 00000000:00000000 03:00000000 00000000     0        0 0 3 0000000000000000
`

const sampleTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000    33        0 34567 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000A00000A:01BB 0000000000000000FFFF00000F7100CB:C350 01 00000000:00000000 00:00000000 00000000    33        0 45678 1 0000000000000000 20 4 30 10 -1
`

func TestParseProcNetTCP(t *testing.T) {
	c := ParseProcNet(sampleTCP, "tcp")
	if len(c) != 3 {
		t.Fatalf("got %d conns", len(c))
	}
	if c[0].State != "LISTEN" || c[0].LocalIP != "0.0.0.0" || c[0].LocalPort != 22 || c[0].RemoteIP != "" || c[0].Inode != 12345 {
		t.Fatalf("listen: %+v", c[0])
	}
	if c[1].State != "ESTABLISHED" || c[1].LocalIP != "10.0.0.10" || c[1].RemoteIP != "192.168.1.25" || c[1].RemotePort != 0xD2F0 {
		t.Fatalf("established: %+v", c[1])
	}
	if c[2].State != "TIME_WAIT" || c[2].LocalIP != "127.0.0.1" || c[2].LocalPort != 8080 {
		t.Fatalf("time_wait: %+v", c[2])
	}
}

func TestParseProcNetTCP6(t *testing.T) {
	c := ParseProcNet(sampleTCP6, "tcp6")
	if len(c) != 2 {
		t.Fatalf("got %d conns", len(c))
	}
	if c[0].LocalIP != "::" || c[0].LocalPort != 443 {
		t.Fatalf("v6 listen: %+v", c[0])
	}
	// IPv4-mapped addresses are reported as plain IPv4.
	if c[1].LocalIP != "10.0.0.10" || c[1].RemoteIP != "203.0.113.15" || c[1].RemotePort != 50000 {
		t.Fatalf("v4-mapped: %+v", c[1])
	}
}

func TestParseProcNetUDPAndGarbage(t *testing.T) {
	udp := "header\n   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 999 2 0000000000000000 0\n  bad line\n"
	c := ParseProcNet(udp, "udp")
	if len(c) != 1 || c[0].State != "LISTEN" || c[0].LocalPort != 53 {
		t.Fatalf("udp: %+v", c)
	}
}

func utmpRec(typ int16, line, user, host string, sec int32, ip []byte) []byte {
	b := make([]byte, utmpSize)
	binary.LittleEndian.PutUint16(b[0:2], uint16(typ))
	binary.LittleEndian.PutUint32(b[4:8], 1234)
	copy(b[8:40], line)
	copy(b[44:76], user)
	copy(b[76:332], host)
	binary.LittleEndian.PutUint32(b[340:344], uint32(sec))
	copy(b[348:364], ip)
	return b
}

func TestUtmpAndHistory(t *testing.T) {
	var data []byte
	data = append(data, utmpRec(utBootTime, "~", "reboot", "6.8.0", 1000, nil)...)
	data = append(data, utmpRec(utUserProc, "pts/0", "alice", "198.51.100.2", 2000, []byte{198, 51, 100, 2})...)
	data = append(data, utmpRec(utDeadProc, "pts/0", "", "", 3000, nil)...)
	data = append(data, utmpRec(utUserProc, "pts/1", "bob", "", 4000, []byte{203, 0, 113, 9})...)
	data = append(data, 1, 2, 3) // trailing partial record is ignored

	recs := ParseUtmp(data)
	if len(recs) != 4 {
		t.Fatalf("got %d records", len(recs))
	}
	if recs[1].User != "alice" || recs[1].Line != "pts/0" || recs[1].Addr.String() != "198.51.100.2" || recs[1].Sec != 2000 {
		t.Fatalf("rec: %+v", recs[1])
	}

	h := HistoryFromWtmp(recs, 10)
	if len(h) != 3 {
		t.Fatalf("history: %+v", h)
	}
	// newest first: bob (still logged in), alice (logged out), reboot
	if h[0].User != "bob" || h[0].Host != "203.0.113.9" || h[0].Logout != 0 {
		t.Fatalf("bob: %+v", h[0])
	}
	if h[1].User != "alice" || h[1].Login != 2000000 || h[1].Logout != 3000000 {
		t.Fatalf("alice: %+v", h[1])
	}
	if h[2].Kind != "reboot" {
		t.Fatalf("reboot: %+v", h[2])
	}
	if got := HistoryFromWtmp(recs, 1); len(got) != 1 {
		t.Fatalf("limit not applied: %d", len(got))
	}
}
