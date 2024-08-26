package parser

import (
	"testing"
	"time"
)

func TestCaddyJSONParser(t *testing.T) {
	p := CaddyJSONParser{}
	line := `{"level":"info","ts":1646861401.5241024,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"127.0.0.1","remote_port":"41342","client_ip":"127.0.0.1","proto":"HTTP/2.0","method":"GET","host":"localhost","uri":"/","headers":{"User-Agent":["curl/7.82.0"],"Accept":["*/*"],"Accept-Encoding":["gzip, deflate, br"]},"tls":{"resumed":false,"version":772,"cipher_suite":4865,"proto":"h2","server_name":"example.com"}},"bytes_read": 0,"user_id":"","duration":0.000929675,"size":10900,"status":200,"resp_headers":{"Server":["Caddy"],"Content-Encoding":["gzip"],"Content-Type":["text/html; charset=utf-8"],"Vary":["Accept-Encoding"]}}`
	log, err := p.Parse([]byte(line))
	if err != nil {
		t.Error(err)
	}
	if log.URL != "/" {
		t.Errorf("expected url does not match")
	}
	if log.Size != 10900 {
		t.Errorf("expected size does not match")
	}
	if log.Client != "127.0.0.1" {
		t.Errorf("expected client 127.0.0.1, got %v", log.Client)
	}
	expectedTime := time.Unix(1646861401, 524102400)
	if expectedTime.Sub(log.Time).Abs() > time.Microsecond {
		t.Errorf("expected time %v, got %v", expectedTime, log.Time)
	}
}
