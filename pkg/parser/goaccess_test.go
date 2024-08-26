package parser

import (
	"os"
	"testing"
	"time"
)

func TestGoAccessParser(t *testing.T) {
	configEnvName := "GOACCESS_CONFIG"
	originalValue, hadValue := os.LookupEnv(configEnvName)

	err := os.Setenv(configEnvName, "../../assets/goaccess.conf")
	if err != nil {
		t.Fatalf("Error setting environment variable: %v", err)
	}

	t.Cleanup(func() {
		if hadValue {
			os.Setenv(configEnvName, originalValue)
		} else {
			os.Unsetenv(configEnvName)
		}
	})

	p, err := GetParser("goaccess")
	if err != nil {
		t.Error(err)
	}
	line := `{"level":"info","ts":1646861401.5241024,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"127.0.0.1","remote_port":"41342","client_ip":"127.0.0.1","proto":"HTTP/2.0","method":"GET","host":"localhost","uri":"/","headers":{"User-Agent":["curl/7.82.0"],"Accept":["*/*"],"Accept-Encoding":["gzip, deflate, br"]},"tls":{"resumed":false,"version":772,"cipher_suite":4865,"proto":"h2","server_name":"example.com"}},"bytes_read": 0,"user_id":"","duration":0.000929675,"size":1090000000,"status":200,"resp_headers":{"Server":["Caddy"],"Content-Encoding":["gzip"],"Content-Type":["text/html; charset=utf-8"],"Vary":["Accept-Encoding"]},"server":"1.3.5.7"}`
	log, err := p.Parse([]byte(line))
	if err != nil {
		t.Error(err)
	}
	if log.URL != "/" {
		t.Errorf("expected url does not match")
	}
	if log.Size != 1090000000 {
		t.Errorf("expected size does not match")
	}
	if log.Client != "127.0.0.1" {
		t.Errorf("expected client 127.0.0.1, got %v", log.Client)
	}
	// Currently goaccess would ignore nsec part.
	expectedTime := time.Unix(1646861401, 0)
	if expectedTime.Sub(log.Time).Abs() > time.Microsecond {
		t.Errorf("expected time %v, got %v", expectedTime, log.Time)
	}
	if log.Server != "1.3.5.7" {
		t.Errorf("expected server does not match")
	}
}
