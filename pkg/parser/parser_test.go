package parser

import (
	"os"
	"testing"
	"time"
)

func TestNginxJsonParser(t *testing.T) {
	p := NginxJSONParser{}
	line := `{"timestamp":1678551332.293,"clientip":"123.45.67.8","serverip":"87.65.4.32","method":"GET","url":"/path/to/a/file","status":200,"size":3009,"resp_time":0.000,"http_host":"example.com","referer":"","user_agent":""}`
	log, err := p.Parse([]byte(line))
	if err != nil {
		t.Error(err)
	}
	if log.Size != 3009 {
		t.Errorf("expected size 3009, got %d", log.Size)
	}
	if log.Client != "123.45.67.8" {
		t.Errorf("expected client 123.45.67.8, got %s", log.Client)
	}
	if log.URL != "/path/to/a/file" {
		t.Errorf("expected url /path/to/a/file, got %s", log.URL)
	}
	expectedTime := time.Unix(1678551332, 293000000)
	if expectedTime.Sub(log.Time).Abs() > time.Microsecond {
		t.Errorf("expected time %v, got %v", expectedTime, log.Time)
	}
}

func TestNginxCombinedParser(t *testing.T) {
	p := NginxCombinedParser{}
	line := `123.45.67.8 - - [12/Mar/2023:00:15:32 +0800] "GET /path/to/a/file HTTP/1.1" 200 3009 "-" ""`
	log, err := p.Parse([]byte(line))
	if err != nil {
		t.Error(err)
	}
	if log.Size != 3009 {
		t.Errorf("expected size 3009, got %d", log.Size)
	}
	if log.Client != "123.45.67.8" {
		t.Errorf("expected client 123.45.67.8, got %s", log.Client)
	}
	if log.URL != "/path/to/a/file" {
		t.Errorf("expected url /path/to/a/file, got %s", log.URL)
	}
	expectedTime := time.Date(2023, 3, 12, 0, 15, 32, 0, time.FixedZone("CST", 8*60*60))
	if expectedTime.Sub(log.Time).Abs() > time.Microsecond {
		t.Errorf("expected time %v, got %v", expectedTime, log.Time)
	}
}

func TestNginxCombinedParserWithUnusualInputs(t *testing.T) {
	p := NginxCombinedParser{}
	line := `114.5.1.4 - - [04/Apr/2024:08:01:12 +0800] "\x16\x03\x01\x00\xCA\x01\x00\x00\xC6\x03\x03\x94b\x22\x06u\xBEi\xF6\xC5cA\x97eq\xF0\xD5\xD3\xE6\x08I" 400 163 "-" "-"`
	log, err := p.Parse([]byte(line))
	if err != nil {
		t.Error(err)
	}
	if log.URL != `\x16\x03\x01\x00\xCA\x01\x00\x00\xC6\x03\x03\x94b\x22\x06u\xBEi\xF6\xC5cA\x97eq\xF0\xD5\xD3\xE6\x08I` {
		t.Errorf("expected url does not match")
	}
	line = `114.5.1.5 - - [04/Apr/2024:09:02:13 +0800] "\x16\x03\x01\x00\xEE\x01\x00\x00\xEA\x03\x03\x9C\xB4\x92\xC5{\xE9\xEC\x18\xB1\x17\x04f\xCA\x0F\xF3\xFD\xAA\x98H\xA5N\xBC\xC9\xD7\xF8\x95.H\x15\x13\xF2\xF9 ~W\xB9\x94Qs\x01\x02\xE3c'\xA8pB\xC5\xCC\x10c\xC9\xF4\x99{\x0E1\x90\x81\xBD4J\x10y\x17\x00&\xC0+\xC0/\xC0,\xC00\xCC\xA9\xCC\xA8\xC0\x09\xC0\x13\xC0" 400 163 "-" "-"`
	log, err = p.Parse([]byte(line))
	if err != nil {
		t.Error(err)
	}
	// When the abnormal request have a space in the URL, we ignore things before the space (shall be "method")
	if log.URL != `~W\xB9\x94Qs\x01\x02\xE3c'\xA8pB\xC5\xCC\x10c\xC9\xF4\x99{\x0E1\x90\x81\xBD4J\x10y\x17\x00&\xC0+\xC0/\xC0,\xC00\xCC\xA9\xCC\xA8\xC0\x09\xC0\x13\xC0` {
		t.Errorf("expected url does not match")
	}
}

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
