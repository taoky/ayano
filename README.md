# ayano

Follow nginx log, and find out bad guys! Ayano parses nginx log and shows clients eating most bandwidth every few seconds.

## Build

```shell
CGO_ENABLED=0 go build
```

## Usage

```console
$ ./ayano
A simple log analysis tool for Nginx, Apache, or other web server logs

Usage:
  ayano [command]

Available Commands:
  analyze     Log analyse mode (no tail following, only show top N at the end, and implies --whole)
  daemon      Daemon mode, prints out IP CIDR and total size every 1 GiB
  run         Run and follow the log file

$ ./ayano run --help
Run and follow the log file

Usage:
  ayano run [filename] [flags]

Flags:
  -a, --absolute         Show absolute time for each item
  -h, --help             help for run
      --no-netstat       Do not detect active connections
  -o, --outlog string    Change log output file
  -p, --parser string    Log parser (nginx-combined|nginx-json|caddy-json|goaccess) (default "nginx-json")
  -r, --refresh int      Refresh interval in seconds (default 5)
  -s, --server string    Server IP to filter (nginx-json only)
  -S, --sort-by string   Sort result by (size|requests) (default "size")
  -t, --threshold size   Threshold size for request (only requests at least this large will be counted) (default 10 MB)
  -n, --top int          Number of top items to show (default 10)
  -w, --whole            Analyze whole log file and then tail it

# Example 1
$ ./ayano run -n 20 --threshold 50M /var/log/nginx/access_json.log
# Example 2
$ ./ayano run -n 50 --whole --parser nginx-combined /var/log/nginx/access.log
# Example 3. This will use fast path to analyse log, and just print result and quit.
$ ./ayano analyze -n 100 /var/log/nginx/access_json.log
```

By default, it would output like this every 5 seconds:

```log
2024/07/10 00:13:48 2222:222:2222::/48 (active, 1): 457 MiB 2 228 MiB /some/big/file (from 6 seconds ago, last accessed 6 seconds ago)
2024/07/10 00:13:48 111.11.111.0/24: 268 MiB 1 268 MiB /another/big/file (from 13 seconds ago, last accessed 13 seconds ago)
```

`457 MiB 2 228 MiB` means it downloads 457 MiB large files in total, with 2 requests and 228 MiB on average.

### Daemon mode (experimental)

Daemon mode is a simple log output mode that intended to work with fail2ban.

Current log format looks like this (`log_time client_cidr total_gib GiB first_time path`):

```log
2024/06/25 01:03:17 172.26.3.0/24 1.0 GiB 2024-06-25 01:03:17 /big
2024/06/25 01:03:29 172.26.3.0/24 2.0 GiB 2024-06-25 01:03:17 /big
2024/06/25 01:03:42 172.26.3.0/24 3.0 GiB 2024-06-25 01:03:17 /big
2024/06/25 01:03:56 172.26.3.0/24 4.0 GiB 2024-06-25 01:03:17 /big
2024/06/25 01:04:09 172.26.3.0/24 5.0 GiB 2024-06-25 01:03:17 /big
```

A reference systemd service file, logrotate file and fail2ban configs are provided in [assets/](assets/).

Please note that the stats output would NOT be rotated (unless you restart ayano).

If you don't like to use fail2ban, you could also use this simple one-liner to check stats. Here is an example:

```console
$ awk '{print $3}' record.log | sort | uniq -c | sort -nr
36 114.5.14.0/24
 3 191.9.81.0/24
```

which means that "114.5.14.0/24" takes at least 36GiB bandwidth, and "191.9.81.0/24" takes at least 3GiB bandwidth, for the time period this log file covers.

## Format support

Ayano supports two types of nginx log:

1. Standard "combined" format access log.
2. JSON format access log configured as:

    ```nginx
    log_format ngx_json escape=json '{'
        '"timestamp":$msec,'
        '"clientip":"$remote_addr",'
        '"serverip":"$server_addr",'
        '"method":"$request_method",'
        '"url":"$request_uri",'
        '"status":$status,'
        '"size":$body_bytes_sent,'
        '"resp_time":$request_time,'
        '"http_host":"$host",'
        '"referer":"$http_referer",'
        '"user_agent":"$http_user_agent"'
        '}';
    ```

3. Caddy default JSON format like [this](https://caddyserver.com/docs/logging#structured-logs):

    ```json
    {"level":"info","ts":1646861401.5241024,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"127.0.0.1","remote_port":"41342","client_ip":"127.0.0.1","proto":"HTTP/2.0","method":"GET","host":"localhost","uri":"/","headers":{"User-Agent":["curl/7.82.0"],"Accept":["*/*"],"Accept-Encoding":["gzip, deflate, br"]},"tls":{"resumed":false,"version":772,"cipher_suite":4865,"proto":"h2","server_name":"example.com"}},"bytes_read": 0,"user_id":"","duration":0.000929675,"size":10900,"status":200,"resp_headers":{"Server":["Caddy"],"Content-Encoding":["gzip"],"Content-Type":["text/html; charset=utf-8"],"Vary":["Accept-Encoding"]}}
    ```

    > [!IMPORTANT]
    > If you are using Caddy behind a reverse proxy, please upgrade Caddy to 2.7.0+ and set `trusted_proxies` (and `client_ip_headers`) in configuration file to let log have `client_ip` field outputted.

4. GoAccess format string. You shall set `GOACCESS_CONFIG` env to a goaccess config file beforehand ([format recognized](https://github.com/taoky/goaccessfmt?tab=readme-ov-file#config-file-format), [example](assets/goaccess.conf)).

## Naming

Ayano is named after *Sugiura Ayano*, the Student Council vice-president in [*Yuru Yuri*](https://en.wikipedia.org/wiki/YuruYuri#Student_Council).

Also, if you want something easier to use than iftop... Please try my new little project [chitose](https://github.com/taoky/chitose)!
