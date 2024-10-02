# ayano

Follow nginx log, and find out bad guys! Ayano parses web server log and shows clients eating most bandwidth every few seconds.

## Build

```shell
CGO_ENABLED=0 go build
```

## Usage

```console
$ ./ayano
A simple log analysis tool for Nginx, Apache, or other web server logs

Usage:
  ayano [flags]
  ayano [command]

Available Commands:
  analyze     Log analyse mode (no tail following, only show top N at the end, and implies --whole)
  completion  Generate the autocompletion script for the specified shell
  daemon      Daemon mode, prints out IP CIDR and total size every 1 GiB
  help        Help about any command
  list        List various items
  run         Run and follow the log file(s)

Flags:
  -h, --help   help for ayano

Use "ayano [command] --help" for more information about a command.
$ ./ayano run --help
Run and follow the log file(s)

Usage:
  ayano run [filename...] [flags]

Flags:
  -a, --absolute          Show absolute time for each item
  -g, --group             Try to group CIDRs
  -h, --help              help for run
      --no-netstat        Do not detect active connections
  -o, --outlog string     Change log output file
  -p, --parser string     Log parser (see "ayano list parsers") (default "nginx-json")
      --prefixv4 int      Group IPv4 by prefix (default 24)
      --prefixv6 int      Group IPv6 by prefix (default 48)
  -r, --refresh int       Refresh interval in seconds (default 5)
  -s, --server string     Server IP to filter (nginx-json only)
  -S, --sort-by string    Sort result by (size|requests) (default "size")
  -t, --threshold size    Threshold size for request (only requests at least this large will be counted) (default 10 MB)
  -n, --top int           Number of top items to show (default 10)
      --truncate          Truncate long URLs from output
      --truncate-to int   Truncate URLs to given length, overrides --truncate
  -w, --whole             Analyze whole log file and then tail it

# Example 1
$ ./ayano run -n 20 --threshold 50M /var/log/nginx/access_json.log
# Example 2
$ ./ayano run -n 50 --whole --parser nginx-combined /var/log/nginx/access.log
# Example 3. This will use fast path to analyse log, and just print result and quit.
$ ./ayano analyze -n 100 /var/log/nginx/access_json.log
```

Ayano would output a table which is easy for humans to read.

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

Ayano supports following types of log format. You could also use `ayano list parsers` to check.

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

    **Note**: If you are using Caddy behind a reverse proxy, please upgrade Caddy to 2.7.0+ and set `trusted_proxies` (and `client_ip_headers`) in configuration file to let log have `client_ip` field outputted.

4. GoAccess format string. You shall set `GOACCESS_CONFIG` env to a goaccess config file beforehand ([format recognized](https://github.com/taoky/goaccessfmt?tab=readme-ov-file#config-file-format), [example](assets/goaccess.conf)).
5. Tencent CDN log format.

## Note

### Memory footprint

If you have literally A LOT OF logs to analyze, and you're running ayano on a server with very low RAM, you could use `systemd-run` to restrict its memory footprint like this:

```shell
GOMEMLIMIT=270MiB systemd-run --user --scope -p MemoryMax=300M ayano analyze ...
```

`GOMEMLIMIT` is a soft limit -- it helps go runtime GC to do its job more aggressively when it would reach the limit (at the cost of more CPU time). Please read [A Guide to the Go Garbage Collector](https://tip.golang.org/doc/gc-guide#Memory_limit) for more information.

Also, when in interactive mode (`ayano run`), `ayano` might take double memory if log format has server IP set, to support filtering by server IP without restarting.

## Naming

Ayano is named after *Sugiura Ayano*, the Student Council vice-president in [*Yuru Yuri*](https://en.wikipedia.org/wiki/YuruYuri#Student_Council).

Also, if you want something easier to use than iftop... Please try my new little project [chitose](https://github.com/taoky/chitose)!
