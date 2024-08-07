# ayano

Follow nginx log, and find out bad guys! Ayano parses nginx log and shows clients eating most bandwidth every few seconds.

## Build

```
CGO_ENABLED=0 go build
```

## Usage

```console
> ./ayano -h
Usage of ./ayano:
  -absolute
        Show absolute time for each item
  -analyse
        Log analyse mode (no tail following, only show top N at the end, and implies -whole)
  -daemon
        Daemon mode, prints out IP cidr and total size every 1GiB
  -n int
        Show top N values (0 means no limit) (default 10)
  -no-netstat
        Do not detect active connections
  -outlog string
        Change log output file
  -parser string
        Parser to use (nginx-json or nginx-combined) (default "nginx-json")
  -r int
        Refresh interval in seconds (default 5)
  -server string
        Server IP to filter (nginx-json only)
  -threshold string
        Threshold size for request (only requests larger than this will be counted) (default "100M")
  -whole
        Analyze whole log file and then tail it
> # Example 1
> ./ayano -n 20 -threshold 50M /var/log/nginx/access_json.log
> # Example 2
> ./ayano -n 50 -whole -parser nginx-combined /var/log/nginx/access.log
> # Example 3. This will use fast path to analyse log, and just print result and quit.
> ./ayano -n 100 -analyse /var/log/nginx/access_json.log
```

By default, it would output like this every 5 seconds:

```
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

## Naming

Ayano is named after *Sugiura Ayano*, the Student Council vice-president in [*Yuru Yuri*](https://en.wikipedia.org/wiki/YuruYuri#Student_Council).

Also, if you want something easier to use than iftop... Please try my new little project [chitose](https://github.com/taoky/chitose)!

