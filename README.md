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
  -n int
        Show top N values (default 10)
  -no-netstat
        Do not detect active connections
  -parser string
        Parser to use (nginx-json or nginx-combined) (default "nginx-json")
  -r int
        Refresh interval in seconds (default 5)
  -threshold string
        Threshold size for request (only requests larger than this will be counted) (default "100M")
  -whole
        Analyze whole log file and then tail it
> # Example 1
> ./ayano -n 20 -threshold 50M /var/log/nginx/access_json.log
> # Example 2
> ./ayano -n 50 -whole -parser nginx-combined /var/log/nginx/access.log
```

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
