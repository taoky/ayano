# ayano

Follow nginx JSON log, and find out bad guys! Ayano parses nginx log and shows clients eating most bandwidth every few seconds.

## Build

```
go build
```

## Usage

```
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
  -whole
        Analyze whole log file and then tail it
```

## Naming

Ayano is named after *Sugiura Ayano*, the Student Council vice-president in [*Yuru Yuri*](https://en.wikipedia.org/wiki/YuruYuri#Student_Council).
