# goDNS
A simple DNS in go, help learn DNS protocol

# build
go build -o server

# test
Execute server:
```
$ ./server
Server start ...
```

Test DNS query:
```
$ dig @127.0.0.1 -p 9000 www.baidu.com A
; <<>> DiG 9.16.1-Ubuntu <<>> @127.0.0.1 -p 9000 www.baidu.com A
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 59420
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;www.baidu.com.                 IN      A

;; ANSWER SECTION:
www.baidu.com.          3600    IN      A       10.10.0.1

;; Query time: 10 msec
;; SERVER: 127.0.0.1#9000(127.0.0.1)
;; WHEN: Sun Jun 28 01:13:32 CST 2020
;; MSG SIZE  rcvd: 60
```