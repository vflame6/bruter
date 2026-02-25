# Dependencies Review

## Direct Dependencies (20)

| Dependency | Purpose | Status | Notes |
|---|---|---|---|
| kingpin/v2 | CLI parsing | "contributions only" | Consider `kong` (same author) |
| clickhouse-go/v2 | ClickHouse client | Active | Heavy dep for one module |
| go-ldap/v3 | LDAP client | Active | Good |
| go-sql-driver/mysql | MySQL driver | Active | Good |
| gosnmp | SNMP client | Active | Good |
| go-smb2 | SMB client | Active | Good |
| jlaffaye/ftp | FTP client | Active | Good |
| lib/pq | PostgreSQL driver | Active | Consider `pgx` (more modern) |
| gosmpp | SMPP client | Active | Niche but fine |
| go-mssqldb | MSSQL driver | Active | Good |
| go-vnc | VNC client | **Archived** (2015) | ⚠️ No updates in 11 years |
| amqp091-go | AMQP client | Active | Good (rabbitmq official) |
| go-redis/v9 | Redis client | Active | Good |
| go-xmpp | XMPP client | Active | Good |
| etcd/client/v3 | etcd client | Active | Heavy dep (gRPC) for one module |
| mongo-driver/v2 | MongoDB driver | Active | Good |
| zap | Logging | Active | Only used for etcd client (suppressing logs) |
| golang.org/x/crypto | SSH | Active | Good |
| golang.org/x/net | Proxy/SOCKS5 | Active | Good |
| google.golang.org/grpc | gRPC | Active | Only for etcd |

### DEP-1: go-vnc is archived and unmaintained (HIGH)
`mitchellh/go-vnc` hasn't been updated since 2015. It works for basic VNC auth but may have unfixed bugs. Consider forking or writing a minimal VNC auth implementation (RFB handshake + DES challenge-response is ~100 lines).

### DEP-2: Heavy transitive deps from etcd and clickhouse (MEDIUM)
etcd brings in gRPC + protobuf + opentelemetry. ClickHouse brings in its own compression stack. These significantly increase binary size and compile time for two niche modules. Consider making them optional (build tags) or extracting to a plugin.

### DEP-3: lib/pq vs pgx (LOW)
`lib/pq` is in maintenance mode. The community has moved to `jackc/pgx`. Not urgent since pq works fine, but pgx has better performance and active development.

### DEP-4: zap imported only for etcd log suppression (LOW)
`go.uber.org/zap` is imported only to create a no-op logger for the etcd client. Could use a simpler approach or the etcd client's built-in log config.

### Vulnerability Check
No known CVEs in current dependency versions (checked via `go mod` dates — all 2024-2025 versions).
