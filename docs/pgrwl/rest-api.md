# REST API

`pgrwl` exposes an HTTP API on the configured `listen_port` in receive mode.

| Method | Path                        | Description                         |
| ------ | --------------------------- | ----------------------------------- |
| `GET`  | `/healthz`                  | Health check                        |
| `GET`  | `/api/v1/status`            | Receiver status and WAL position    |
| `GET`  | `/api/v1/wals`              | List archived WAL files             |
| `GET`  | `/api/v1/backups`           | List base backups                   |
| `POST` | `/api/v1/basebackup`        | Trigger a manual base backup        |
| `GET`  | `/api/v1/basebackup/status` | Running backup status               |
| `GET`  | `/api/v1/redacted-config`   | Active config with secrets redacted |
| `GET`  | `/metrics`                  | Prometheus metrics (if enabled)     |
| `GET`  | `/api/v1/wal/{filename}`    | Fetch a WAL file by name            |
