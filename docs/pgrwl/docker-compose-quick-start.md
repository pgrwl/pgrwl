
### Docker-Compose Quick Start

#### Start the stack

Download [docker-compose.yml](https://raw.githubusercontent.com/pgrwl/pgrwl/refs/heads/master/docker-compose.yml),
then run: `docker compose up -d`

#### Open the dashboards

| Service               | URL                                      | Description                         |
|-----------------------|------------------------------------------|-------------------------------------|
| pgrwl dashboard       | <http://localhost:8585/ui>               | Receiver and backup overview        |
| SeaweedFS admin       | <http://localhost:23646>                 | SeaweedFS cluster/storage dashboard |
| SeaweedFS filer       | <http://localhost:8888>                  | Browse files stored by SeaweedFS    |
| SeaweedFS bucket view | <http://localhost:8888/buckets/backups/> | Browse uploaded WALs and backups    |
| SeaweedFS S3 API      | <http://localhost:8333>                  | S3-compatible API endpoint          |
| PostgreSQL            | `psql -U postgres -h localhost -p 15432` | PostgreSQL primary instance         |
