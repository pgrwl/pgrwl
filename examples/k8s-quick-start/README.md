## A brief example of usage

### Prerequisites:

You can use a Kind cluster for testing. If you haven’t installed it yet, check out
the [Kind installation guide](https://kind.sigs.k8s.io/).

### Deploy:

Execute scripts one by one:

```
# prepare kind cluster
bash 00-setup-kind.sh

# deploy
bash 01-deploy.sh
```

### Check Local Registry:

```
curl -X GET http://localhost:5000/v2/_catalog
curl -X GET http://localhost:5000/v2/pgrwl/tags/list
```

### Endpoints:

- grafana: http://localhost:30270

  ```
  User: admin
  Pass: admin
  ```

- seaweedfs admin UI: http://localhost:30267

  ```
  User: s3admin
  Pass: s3admin123
  ```

- seaweedfs S3 API: https://localhost:30268 (self-signed cert, same credentials)

### Verification:

```
curl --location 'http://localhost:30266/status'
```

```
# Example response:
#
# {
#     "running_mode": "receive",
#     "stream_status": {
#         "slot": "pgrwl_v5",
#         "timeline": 1,
#         "last_flush_lsn": "0/246539F0",
#         "uptime": "58m36.71s",
#         "running": true
#     }
# }
```

### Generate 512Mi of data:

```
kubectl -n pgrwl-test exec -it postgres-0 -- psql -U postgres -c "drop table if exists bigdata; CREATE TABLE bigdata AS SELECT i, repeat('x', 1024) AS filler FROM generate_series(1, (1 * 1024 * 1024)/2) AS t(i);"
```

### Dashboard Basic Example (available in current grafana setup):

![Basic Dashboard 1](https://github.com/hashmap-kz/assets/blob/main/pgrwl/dashboards/m1.png)

![Basic Dashboard 2](https://github.com/hashmap-kz/assets/blob/main/pgrwl/dashboards/m2.png)

### Logging

![Receive Logs](https://github.com/hashmap-kz/assets/blob/main/pgrwl/logs/logs-receive.png)

![Backup Logs](https://github.com/hashmap-kz/assets/blob/main/pgrwl/logs/logs-backup.png)
