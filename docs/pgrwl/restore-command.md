# Restore Command

`restore_command` example for postgresql.conf:

```ini
# where 'k8s-worker5:30266' represents the host and port
# of a 'pgrwl' instance running in 'serve' mode.
restore_command = 'pgrwl restore-command --serve-addr=k8s-worker5:30266 %f %p'
```
