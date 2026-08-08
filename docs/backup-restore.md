# Backup And Restore

Platform93 backups use PostgreSQL custom format and include the complete installation.
Provider credentials and signing material remain encrypted with the installation master
key, so the backup and the matching master key must be protected and retained separately.

```sh
platform93 backup /backups/platform93-$(date +%Y%m%d-%H%M%S).dump
```

The command writes through a private temporary file and atomically publishes a mode
`0600` backup. Run it from an API, worker, or one-off pod with a writable backup volume.

Stop API, worker, and dispatcher processes before restore. Restore replaces objects in
the configured database and therefore requires an explicit confirmation argument:

```sh
platform93 restore /backups/platform93-20260807-120000.dump --confirm-replace
platform93 migrate
platform93 doctor
```

Test restore regularly against an empty recovery database. A backup that has not passed
a restore drill is not considered a recoverable backup.
