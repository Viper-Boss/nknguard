# fnOS deployment on an existing data disk

This deployment keeps NKNGuard under `/mnt/docker-data/nknguard` on the
already-mounted data disk. It does not turn that disk into an fnOS App Center
volume and does not install the `.fpk` through App Center. The systemd unit is
the only NKNGuard file outside the data disk.

The service definition is
[`deploy/systemd/nknguard-fnos-disk.service`](../deploy/systemd/nknguard-fnos-disk.service).
It requires `/mnt/docker-data` to be mounted before the daemon can start.
The binary, configuration, identity keys, socket, and persistent state all
reside under `/mnt/docker-data/nknguard`. The device identity is generated on
first initialization. The owner sets the dashboard password interactively;
only a salted hash is stored in the private state directory.

## Operate

```sh
sudo systemctl status nknguard.service
sudo systemctl stop nknguard.service
sudo systemctl start nknguard.service
sudo /mnt/docker-data/nknguard/bin/nknguard \
  --config /mnt/docker-data/nknguard/etc/config.yaml status
```

The dashboard binds to `127.0.0.1:7878` on the NAS. From a computer on the
same network, forward it over SSH:

```sh
ssh -L 7878:127.0.0.1:7878 NAS_USER@NAS_ADDRESS
```

Then open `http://127.0.0.1:7878/` on that computer. Log in as `admin` with
the password chosen during setup. To set or reset it privately from the NAS:

```sh
sudo /mnt/docker-data/nknguard/bin/nknguard \
  --config /mnt/docker-data/nknguard/etc/config.yaml dashboard-password set
```

The existing NAS installation predates this setup flow. Run this command once
to replace its generated password; it does not require entering the old one.
The command removes the old password and legacy first-run note after saving
the new hash. The service does not need to restart.

## Full removal

Stop and disable the service, remove the unit, and reload systemd. Deleting
`/mnt/docker-data/nknguard` also destroys the device identity and all
pairings, so only do it for a complete uninstall. Confirm the path before
deletion; leave other data-disk directories alone.

```sh
sudo systemctl disable --now nknguard.service
sudo rm -f /etc/systemd/system/nknguard.service
sudo systemctl daemon-reload
sudo rm -rf -- /mnt/docker-data/nknguard
```

Afterward verify that `nkg0`, the process, unit, and app directory are gone.
