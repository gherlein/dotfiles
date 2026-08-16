# systemd Timers

How to run something on a schedule with systemd instead of cron. Worked example
is the `nfs-home-mount` reconciler (lives in the `sbin` stow package) that mounts
a home-only NFS share when the server is reachable and unmounts it otherwise.

## Model: a timer activates a service

A systemd timer is **two units working as a pair**:

- `foo.service` -- the thing that does work (`ExecStart=...`).
- `foo.timer` -- the schedule. When it fires, it activates the service of the
  **same base name**. No wiring needed if the names match.

You enable the *timer*, not the service. The service has no `[Install]` section
and never starts on its own -- the timer is its only trigger.

## Two kinds of timer

| Kind | Directive | Fires | Use for |
|------|-----------|-------|---------|
| Monotonic | `OnBootSec`, `OnUnitActiveSec`, ... | Relative to an event (boot, last run) | "Every N seconds/minutes" polling |
| Calendar | `OnCalendar=` | Absolute wall-clock time | "03:00 daily", "Mon 09:00" (cron-like) |

`nfs-home-mount` polls every 30s, so it uses a **monotonic** timer.

## The worked example

### The service -- `nfs-home-mount.service`

```ini
[Unit]
Description=Reconcile home NFS mount against server reachability
After=network.target

[Service]
Type=oneshot
ExecStart=/home/gherlein/sbin/nfs-home-mount.sh
```

`Type=oneshot`: systemd considers the unit "active" only while the script runs,
then marks it cleanly `Finished`. Two consequences that matter for a poller:

1. **No self-overlap.** The next timer fire is measured off this service, and a
   oneshot must finish before it counts as done -- so two probes can never run at
   once, even if one stalls near its timeout.
2. Each run shows up in the journal as `Starting... / Finished...`, which is your
   proof it ticked.

No `[Install]` section -- this service is triggered only by the timer.

### The timer -- `nfs-home-mount.timer`

```ini
[Unit]
Description=Periodically reconcile the home NFS mount

[Timer]
OnBootSec=30s
OnUnitActiveSec=30s
AccuracySec=10s
Persistent=false

[Install]
WantedBy=timers.target
```

| Directive | Meaning here |
|-----------|--------------|
| `OnBootSec=30s` | First fire, 30s after boot. Seeds the initial check. |
| `OnUnitActiveSec=30s` | Recurring: fire 30s after the service last **became active**. This is the heartbeat. |
| `AccuracySec=10s` | Allow up to 10s slack so systemd can batch wakeups (saves laptop power). Default is 1min -- too coarse for a 30s poll, so set it explicitly. |
| `Persistent=false` | Don't run a "missed" fire after downtime. Only meaningful for `OnCalendar`; off for a monotonic poll. |
| `WantedBy=timers.target` | What `systemctl enable` hooks into so the timer starts at boot. |

`OnUnitActiveSec` (from when the service *started*) vs `OnUnitInactiveSec` (from
when it *finished*): for a short oneshot the difference is tiny; keying off active
gives a steadier cadence regardless of run length.

## Install and enable

Timers are system units, so they live in `/etc/systemd/system/` and need root.

```bash
# copy the two unit files into place
sudo cp foo.service foo.timer /etc/systemd/system/

# make systemd re-read units after any add/edit
sudo systemctl daemon-reload

# enable (start at boot) AND start now
sudo systemctl enable --now foo.timer
```

`enable --now` = `enable` (persist across reboots) + `start` (this session). For
`nfs-home-mount` this is exactly what `install.sh` does, plus it templates the
`ExecStart` path to the stowed `~/sbin/nfs-home-mount.sh`.

Edit a unit later? Always `sudo systemctl daemon-reload` before it takes effect.

## Inspect and operate

```bash
# when did it last fire, when next? (the go-to command)
systemctl list-timers nfs-home-mount.timer

# see the effective unit text (after drop-ins/overrides)
systemctl cat nfs-home-mount.timer

# is the timer active/enabled?
systemctl status nfs-home-mount.timer

# watch each fire live
journalctl -u nfs-home-mount.service -f

# run the work NOW, without waiting for the next tick
sudo systemctl start nfs-home-mount.service
```

`list-timers` output reads: `NEXT` (next fire), `LEFT` (time until), `LAST`
(previous fire), `PASSED` (time since), `UNIT`, `ACTIVATES` (the service).

## Turn it off

```bash
sudo systemctl disable --now foo.timer   # stop now + don't start at boot
```

Disabling the *timer* stops future runs; it doesn't touch the service (which was
never enabled independently).

## Calendar timer, for contrast

Same service, but fire at a wall-clock time instead of polling:

```ini
[Timer]
OnCalendar=*-*-* 03:00:00      # 03:00 every day
Persistent=true                # if the machine was off at 03:00, run at next boot
AccuracySec=1min
```

Test a calendar expression without installing anything:

```bash
systemd-analyze calendar "*-*-* 03:00:00"      # shows the next elapse
systemd-analyze calendar "Mon..Fri 09:00"      # weekdays at 09:00
```

`OnCalendar` syntax: `DOW YYYY-MM-DD HH:MM:SS`. Shorthands exist: `daily`,
`weekly`, `hourly`, `Mon *-*-* 00:00:00`, etc.

## When a timer beats cron

- Sub-minute cadence (cron's floor is 1 minute; the example needs 30s).
- Boot-relative scheduling (`OnBootSec`) -- cron has no equivalent.
- No self-overlap with `Type=oneshot`.
- Everything lands in the journal (`journalctl -u ...`) -- unified logging.
- `AccuracySec` batching for power efficiency on laptops.
- Missed-run catch-up via `Persistent=true` for calendar timers.

## User timers (no root)

For per-user tasks that need no privileges, drop the same unit files in
`~/.config/systemd/user/` and use `--user`:

```bash
systemctl --user enable --now foo.timer
loginctl enable-linger $USER    # let user timers run even when not logged in
```

`nfs-home-mount` is a **system** timer because mount/umount needs root; a task
that only touches your own files could be a user timer instead.
