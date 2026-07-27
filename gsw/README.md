# Pisat COSMOS

Install OpenC3 as normal. 1.4.0.gem should be the latest up to date one (as of 19 July).

## Zeek 

Install Zeek using 

```
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt update
sudo apt install zeek
```

Run `python3 cosmos_to_zeek.py openc3-cosmos-cfs/targets` to generate files

Copy to Zeek's site directory `sudo cp ccsds_analyzer.zeek /opt/zeek/share/zeek/site/`

Add the following lines to `sudo nano /opt/zeek/share/zeek/site/local.zeek`

```
# Load CCSDS analyzer
@load ./ccsds_analyzer.zeek

# Enable JSON logging
@load policy/tuning/json-logs.zeek
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# REQUIRED: Zeek does NOT raise the udp_contents event (which the CCSDS
# analyzer relies on) unless the ports are registered for content delivery.
# Without these two lines the analyzer loads fine but NEVER writes a log.
# (cosmos_to_zeek.py now also bakes these into ccsds_analyzer.zeek; keeping
# them here is harmless and works even with an older generated analyzer.)
redef udp_content_delivery_ports_orig += { [5012/udp] = T, [5013/udp] = T };
redef udp_content_delivery_ports_resp += { [5012/udp] = T, [5013/udp] = T };
```

> The analyzer watches **UDP 5012 (commands) / 5013 (telemetry)**. If your
> OpenC3<->cFS link uses different ports, override them (they are `&redef`):
> `redef CCSDS::COMMAND_PORT = <p>/udp;` / `redef CCSDS::TELEMETRY_PORT = <q>/udp;`
> and change the two delivery-port lines above to match.

Update the Zeek interface with actual interface of system `sudo nano /opt/zeek/etc/node.cfg`

```
[zeek]
type=standalone
host=localhost
interface=eth0
```

> **Pick the interface the traffic actually crosses.** If OpenC3 and cFS talk
> over **localhost** (same host), set `interface=lo` — loopback traffic never
> touches `eth0`, so Zeek on `eth0` would see nothing. If cFS is on a separate
> flight computer, use the real NIC (`eth0`/`wlan0`).

Deploy Zeek `sudo /opt/zeek/bin/zeekctl deploy`

Check Zeek status `sudo /opt/zeek/bin/zeekctl status`

Check logs for commands and telemetry `tail -f /opt/zeek/logs/current/ccsds_*.log | jq .`

Create Zeek service `sudo nano /etc/systemd/system/zeek.service`

```
[Unit]
Description=Zeek Network Security Monitor (CCSDS Packet Analyzer)
Documentation=https://docs.zeek.org
After=network-online.target
Wants=network-online.target

[Service]
Type=forking
ExecStartPre=/opt/zeek/bin/zeekctl check
ExecStart=/opt/zeek/bin/zeekctl start
ExecStop=/opt/zeek/bin/zeekctl stop
ExecReload=/opt/zeek/bin/zeekctl restart
User=root
Restart=on-failure
RestartSec=10s
TimeoutStartSec=60s
TimeoutStopSec=60s

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=zeek

[Install]
WantedBy=multi-user.target
```

```
# Reload systemd to recognize the new service
sudo systemctl daemon-reload

# Enable auto-start on boot
sudo systemctl enable zeek

# Start Zeek now
sudo systemctl start zeek

# Check status
sudo systemctl status zeek
```

Create Zeek cron job

```
# Install ZeekControl cron
sudo /opt/zeek/bin/zeekctl install

# Verify cron was created
sudo crontab -l | grep zeek
```

## Troubleshooting: Zeek runs but no `ccsds_*.log` appears

A Zeek log file is only created once at least one record is written to it. So
"status is healthy but no log" almost always means the analyzer is not *seeing*
matching packets. Check, in order:

1. **UDP content delivery enabled?** This is the #1 cause. The `udp_contents`
   event does not fire unless the ports are registered (see the two
   `udp_content_delivery_ports_*` lines in `local.zeek` above). Missing them =
   analyzer loads, logs nothing, status still green.
2. **Are packets reaching Zeek?** While sending a command from OpenC3:
   ```
   sudo tcpdump -ni any 'udp port 5012 or udp port 5013'
   ```
   - Packets appear → after `sudo zeekctl deploy` you should get logs.
   - Nothing → wrong **interface** (see the `lo` vs `eth0` note above) or wrong
     **ports** (confirm the real OpenC3<->cFS ports and match them, above).
3. **Confirm the logs exist and parse:**
   ```
   ls -l /opt/zeek/logs/current/ccsds_*.log
   tail -f /opt/zeek/logs/current/ccsds_commands.log | jq .
   ```

## Forwarding the CCSDS logs to Logstash / Elastic

Zeek is already emitting JSON (the `LogAscii::use_json` line above), so ship the
logs with **Filebeat -> Logstash**. A ready config lives in this folder as
`filebeat-zeek.yml`.

On the Zeek host:
```
sudo cp filebeat-zeek.yml /etc/filebeat/filebeat.yml
sudo nano /etc/filebeat/filebeat.yml     # set LOGSTASH_HOST to your server
sudo filebeat test output                # expect "talk to server ... OK"
sudo systemctl enable --now filebeat
```

On the Logstash server, a matching pipeline:
```ruby
input { beats { port => 5044 } }
filter {
  # Zeek 'ts' is epoch seconds; map it to the event timestamp.
  date { match => ["ts", "UNIX"] target => "@timestamp" }
}
output {
  elasticsearch {
    hosts => ["http://ELASTIC_HOST:9200"]
    index => "zeek-ccsds-%{+YYYY.MM.dd}"
  }
}
```

Each record carries `src_ip` + timestamp, so in Elastic these join against the
access portal's `sessions` / `access_log` data to attribute every command to a
logged-in user (who-sent-what).
