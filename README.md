# tcptrace
Tool for analysing network traffic from ebpf in influxdb
## Dependencies

On Ubuntu 20.04, requires packages `libbpfcc_0.26.0` and `python3-bpfcc_0.26.0`.

Additionally, the python package `influxdb-client` must be installed via `pip`.

Finally, an influxdb connection must be configured as per the example file `/etc/default/influxdb`.

# Installation

After installing dependencies, copy `tcptrace.py` and `tcptrace.service` to their specific locations and configure the systemd service. Root level access is required.

```
chmod +x /usr/local/bin/tcptrace.py
systemctl daemon-reload
systemctl enable tcptrace
systemctl start tcptrace
```

# Usage

The script will upload to influx when the script is restarted or when the system reboots. This is done on purpose to isolote the influxdb upload from the scripts own data collection.

The data will be uploaded to the specified influxdb bucket under the `net_profile` measurement.

# Example Data Stream

```
{"measurement": "net_profile", "tags": {"host": "test1", "comm": "openvpn", "pid": 850, "laddr": "192.168.1.100", "lport": 41600, "daddr": "redacted", "dport": 443}, "fields": {"bytes_sent": 2523, "bytes_recv": 2046}, "time": "2023-08-24T18:56:44Z"}
{"measurement": "net_profile", "tags": {"host": "test1", "comm": "openvpn", "pid": 849, "laddr": "192.168.1.100", "lport": 52056, "daddr": "redacted", "dport": 443}, "fields": {"bytes_sent": 221, "bytes_recv": 0}, "time": "2023-08-24T18:56:44Z"}
{"measurement": "net_profile", "tags": {"host": "test1", "comm": "node", "pid": 2739, "laddr": "127.0.0.1", "lport": 59552, "daddr": "127.0.0.1", "dport": 1883}, "fields": {"bytes_sent": 2, "bytes_recv": 2}, "time": "2023-08-24T18:56:44Z"}
{"measurement": "net_profile", "tags": {"host": "test1", "comm": "node", "pid": 2576, "laddr": "192.168.1.100", "lport": 44940, "daddr": "redacted", "dport": 443}, "fields": {"bytes_sent": 29, "bytes_recv": 25}, "time": "2023-08-24T18:56:44Z"}
{"measurement": "net_profile", "tags": {"host": "test1", "comm": "node", "pid": 2739, "laddr": "::ffff:127.0.0.1", "lport": 8015, "daddr": "::ffff:127.0.0.1", "dport": 51488}, "fields": {"bytes_sent": 406, "bytes_recv": 488}, "time": "2023-08-24T18:56:44Z"}
```

# License

MIT
