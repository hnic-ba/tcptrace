#!/usr/bin/env python
# Trace TCP throughput by appliction and upload to influxDB
# Modified from: https://github.com/iovisor/bcc/blob/master/tools/tcptop.py

from bcc import BPF
from bcc.containers import filter_by_containers
import argparse
import configparser
from influxdb_client import InfluxDBClient, Point, WriteOptions
from socket import inet_ntop, AF_INET, AF_INET6, gethostname
from struct import pack
from time import sleep, strftime
from subprocess import call
from collections import namedtuple, defaultdict
import datetime
import os
import tarfile
import json


# Uploads previous run's data, compresses, and clears old archives
def process_files(dir_path):
    file_list = os.listdir(dir_path)

    for file_name in file_list:
        file_path = os.path.join(dir_path, file_name)
        file_base_name, file_extension = os.path.splitext(file_name)

        # Only compress the file if it's not already compressed
        if file_extension != '.gz':
            upload(file_path)
            compress_file(file_path)

        if file_extension == '.gz':
            # Delete compressed files older than 7 days
            mod_time = os.path.getmtime(file_path)
            now = datetime.datetime.now().timestamp()
            days_since_mod = (now - mod_time) / (24 * 3600)
            if days_since_mod > 7:
                os.remove(file_path)
                if args.verbose:
                    print(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: Deleted {file_path} because file is {round(days_since_mod,1)} days old.")

def compress_file(file_path):
    file_name, file_extension = os.path.splitext(file_path)
    compressed_file_name = file_name + '.tar.gz'

    # If the compressed file already exists, add a numeric suffix to the file name
    suffix = 1
    while os.path.exists(compressed_file_name):
        compressed_file_name = f"{file_name}-{suffix}.tar.gz"
        suffix += 1

    # Compress file
    with tarfile.open(compressed_file_name, 'w:gz') as tar:
        tar.add(file_path, arcname=os.path.basename(file_path))

    if args.verbose:
        print(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: Compressed {file_path} -> {compressed_file_name}")

    # Remove file
    os.remove(file_path)

    if args.verbose:
        print(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: Deleted {file_path}")

def upload(file_path):
    if args.verbose:
        print(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: Uploading {file_path} to influxDB. influx_bucket={influx_bucket}, influx_org={influx_org}")
        point_counter = 0
    with open(file_path, 'r') as f:
        for line in f:
            point_dict = json.loads(line)
            point = Point.from_dict(point_dict)

            # Upload the point to InfluxDB
            write_api.write(bucket=influx_bucket, org=influx_org, record=point)

            if args.verbose:
                point_counter += 1

    if args.verbose:
        print(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: Upload complete. Uploaded {point_counter} data points.")

# Arguments
def range_check(string):
    value = int(string)
    if value < 1:
        msg = "value must be stricly positive, got %d" % (value,)
        raise argparse.ArgumentTypeError(msg)
    return value

parser = argparse.ArgumentParser(
    description="Summarize TCP send/recv throughput by host",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("interval", nargs="?", default=1, type=range_check,
    help="output interval, in seconds (default 1)")
parser.add_argument("--cgroupmap",
    help="trace cgroups in this BPF map only")
parser.add_argument("--mntnsmap",
    help="trace mount namespaces in this BPF map only")
parser.add_argument("-v", "--verbose", action="store_true",
    help="increase output verbosity")
args = parser.parse_args()

#Get InfluxDB config
config = configparser.ConfigParser()

#Write dummy line to config so we can use configparser
with open('/etc/default/influxdb') as stream:
    config.read_string("[INFLUX_CONF]\n" + stream.read())

influx_url = config.get('INFLUX_CONF', 'INFLUX_URL').strip('"')
influx_token = config.get('INFLUX_CONF', 'INFLUX_TOKEN').strip('"')
influx_org = config.get('INFLUX_CONF', 'INFLUX_ORG').strip('"')
influx_bucket = config.get('INFLUX_CONF', 'INFLUX_BUCKET').strip('"')

client = InfluxDBClient(url=influx_url, token=influx_token, org=influx_org)

write_api = client.write_api(write_options=WriteOptions(batch_size=500,
                                                        flush_interval=10000,
                                                        jitter_interval=2000,
                                                        retry_interval=5000))


# Create directory if it doesn't exist
DATA_DIR="/var/tcptrace/"
if not os.path.exists(DATA_DIR):
    if args.verbose:
        print(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: Creating data directory {DATA_DIR}")
    os.makedirs(DATA_DIR)
else:
    # Compress and upload any old data
    if args.verbose:
        print(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: Processing {DATA_DIR}")
    process_files(DATA_DIR)

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
struct ipv4_key_t {
    u32 pid;
    char name[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
};
BPF_HASH(ipv4_send_bytes, struct ipv4_key_t);
BPF_HASH(ipv4_recv_bytes, struct ipv4_key_t);
struct ipv6_key_t {
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u32 pid;
    char name[TASK_COMM_LEN];
    u16 lport;
    u16 dport;
    u64 __pad__;
};
BPF_HASH(ipv6_send_bytes, struct ipv6_key_t);
BPF_HASH(ipv6_recv_bytes, struct ipv6_key_t);
BPF_HASH(sock_store, u32, struct sock *);
static int tcp_sendstat(int size)
{
    if (container_should_be_filtered()) {
        return 0;
    }
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    u32 tid = bpf_get_current_pid_tgid();
    struct sock **sockpp;
    sockpp = sock_store.lookup(&tid);
    if (sockpp == 0) {
        return 0; //miss the entry
    }
    struct sock *sk = *sockpp;
    u16 dport = 0, family;
    bpf_probe_read_kernel(&family, sizeof(family),
        &sk->__sk_common.skc_family);
    FILTER_FAMILY
    
    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        bpf_get_current_comm(&ipv4_key.name, sizeof(ipv4_key.name));
        bpf_probe_read_kernel(&ipv4_key.saddr, sizeof(ipv4_key.saddr),
            &sk->__sk_common.skc_rcv_saddr);
        bpf_probe_read_kernel(&ipv4_key.daddr, sizeof(ipv4_key.daddr),
            &sk->__sk_common.skc_daddr);
        bpf_probe_read_kernel(&ipv4_key.lport, sizeof(ipv4_key.lport),
            &sk->__sk_common.skc_num);
        bpf_probe_read_kernel(&dport, sizeof(dport),
            &sk->__sk_common.skc_dport);
        ipv4_key.dport = ntohs(dport);
        ipv4_send_bytes.increment(ipv4_key, size);
    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        bpf_get_current_comm(&ipv6_key.name, sizeof(ipv6_key.name));
        bpf_probe_read_kernel(&ipv6_key.saddr, sizeof(ipv6_key.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.daddr, sizeof(ipv6_key.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.lport, sizeof(ipv6_key.lport),
            &sk->__sk_common.skc_num);
        bpf_probe_read_kernel(&dport, sizeof(dport),
            &sk->__sk_common.skc_dport);
        ipv6_key.dport = ntohs(dport);
        ipv6_send_bytes.increment(ipv6_key, size);
    }
    sock_store.delete(&tid);
    // else drop
    return 0;
}
int kretprobe__tcp_sendmsg(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);
    if (size > 0)
        return tcp_sendstat(size);
    else
        return 0;
}
int kretprobe__tcp_sendpage(struct pt_regs *ctx)
{
    int size = PT_REGS_RC(ctx);
    if (size > 0)
        return tcp_sendstat(size);
    else
        return 0;
}
static int tcp_send_entry(struct sock *sk)
{
    if (container_should_be_filtered()) {
        return 0;
    }
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    u32 tid = bpf_get_current_pid_tgid();
    u16 family = sk->__sk_common.skc_family;
    FILTER_FAMILY
    sock_store.update(&tid, &sk);
    return 0;
}
int kprobe__tcp_sendmsg(struct pt_regs *ctx, struct sock *sk,
    struct msghdr *msg, size_t size)
{
    return tcp_send_entry(sk);
}
int kprobe__tcp_sendpage(struct pt_regs *ctx, struct sock *sk,
    struct page *page, int offset, size_t size)
{
    return tcp_send_entry(sk);
}
/*
 * tcp_recvmsg() would be obvious to trace, but is less suitable because:
 * - we'd need to trace both entry and return, to have both sock and size
 * - misses tcp_read_sock() traffic
 * we'd much prefer tracepoints once they are available.
 */
int kprobe__tcp_cleanup_rbuf(struct pt_regs *ctx, struct sock *sk, int copied)
{
    if (container_should_be_filtered()) {
        return 0;
    }
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    FILTER_PID
    u16 dport = 0, family = sk->__sk_common.skc_family;
    u64 *val, zero = 0;
    if (copied <= 0)
        return 0;
    FILTER_FAMILY
    
    if (family == AF_INET) {
        struct ipv4_key_t ipv4_key = {.pid = pid};
        bpf_get_current_comm(&ipv4_key.name, sizeof(ipv4_key.name));
        ipv4_key.saddr = sk->__sk_common.skc_rcv_saddr;
        ipv4_key.daddr = sk->__sk_common.skc_daddr;
        ipv4_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv4_key.dport = ntohs(dport);
        ipv4_recv_bytes.increment(ipv4_key, copied);
    } else if (family == AF_INET6) {
        struct ipv6_key_t ipv6_key = {.pid = pid};
        bpf_get_current_comm(&ipv6_key.name, sizeof(ipv6_key.name));
        bpf_probe_read_kernel(&ipv6_key.saddr, sizeof(ipv6_key.saddr),
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        bpf_probe_read_kernel(&ipv6_key.daddr, sizeof(ipv6_key.daddr),
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6_key.lport = sk->__sk_common.skc_num;
        dport = sk->__sk_common.skc_dport;
        ipv6_key.dport = ntohs(dport);
        ipv6_recv_bytes.increment(ipv6_key, copied);
    }
    // else drop
    return 0;
}
"""

# Code substitutions
bpf_text = bpf_text.replace('FILTER_PID', '')
bpf_text = bpf_text.replace('FILTER_FAMILY', '')
bpf_text = filter_by_containers(args) + bpf_text

TCPSessionKey = namedtuple('TCPSession', ['pid', 'name', 'laddr', 'lport', 'daddr', 'dport'])

def get_ipv4_session_key(k):
    return TCPSessionKey(pid=k.pid,
                         name=k.name,
                         laddr=inet_ntop(AF_INET, pack("I", k.saddr)),
                         lport=k.lport,
                         daddr=inet_ntop(AF_INET, pack("I", k.daddr)),
                         dport=k.dport)

def get_ipv6_session_key(k):
    return TCPSessionKey(pid=k.pid,
                         name=k.name,
                         laddr=inet_ntop(AF_INET6, k.saddr),
                         lport=k.lport,
                         daddr=inet_ntop(AF_INET6, k.daddr),
                         dport=k.dport)

# initialize BPF
b = BPF(text=bpf_text)

ipv4_send_bytes = b["ipv4_send_bytes"]
ipv4_recv_bytes = b["ipv4_recv_bytes"]
ipv6_send_bytes = b["ipv6_send_bytes"]
ipv6_recv_bytes = b["ipv6_recv_bytes"]

hostname = gethostname()

if args.verbose:
    print(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: Starting tcptrace...")

exiting = False
while not exiting:
    try:
        sleep(args.interval)
    except KeyboardInterrupt:
        exiting = True

    # IPv4: build dict of all seen keys
    ipv4_throughput = defaultdict(lambda: [0, 0])
    for k, v in ipv4_send_bytes.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][0] = v.value
    ipv4_send_bytes.clear()

    for k, v in ipv4_recv_bytes.items():
        key = get_ipv4_session_key(k)
        ipv4_throughput[key][1] = v.value
    ipv4_recv_bytes.clear()

    # IPv6: build dict of all seen keys
    ipv6_throughput = defaultdict(lambda: [0, 0])
    for k, v in ipv6_send_bytes.items():
        key = get_ipv6_session_key(k)
        ipv6_throughput[key][0] = v.value
    ipv6_send_bytes.clear()
    
    for k, v in ipv6_recv_bytes.items():
        key = get_ipv6_session_key(k)
        ipv6_throughput[key][1] = v.value
    ipv6_recv_bytes.clear()
    
    # Collection of influxDB data points for each interval
    points = []

    for throughput_list in (ipv4_throughput, ipv6_throughput):
        for comm, (send_bytes, recv_bytes) in throughput_list.items():
            point_dict = {
                "measurement": "net_profile",
                "tags": {
                    "host": hostname,
                    "comm": comm[1].decode(),
                    "pid": comm[0],
                    "laddr": comm[2],
                    "lport": comm[3],
                    "daddr": comm[4],
                    "dport": comm[5]
                   },
                "fields": {
                    "bytes_sent": send_bytes,
                    "bytes_recv": recv_bytes
                   },
                "time": datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            }
            points.append(point_dict)

            if args.verbose:
                print(json.dumps(point_dict, indent=4, sort_keys=True))

    # Save points to file at the end of the defined collection interval (args.interval)
    now = datetime.datetime.now()
    date_string = now.strftime('%Y-%m-%d')
    # File name conflicts are accounted for when program starts and files are compressed
    filename = f"{hostname}_tcptrace_influx_data_{date_string}.json"

    if args.verbose:
        print(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}: Writing points to {DATA_DIR}{filename}")

    with open(f"{DATA_DIR}{filename}", 'a') as f:
        for p in points:
            f.write(json.dumps(p) + '\n')

client.close() # Close influxDB connection
