#!/usr/bin/env python3
"""Convert Zeek logs into SAGE compatible JSON format."""

import argparse
import datetime
import json
import os
import sys


def parse_zeek_log(log_file):
    """Parse a single Zeek log file returning list of records."""
    records = []
    try:
        with open(log_file, 'r') as f:
            lines = f.readlines()
    except OSError as exc:
        print(f"Error reading {log_file}: {exc}")
        return records

    data_lines = [ln for ln in lines if not ln.startswith('#')]
    header_lines = [ln for ln in lines if ln.startswith('#fields')]
    if not header_lines:
        print(f"No header found in {log_file}")
        return records
    fields = header_lines[-1].strip()[8:].split('\t')
    for line in data_lines:
        values = line.strip().split('\t')
        if len(values) != len(fields):
            continue
        rec = dict(zip(fields, values))
        records.append(rec)
    return records


def process_notice_log(log_file):
    records = parse_zeek_log(log_file)
    alerts = []
    for record in records:
        ts = float(record.get('ts', '0'))
        timestamp = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f%z')
        src_ip = record.get('id.orig_h')
        src_port = record.get('id.orig_p')
        if src_port and src_port != '-':
            src_port = int(src_port)
        else:
            src_port = None
        dst_ip = record.get('id.resp_h')
        dst_port = record.get('id.resp_p')
        if dst_port and dst_port != '-':
            dst_port = int(dst_port)
        else:
            dst_port = None
        note = record.get('note', 'Unknown')
        msg = record.get('msg', '')
        alert = {
            'event_type': 'alert',
            'timestamp': timestamp,
            'alert': {
                'signature': note,
                'category': note.split('_')[0] if '_' in note else 'Notice'
            },
            'src_ip': src_ip,
            'src_port': src_port,
            'dest_ip': dst_ip,
            'dest_port': dst_port,
            'host': 'zeek',
            'result': {
                '_raw': json.dumps({'msg': msg, 'zeek_original': record})
            }
        }
        alerts.append(alert)
    return alerts


def process_modbus_log(log_file):
    records = parse_zeek_log(log_file)
    alerts = []
    for record in records:
        ts = float(record.get('ts', '0'))
        timestamp = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f%z')
        src_ip = record.get('id.orig_h')
        src_port = record.get('id.orig_p')
        if src_port and src_port != '-':
            src_port = int(src_port)
        else:
            src_port = None
        dst_ip = record.get('id.resp_h')
        dst_port = record.get('id.resp_p')
        if dst_port and dst_port != '-':
            dst_port = int(dst_port)
        else:
            dst_port = None
        func = record.get('func', 'Unknown')
        is_write = any(w in func.lower() for w in ['write', 'force'])
        signature = f"Modbus {func}"
        category = 'Modbus Write' if is_write else 'Modbus Read'
        alert = {
            'event_type': 'alert',
            'timestamp': timestamp,
            'alert': {
                'signature': signature,
                'category': category
            },
            'src_ip': src_ip,
            'src_port': src_port,
            'dest_ip': dst_ip,
            'dest_port': dst_port,
            'host': 'zeek',
            'result': {
                '_raw': json.dumps({'func': func, 'zeek_original': record})
            }
        }
        alerts.append(alert)
    return alerts


def process_http_log(log_file):
    records = parse_zeek_log(log_file)
    alerts = []
    suspicious_patterns = ['upload', 'cmd', 'shell', 'admin', 'exec', 'passwd']
    for record in records:
        uri = record.get('uri', '')
        method = record.get('method', '')
        if not any(p in uri.lower() for p in suspicious_patterns) and method != 'POST':
            continue
        ts = float(record.get('ts', '0'))
        timestamp = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f%z')
        src_ip = record.get('id.orig_h')
        src_port = record.get('id.orig_p')
        if src_port and src_port != '-':
            src_port = int(src_port)
        else:
            src_port = None
        dst_ip = record.get('id.resp_h')
        dst_port = record.get('id.resp_p')
        if dst_port and dst_port != '-':
            dst_port = int(dst_port)
        else:
            dst_port = None
        signature = f"HTTP Suspicious URI: {uri}" if any(p in uri.lower() for p in suspicious_patterns) else f"HTTP {method} Request"
        category = 'Web Attack' if 'Suspicious' in signature else 'Web Activity'
        alert = {
            'event_type': 'alert',
            'timestamp': timestamp,
            'alert': {
                'signature': signature,
                'category': category
            },
            'src_ip': src_ip,
            'src_port': src_port,
            'dest_ip': dst_ip,
            'dest_port': dst_port,
            'host': 'zeek',
            'result': {
                '_raw': json.dumps({'uri': uri, 'method': method, 'zeek_original': record})
            }
        }
        alerts.append(alert)
    return alerts


def convert_zeek_logs(log_directory, output_file):
    alerts = []
    notice = os.path.join(log_directory, 'notice.log')
    if os.path.exists(notice):
        alerts.extend(process_notice_log(notice))
    modbus = os.path.join(log_directory, 'modbus.log')
    if os.path.exists(modbus):
        alerts.extend(process_modbus_log(modbus))
    modbus_det = os.path.join(log_directory, 'modbus_detailed.log')
    if os.path.exists(modbus_det):
        alerts.extend(process_modbus_log(modbus_det))
    http = os.path.join(log_directory, 'http.log')
    if os.path.exists(http):
        alerts.extend(process_http_log(http))
    alerts.sort(key=lambda a: a['timestamp'])
    with open(output_file, 'w') as f:
        json.dump(alerts, f, indent=2)
    print(f"Converted {len(alerts)} alerts to {output_file}")
    return len(alerts)


def main():
    parser = argparse.ArgumentParser(description='Convert Zeek logs to SAGE JSON')
    parser.add_argument('log_directory', help='Path to directory containing Zeek logs')
    parser.add_argument('output_file', help='Path to output JSON file')
    args = parser.parse_args()
    if not os.path.isdir(args.log_directory):
        print(f"{args.log_directory} is not a directory")
        return 1
    convert_zeek_logs(args.log_directory, args.output_file)
    return 0


if __name__ == '__main__':
    sys.exit(main())
