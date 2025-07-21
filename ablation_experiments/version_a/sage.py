import argparse
import csv
import datetime
import glob
import json
import os
import re
import sys

import requests

from ag_generation import make_attack_graphs
from episode_sequence_generation import aggregate_into_episodes, host_episode_sequences, break_into_subbehaviors
from model_learning import generate_traces, flexfringe, load_model, encode_sequences
from plotting import plot_alert_filtering, plot_histogram, plot_state_groups
from signatures.attack_stages import MicroAttackStage
from signatures.mappings import micro_inv
from signatures.alert_signatures import (
    usual_mapping,
    unknown_mapping,
    ccdc_combined,
    attack_stage_mapping,
    zeek_mapping,
)


IANA_CSV_FILE = "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv"
IANA_NUM_RETRIES = 5
SAVE_AG = True
CPTC_BAD_IP = '169.254.169.254'


def _get_attack_stage_mapping(signature):
    """
    ABLATION VERSION A: Return raw signature without abstraction
    
    @param signature: the signature of the alert
    @return: the raw signature (no mapping)
    """
    # For ablation study: skip event abstraction
    # Return raw signature as-is
    return signature


# Step 0: Download the IANA port-service mapping
def load_iana_mapping():
    """
    Downloads the IANA port-service mapping. In case of a failure or a timeout, retries IANA_NUM_RETRIES times.

    @return: a dictionary that maps a port to the corresponding service based on the IANA mapping
    """
    # Perform the first request and in case of a failure retry the specified number of times
    for attempt in range(IANA_NUM_RETRIES + 1):
        response = requests.get(IANA_CSV_FILE)
        if response.ok:
            content = response.content.decode("utf-8")
            break
        elif attempt < IANA_NUM_RETRIES:
            print('Could not download IANA ports. Retrying...')
        else:
            raise RuntimeError('Cannot download IANA ports')
    table = csv.reader(content.splitlines())

    # Drop headers (service name, port, protocol, description, ...)
    next(table)

    # Note that ports might have holes
    ports = {}
    for row in table:
        # Drop missing port number, Unassigned and Reserved ports
        if row[1] and 'Unassigned' not in row[3]:  # and 'Reserved' not in row[3]:

            # Split range in single ports
            if '-' in row[1]:
                low_port, high_port = map(int, row[1].split('-'))
            else:
                low_port = high_port = int(row[1])

            for port in range(low_port, high_port + 1):
                ports[port] = {
                    "name": row[0] if row[0] else "unknown",
                    "description": row[3] if row[3] else "---",
                }
    return ports


def _readfile(fname):
    """
    Reads the file with the alerts.

    @param fname: the name of the file with the alerts
    @return: the unparsed alerts
    """
    with open(fname, 'r') as f:
        unparsed_data = json.load(f)

    unparsed_data = unparsed_data[::-1]
    return unparsed_data


# Step 1.1: Parse the input alerts
def _parse(unparsed_data):
    """
    Parses the alerts and converts them into the specific format:
        (diff_dt, src_ip, src_port, dst_ip, dst_port, sig, cat, host, dt, mcat).

    @param unparsed_data: the unparsed alerts
    @return: parsed alerts, sorted by the start time
    """
    parsed_data = []

    prev = -1
    for d in unparsed_data:
        if 'result' in d and '_raw' in d['result']:
            raw = json.loads(d['result']['_raw'])
        elif '_raw' in d:
            raw = json.loads(d['_raw'])
        else:
            raw = d

        is_zeek = 'zeek_original' in raw or raw.get('host') == 'zeek' or d.get('host') == 'zeek'

        if not is_zeek and raw.get('event_type') != 'alert':
            continue

        host = 'zeek' if is_zeek else (
            raw['host'] if 'host' in raw else (d['host'][3:] if 'host' in d else 'dummy')
        )

        ts = d.get('timestamp', raw.get('timestamp'))
        try:
            dt = datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S.%f%z')
        except ValueError:
            dt = datetime.datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S%z')

        diff_dt = 0.0 if prev == -1 else round((dt - prev).total_seconds(), 2)
        prev = dt

        if is_zeek:
            sig = d.get('alert', {}).get('signature', raw.get('alert', {}).get('signature', 'Unknown'))
            cat = d.get('alert', {}).get('category', raw.get('alert', {}).get('category', 'Zeek'))
            
            src_ip = d.get('src_ip') or raw.get('src_ip')
            src_port = d.get('src_port') or raw.get('src_port')
            dst_ip = d.get('dest_ip') or raw.get('dest_ip')
            dst_port = d.get('dest_port') or raw.get('dest_port')
        else:
            sig = raw['alert']['signature']
            cat = raw['alert']['category']
            src_ip = raw['src_ip']
            src_port = None if 'src_port' not in raw else raw['src_port']
            dst_ip = raw['dest_ip']
            dst_port = None if 'dest_port' not in raw else raw['dest_port']

        # Filter out mistaken alerts / uninteresting alerts
        if (dataset_name == 'cptc' and CPTC_BAD_IP in (src_ip, dst_ip)) or cat == 'Not Suspicious Traffic':
            continue

        mcat = _get_attack_stage_mapping(sig)
        parsed_data.append((diff_dt, src_ip, src_port, dst_ip, dst_port, sig, cat, host, dt, mcat))

    print('Reading # alerts: ', len(parsed_data))
    parsed_data = sorted(parsed_data, key=lambda al: al[8])  # Sort alerts into ascending order
    return parsed_data


# Step 1.2: Remove duplicate alerts (defined by the alert_filtering_window parameter)
def _remove_duplicates(unfiltered_alerts, plot=False, gap=1.0):
    """
    Removes the duplicate alerts, i.e. all alerts with identical attributes that occur within a gap (=1.0),
        keeping only the first occurrence, as defined in the paper.

    @param unfiltered_alerts: the parsed alerts that have not yet been filtered
    @param plot: whether to plot the alert frequencies per Micro Attack Stage before and after filtering
    @param gap: the filtering gap, i.e. alert filtering window (parameter `t` in the paper, default 1.0 sec)
    @return: the alerts without duplicates
    """
    filtered_alerts = []
    prev_alerts = {}
    for alert in unfiltered_alerts:
        if alert[9] == MicroAttackStage.NON_MALICIOUS:
            continue

        key = (alert[1], alert[3], alert[5])
        if key in prev_alerts:
            prev = prev_alerts[key]
            if (alert[8] - prev[8]).total_seconds() <= gap:
                continue
        prev_alerts[key] = alert
        filtered_alerts.append(alert)
    if plot:
        plot_alert_filtering(unfiltered_alerts, filtered_alerts)

    print('Filtered # alerts (remaining):', len(filtered_alerts))
    return filtered_alerts


# Step 1: Read the input alerts
def load_data(path_to_alerts, filtering_window, start, end):
    """
    Reads the input alerts, parses them, removes duplicates, and groups them per attacker team.

    @param path_to_alerts: the path to the directory with the alerts
    @param filtering_window: filtering window (aka gap, aka t, default: 1.0)
    @param start: the start hour to limit alerts based on the user preferences (default: 0)
    @param end: the end hour to limit alerts based on the user preferences (default: 100)
    @return: parsed and filtered alerts grouped by team, team labels and the first timestamp for each team
    """
    _team_alerts = []
    _team_labels = []
    _team_start_times = []  # Record the first alert just to get the real elapsed time (if the user filters (s,e) range)
    files = glob.glob(path_to_alerts + "/*.json")
    print('About to read json files...')
    if len(files) < 1:
        print('No alert files found.')
        sys.exit()
    for f in files:
        name = os.path.basename(f)[:-5]
        print(name)
        _team_labels.append(name)

        parsed_alerts = _parse(_readfile(f))
        parsed_alerts = _remove_duplicates(parsed_alerts, gap=filtering_window)

        # EXP: Limit alerts by timing is better than limiting volume because each team is on a different scale.
        # 50% alerts for one team end at a diff time than for others
        end_time_limit = 3600 * end       # Which hour to end at?
        start_time_limit = 3600 * start   # Which hour to start from?

        first_ts = parsed_alerts[0][8]
        _team_start_times.append(first_ts)

        filtered_alerts = [x for x in parsed_alerts if (((x[8] - first_ts).total_seconds() <= end_time_limit)
                                                        and ((x[8] - first_ts).total_seconds() >= start_time_limit))]
        _team_alerts.append(filtered_alerts)

    return _team_alerts, _team_labels, _team_start_times



def group_alerts_per_team(alerts, port_mapping):
    _team_data = {}

    for tid, team in enumerate(alerts):
        host_alerts = {}                      # (src ,dst) → [tuple…]

        for alert in team:
            # ------- 既有欄位 (索引 0‥4) -------
            src_ip, dst_ip  = alert[1], alert[3]
            signature, ts   = alert[5], alert[8]
            mcat            = alert[9]
            dst_port        = alert[4] if alert[4] is not None else 65000
            raw             = alert[6] if len(alert) > 6 else {}
            # ------------------------------------

            # ------- 決定 service -------
            if isinstance(raw, dict) and raw.get("service"):
                dst_port_service = raw["service"]                 # Zeek 自帶
            elif dst_port in port_mapping:
                dst_port_service = port_mapping[dst_port]["name"] # IANA
            else:
                dst_port_service = f"port-{dst_port}"             # 備援
            # ------------------------------------

            # ------- 取 Modbus 細節 -------
            func   = raw.get("modbus_func")   if isinstance(raw, dict) else None
            addr   = raw.get("modbus_addr")   if isinstance(raw, dict) else None
            length = raw.get("modbus_count")  if isinstance(raw, dict) else None
            data   = raw.get("modbus_data")   if isinstance(raw, dict) else None
            # 將細節直接拼進 signature → 後續函式都能看見
            sig_detail = signature
            if func is not None:  # 有 Modbus 才加
                sig_detail += f" | FC={func} addr={addr} len={length} data={data}"
            # ------------------------------------

            # ------- CPTC 方向修正 (如有需要保留) -------
            if dataset_name == "cptc" and not src_ip.startswith("10.0.254") \
                                     and not dst_ip.startswith("10.0.254"):
                continue
            if dataset_name == "cptc" and dst_ip.startswith("10.0.254"):
                src_ip, dst_ip = dst_ip, src_ip
            # -----------------------------------------

            # ------- 建立 / 追加 -------
            key_fwd = (src_ip, dst_ip)
            key_rev = (dst_ip, src_ip)
            if key_fwd not in host_alerts and key_rev not in host_alerts:
                host_alerts[key_fwd] = []

            record = (dst_ip, mcat, ts, dst_port_service, sig_detail)  # 只有 5 欄
            if key_fwd in host_alerts:
                host_alerts[key_fwd].append(record)
            else:
                host_alerts[key_rev].append((src_ip, mcat, ts, dst_port_service, sig_detail))
            # -----------------------------------------

        _team_data[tid] = host_alerts.items()

    return _team_data


# OLD 
# def group_alerts_per_team(alerts, port_mapping):
#     """
#     Reorganises the alerts per team, for each attacker and victim pair.

#     @param alerts: the parsed and filtered alerts, grouped by team
#     @param port_mapping: the IANA port-service mapping
#     @return: alerts grouped by team and by (src_ip, dst_ip)
#     """
#     _team_data = dict()
#     for tid, team in enumerate(alerts):
#         host_alerts = dict()  # (attacker, victim) -> alerts

#         for alert in team:
#             # Alert format: (diff_dt, src_ip, src_port, dst_ip, dst_port, sig, cat, host, ts, mcat)
#             src_ip, dst_ip, signature, ts, mcat = alert[1], alert[3], alert[5], alert[8], alert[9]
#             dst_port = alert[4] if alert[4] is not None else 65000

#             is_zeek_format = (
#                 'zeek' in alert[7].lower()
#                 or 'OT_' in signature
#                 or 'Modbus' in signature
#                 or 'HTTP' in signature
#             )

#             if is_zeek_format:
#                 if isinstance(dst_port, str) and dst_port != 'unknown':
#                     dst_port_service = dst_port
#                 elif dst_port == 502:
#                     dst_port_service = 'modbus'
#                 elif dst_port == 80:
#                     dst_port_service = 'http'
#                 elif dst_port == 443:
#                     dst_port_service = 'https'
#                 elif dst_port in port_mapping:
#                     dst_port_service = port_mapping[dst_port]['name']
#                 else:
#                     # dst_port_service = 'unknown'
#                     dst_port_service = f"port-{dst_port}" 
#             else:
#                 if dst_port not in port_mapping or port_mapping[dst_port] == 'unknown':
#                     # dst_port_service = 'unknown'
#                     dst_port_service = f"port-{dst_port}" 
#                 else:
#                     dst_port_service = port_mapping[dst_port]['name']

#             # For the CPTC dataset, attacker IPs (src_ip) start with '10.0.254', but this prefix might also be in dst_ip
#             # TODO: for the future, we might want to address internal paths
#             if dataset_name == 'cptc' and not src_ip.startswith('10.0.254') and not dst_ip.startswith('10.0.254'):
#                 continue
#             # Swap src_ip and dst_ip, so that the prefix '10.0.254' is in src_ip
#             if dataset_name == 'cptc' and dst_ip.startswith('10.0.254'):
#                 src_ip, dst_ip = dst_ip, src_ip

#             if (src_ip, dst_ip) not in host_alerts.keys() and (dst_ip, src_ip) not in host_alerts.keys():
#                 host_alerts[(src_ip, dst_ip)] = []

#             if (src_ip, dst_ip) in host_alerts.keys():  # TODO: remove the redundant host names
#                 host_alerts[(src_ip, dst_ip)].append((dst_ip, mcat, ts, dst_port_service, signature))
#             else:
#                 host_alerts[(dst_ip, src_ip)].append((src_ip, mcat, ts, dst_port_service, signature))

#         _team_data[tid] = host_alerts.items()
#     return _team_data


# ----- MAIN ------
parser = argparse.ArgumentParser(description='SAGE: Intrusion Alert-Driven Attack Graph Extractor.')
parser.add_argument('path_to_json_files', type=str, help='Directory containing intrusion alerts in json format. sample-input.json provides an example of the accepted file format')
parser.add_argument('experiment_name', type=str, help='Custom name for all artefacts')
parser.add_argument('-t', type=float, required=False, default=1.0, help='Time window in which duplicate alerts are discarded (default: 1.0 sec)')
parser.add_argument('-w', type=int, required=False, default=150, help='Aggregate alerts occuring in this window as one episode (default: 150 sec)')
parser.add_argument('--timerange', type=int, nargs=2, required=False, default=[0, 100], metavar=('STARTRANGE', 'ENDRANGE'), help='Filtering alerts. Only parsing from and to the specified hours, relative to the start of the alert capture (default: (0, 100))')
parser.add_argument('--dataset', required=False, type=str, choices=['cptc', 'other', 'zeek'], default='other', help='The name of the dataset with the alerts (default: other)')
parser.add_argument('--keep-files', action='store_true', help='Do not delete the dot files after the program ends')
parser.add_argument('--zeek-format', action='store_true', help='Input alerts are produced from Zeek logs')
parser.add_argument('--severity', nargs='+', choices=['low', 'medium', 'high'], default=['high'], 
                    help='Severity levels to include in attack graphs (default: high). Can specify multiple levels.')
args = parser.parse_args()

path_to_json_files = args.path_to_json_files
experiment_name = args.experiment_name
alert_filtering_window = args.t
alert_aggr_window = args.w
start_hour, end_hour = args.timerange
dataset_name = args.dataset
delete_files = not args.keep_files
is_zeek_input = args.zeek_format or dataset_name == 'zeek'
severity_levels = args.severity

path_to_ini = "FlexFringe/ini/spdfa-config.ini"

path_to_traces = experiment_name + '.txt'
ag_directory = experiment_name + 'AGs'

print('------ Downloading the IANA port-service mapping ------')
port_services = load_iana_mapping()

if is_zeek_input:
    print('------ 處理 Zeek 格式的警報 ------')
print('------ Reading alerts ------')
team_alerts, team_labels, team_start_times = load_data(path_to_json_files, alert_filtering_window, start_hour, end_hour)
plot_histogram(team_alerts, team_labels, experiment_name)
team_data = group_alerts_per_team(team_alerts, port_services)

print('------ Converting to episodes ------')
team_episodes, _ = aggregate_into_episodes(team_data, team_start_times, step=alert_aggr_window)

print('\n------ Converting to episode sequences ------')
host_data = host_episode_sequences(team_episodes)

print('------ Breaking into sub-sequences and generating traces ------')
episode_subsequences = break_into_subbehaviors(host_data)
episode_traces = generate_traces(episode_subsequences, path_to_traces)


print('------ Learning S-PDFA ------')
flexfringe(path_to_traces, ini=path_to_ini, symbol_count="2", state_count="4")

os.system("dot -Tpng " + path_to_traces + ".ff.final.dot -o " + path_to_traces + ".png")

print('------ !! Special: Fixing syntax error in main model and sink files ------')
print('--- Sinks')
with open(path_to_traces + ".ff.finalsinks.json", 'r') as file:
    filedata = file.read()
stripped = re.sub(r'[\s+]', '', filedata)
extra_commas = re.search(r'(}(,+)]}$)', stripped)
if extra_commas is not None:
    comma_count = (extra_commas.group(0)).count(',')
    print(extra_commas.group(0), comma_count)
    filedata = ''.join(filedata.rsplit(',', comma_count))
    with open(path_to_traces + ".ff.finalsinks.json", 'w') as file:
        file.write(filedata)

print('--- Main')
with open(path_to_traces + ".ff.final.json", 'r') as file:
    filedata = file.read()
stripped = re.sub(r'[\s+]', '', filedata)
extra_commas = re.search(r'(}(,+)]}$)', stripped)
if extra_commas is not None:
    comma_count = (extra_commas.group(0)).count(',')
    print(extra_commas.group(0), comma_count)
    filedata = ''.join(filedata.rsplit(',', comma_count))
    with open(path_to_traces + ".ff.final.json", 'w') as file:
        file.write(filedata)

print('------ Loading and traversing S-PDFA ------')
main_model = load_model(path_to_traces + ".ff.final.json")
sinks_model = load_model(path_to_traces + ".ff.finalsinks.json")

print('------ Encoding traces into state sequences ------')
state_sequences, severe_sinks = encode_sequences(main_model, sinks_model, episode_subsequences)

# print('------ Clustering state groups ------')
# state_groups = plot_state_groups(state_sequences, path_to_traces)

print('------ Making alert-driven AGs ------')
make_attack_graphs(state_sequences, severe_sinks, path_to_traces, ag_directory, SAVE_AG, severity_levels=severity_levels)

if delete_files:
    print('Deleting extra files')
    os.system("rm " + path_to_traces + ".ff.final.dot")
    os.system("rm " + path_to_traces + ".ff.final.json")
    os.system("rm " + path_to_traces + ".ff.finalsinks.json")
    os.system("rm " + path_to_traces + ".ff.finalsinks.dot")
    os.system("rm " + path_to_traces + ".ff.init.dot")
    os.system("rm " + path_to_traces + ".ff.init.json")
    os.system("rm " + path_to_traces + ".ff.initsinks.dot")
    os.system("rm " + path_to_traces + ".ff.initsinks.json")
    # os.system("rm " + "spdfa-clustered-" + path_to_traces + "-dfa.dot")  # Comment out if this file is created
    os.system("rm " + ag_directory + "/*.dot")

print('\n------- FIN -------')
# ----- END MAIN ------
