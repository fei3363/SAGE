import os

from signatures.mappings import macro_inv, micro, micro2macro, verbose_micro
import re

def _translate(label, root=False):
    """
    Translates the node label into a more human-readable version.

    @param label: the label of the node (`mcat|mserv` or `mcat|mserv|state_ID`, where `mcat` is a string mapped from the `micro` dictionary, e.g. `DATA_DELIVERY|http|36`)
    @param root: whether this node is a root node (will be prepended with 'Victim: <victim_ip>\n')
    @return: a new more human-readable version of the label
    """
    new_label = ""
    parts = label.split("|")
    if root:
        new_label += 'Victim: ' + str(root) + '\n'

    if len(parts) >= 1:
        new_label += verbose_micro[parts[0]]
    if len(parts) >= 2:
        if parts[1] in ['modbus', 'http', 'https', 'ssh', 'telnet', 'ftp', 'smtp']:
            new_label += "\n" + parts[1].upper()
        else:
            new_label += "\n" + parts[1]
    if len(parts) >= 3:
        new_label += " | ID: " + parts[2]

    return new_label


def _get_objective_nodes(state_sequences, obj_only=False):
    """
    Gets the objectives from the state sequences. An objective is defined as `mcat|mserv` (by default),
        with `mcat` having a high severity.

    @param state_sequences: the state sequences per attacker-victim pair
    @param obj_only: whether to use only `mcat` (instead of `mcat|mserv`)
    @return: a list of the found objective nodes
    """
    objectives = set()
    for episodes in state_sequences.values():  # Iterate over all episodes and collect the objective nodes
        for epi in episodes:
            if len(str(epi[2])) == 3:  # If high-severity, then include it
                mcat = micro[epi[2]].split('.')[1]
                if obj_only:  # Experiment: only mcat or mcat + mserv?
                    vert_name = mcat
                else:
                    vert_name = mcat + '|' + epi[4]
                objectives.add(vert_name)
    return list(objectives)


def _is_severe_sink(vname, sev_sinks):
    """
    Checks whether a node is a severe sink (i.e. a sink that has a medium or high severity).

    @param vname: the name of the node (for low-severity nodes: `mcat|mserv`, for other nodes `mcat|mserv|stateID`)
    @param sev_sinks: the list of IDs of the severe sinks
    @return: True if the node is a severe sink, False otherwise
    """
    for sink in sev_sinks:
        if vname.split("|")[-1] == sink:
            return True
    return False


def _make_vertex_info(episode, in_main_model):
    """
    Creates a tuple with the information about the node corresponding to the given episode.
    The format of the node information: (vert_name, start_time, end_time, signs, timestamps)

    @param episode: the episode corresponding to the current node
    @param in_main_model: the state IDs that are present in the main model
    @return: the tuple with the node information, as defined above
    """
    start_time = round(episode[0] / 1.0)
    end_time = round(episode[1] / 1.0)
    cat = micro[episode[2]].split('.')[1]
    signs = episode[5]
    timestamps = episode[6]
    if episode[3] in in_main_model:  # TODO: this check is useless, since it is always True
        state_id = '' if len(str(episode[2])) == 1 else '|' + str(episode[3])
    else:
        state_id = '|Sink'
    vert_name = cat + '|' + episode[4] + state_id
    vert_info = (vert_name, start_time, end_time, signs, timestamps)
    return vert_info


def _get_attack_attempts(state_sequences, victim, objective, in_main_model):
    """
    Gets the attack attempts for a given victim and objective from the given state sequences (per attacker-victim pair).

    @param state_sequences: the state sequences per attacker-victim pair
    @param victim: the IP of the given victim
    @param objective: the given objective (`mcat|mserv`)
    @param in_main_model: the state IDs that are present in the main model
    @return: a list of the attack attempts and a list of the observed objective variants for a given (victim, objective)
    """
    team_attack_attempts = dict()
    observed_obj = set()  # Variants of current objective
    for att, episodes in state_sequences.items():  # Iterate over (a,v): [episode, episode, episode]
        if victim != att.split("->")[1]:  # If it's not the right victim, then don't process further
            continue
        vertices = []
        for epi in episodes:
            vertices.append(_make_vertex_info(epi, in_main_model))

        # If the objective is never reached, don't process further
        if not sum([True if objective.split("|")[:2] == v[0].split("|")[:2] else False for v in vertices]):
            continue

        # If it's an episode sequence targeting the requested victim and obtaining the requested objective
        attempts = []
        sub_attempt = []
        for vertex in vertices:  # Cut each attempt until the requested objective
            sub_attempt.append(vertex)  # Add the vertex in path
            if objective.split("|")[:2] == vertex[0].split("|")[:2]:  # If it's the objective
                if len(sub_attempt) <= 1:  # If only a single node, reject
                    sub_attempt = []
                    continue
                attempts.append(sub_attempt)
                sub_attempt = []
                observed_obj.add(vertex[0])
                continue
        team_attacker = att.split('->')[0]  # Team + attacker
        if team_attacker not in team_attack_attempts.keys():
            team_attack_attempts[team_attacker] = []
        team_attack_attempts[team_attacker].extend(attempts)
        # team_attack_attempts[team_attacker] = sorted(team_attack_attempts[team_attacker], key=lambda item: item[1])

    return team_attack_attempts, observed_obj


def _print_unique_attempts(team_attacker, attempts):
    """
    For a given attacker, print the path info (i.e. total paths, unique paths, the longest and the shortest paths).

    @param team_attacker: the IP of the given attacker (prepended with the team ID, e.g. 't0-10.0.254.30')
    @param attempts: the attack attempts for the given attacker
    """
    paths = [''.join([action[0] for action in attempt]) for attempt in attempts]
    unique_paths = len(set(paths))  # Count exactly unique attempts
    longest_path = max([len(attempt) for attempt in attempts], default=0)
    shortest_path = min([len(attempt) for attempt in attempts], default=0)
    print('Attacker {}, total paths: {}, unique paths: {}, longest path: {}, shortest path: {}'
          .format(team_attacker, len(attempts), unique_paths, longest_path, shortest_path))


def _create_edge_line(vid, vname1, vname2, ts1, ts2, color, attacker):
    """
    Creates a line defining the given edge, which will be written to the dot file for graphviz.

    @param vid: the ID of the current node (the first edge will have a different label format)
    @param vname1: the name of the first node (tail node)
    @param vname2: the name of the second node (head node)
    @param ts1: the start and end times of the first episode
    @param ts2: the start and end times of the second episode
    @param color: the color to be used for this edge
    @param attacker: the IP of the attacker for which this edge is created
    @return: the line defining the given edge (edge name, i.e. "tail -> head", color, label)
    """
    from_last = ts1[1].strftime("%y/%m/%d, %H:%M:%S")
    to_first = ts2[0].strftime("%y/%m/%d, %H:%M:%S")
    gap = round((ts2[0] - ts1[1]).total_seconds())
    edge_name = '"{}" -> "{}"'.format(_translate(vname1), _translate(vname2))
    if vid == 0:  # First transition, add attacker IP
        label = '<<font color="{}"> start_next: {}<br/>gap: {}sec<br/>end_prev: {}</font>'
        label += '<br/><font color="{}"><b>Attacker: {}</b></font>>'
        label = label.format(color, to_first, gap, from_last, color, attacker)
        edge_line = '{} [ color={}] [label={}]'.format(edge_name, color, label)
    else:
        label = 'start_next: {}\ngap: {}sec\nend_prev: {}'.format(to_first, gap, from_last)
        edge_line = '{} [ label="{}"][ fontcolor="{}" color={}]'.format(edge_name, label, color, color)
    return edge_line


def _print_simplicity(ag_name, lines):
    """
    Computes and prints the number of nodes and edges, and the simplicity for the given attack graph.

    @param ag_name: the name of the given attack graph
    @param lines: the lines in the dot file for a given attack graph
    """
    vertices, edges = 0, 0
    for line in lines:  # Count vertices and edges
        if '->' in line[1]:
            edges += 1
        elif 'shape=' in line[1]:
            vertices += 1
    print('{}: # vert: {}, # edges: {}, simplicity: {}'.format(ag_name, vertices, edges, vertices / float(edges)))



# ---------------------------------------------------------------------------
# Step 7: Create AGs per victim per objective (14 Nov)   ★ 完整修正版 ★
# ---------------------------------------------------------------------------
def make_attack_graphs(state_sequences, sev_sinks, datafile, dir_name, save_ag=True):
    """
    Render attack-graphs (AGs) for each victim/objective pair.

    - 前 5 欄索引保持不變；signature 已含 OT 協定細節
    - tooltip 直接使用 action[3] (signatures)
    """
    import os, re
    tcols = {
        't0': 'maroon', 't1': 'orange', 't2': 'darkgreen', 't3': 'blue',
        't4': 'magenta', 't5': 'purple', 't6': 'brown', 't7': 'tomato',
        't8': 'turquoise', 't9': 'skyblue'
    }

    if save_ag:
        try:
            os.mkdir(dir_name)
        except (FileExistsError, FileNotFoundError):
            print("Can't create directory here")
        else:
            print("Successfully created directory for AGs")

    shapes = ['oval', 'oval', 'oval', 'box', 'box', 'box', 'box',
              'hexagon', 'hexagon', 'hexagon', 'hexagon', 'hexagon']

    in_main_model = {epi[3] for seq in state_sequences.values() for epi in seq}
    total_victims = {av.split('->')[1] for av in state_sequences.keys()}
    objectives     = _get_objective_nodes(state_sequences)

    for victim in total_victims:
        print('!!! Rendering AGs for Victim', victim)
        for obj in objectives:
            print('\t!!!! Objective', obj)

            team_attempts, observed_obj = _get_attack_attempts(
                state_sequences, victim, obj, in_main_model
            )
            if not any(team_attempts.values()):    # 無人觸發此 objective
                continue

            ag_name = re.sub(r'[|_\-\(\)]', '', obj)
            lines = [
                (0, f'digraph {ag_name} {{'),
                (0, 'rankdir="BT"; '
                    'graph [nodesep="0.1", ranksep="0.02"]; '
                    'node  [fontname=Arial, fontsize=24, penwidth=3]; '
                    'edge  [fontname=Arial, fontsize=20,penwidth=5];')
            ]

            root_node = _translate(obj, root=victim)
            lines += [
                (0, f'"{root_node}" [shape=doubleoctagon, style=filled, fillcolor=salmon];'),
                (0, f'{{ rank = max; "{root_node}" }}')
            ]

            # --- objective variants 連到 root ---
            for var in observed_obj:
                lines.append((0, f'"{_translate(var)}" -> "{root_node}"'))
                style = ('[style="filled,dotted", fillcolor=salmon]'
                         if _is_severe_sink(var, sev_sinks)
                         else '[style=filled, fillcolor=salmon]')
                lines.append((0, f'"{_translate(var)}" {style}'))
            lines.append((0, '{ rank=same; "' +
                          '" "'.join(_translate(v) for v in observed_obj) + '" }'))

            # -----------------------------------------------------------------
            node_signatures = {}         # vname -> set(str)
            already_addressed = set()    # 已 dotted 的 sink label

            for team_att, attempts in team_attempts.items():
                color = tcols[team_att.split('-')[0]]

                for attempt in attempts:
                    # --------- 收集 tooltip (index 3) ---------
                    for action in attempt:
                        for sig in action[3]:          # signatures 是 set/list
                            node_signatures.setdefault(action[0], set()).add(str(sig))

                    # --------- 建立節點 ---------
                    for idx, action in enumerate(attempt):
                        vname = action[0]
                        if idx == 0:   # 第一個行動
                            style = 'dotted,filled' if _is_severe_sink(vname, sev_sinks) else 'filled'
                            lines.append((0, f'"{_translate(vname)}" [style="{style}", fillcolor=yellow]'))
                            if _is_severe_sink(vname, sev_sinks):
                                already_addressed.add(vname.split('|')[2])
                        else:          # 其餘行動若為 Sink，可補 dotted
                            if 'Sink' in vname and not any(_translate(vname) in l[1] and 'dotted' in l[1]
                                                            for l in lines):
                                lines.append((0, f'"{_translate(vname)}" [style="dotted"]'))

                    # --------- 建立邊 ---------
                    for idx, ((v1, t1, _, _, ts1),
                              (v2, _,  _, _, ts2)) in enumerate(zip(attempt, attempt[1:])):
                        edge_line = _create_edge_line(
                            idx, v1, v2, ts1, ts2, color, team_att.split('-')[1]
                        )
                        lines.append((t1, edge_line))

            # --------- 針對所有節點補 shape、tooltip ---------
            for vname, sigset in node_signatures.items():
                # ---------- 判斷形狀 ----------
                mcat_code = vname.split('|')[0]
                mcat      = macro_inv[micro2macro[f'MicroAttackStage.{mcat_code}']]
                shape     = shapes[mcat]

                dotted = (_is_severe_sink(vname, sev_sinks) and
                        shape != shapes[0] and
                        vname.split('|')[2] not in already_addressed)
                style_part = 'style="dotted",' if dotted else ''

                # ---------- 組 label ----------
                sig_display = list(sigset)[0]            # 取一條最具代表性的 signature
                # 如果 signature 已含 " | FC=5 ..." 會一起顯示
                label_text = _translate(vname) + r'\n' + sig_display.replace('"', r'\"')

                lines.append((0, f'"{_translate(vname)}" '
                                f'[label="{label_text}", {style_part} shape={shape}]'))

            lines.append((1000, '}'))
            print('\t     Created')

            # --------- 輸出 AG 檔案 ---------
            if save_ag:
                out_base = f'{datafile}-attack-graph-for-victim-{victim}-{ag_name}'
                out_path = f'{dir_name}/{out_base}'
                with open(f'{out_path}.dot', 'w') as fh:
                    for _, txt in lines:
                        fh.write(txt + '\n')
                os.system(f'dot -Tpng {out_path}.dot -o {out_path}.png')
                os.system(f'dot -Tsvg {out_path}.dot -o {out_path}.svg')

# # Step 7: Create AGs per victim per objective (14 Nov)
# def make_attack_graphs(state_sequences, sev_sinks, datafile, dir_name, save_ag=True):
#     """
#     Creates the attack graphs based on the given state sequences.

#     @param state_sequences: the previously created state sequences (per attacker-victim pair)
#     @param sev_sinks: the set of severe sinks (i.e. sinks with a medium or high severity)
#     @param datafile: the name of the file with the traces (used as a prefix for the file name of the attack graph)
#     @param dir_name: the name of the directory where the attack graphs should be saved
#     @param save_ag: whether to save the attack graphs (i.e. create dot, png and svg files with the attack graphs)
#     """
#     tcols = {'t0': 'maroon', 't1': 'orange', 't2': 'darkgreen', 't3': 'blue', 't4': 'magenta',
#              't5': 'purple', 't6': 'brown', 't7': 'tomato', 't8': 'turquoise', 't9': 'skyblue'}

#     if save_ag:
#         try:
#             os.mkdir(dir_name)
#         except (FileExistsError, FileNotFoundError):
#             print("Can't create directory here")
#         else:
#             print("Successfully created directory for AGs")

#     shapes = ['oval', 'oval', 'oval', 'box', 'box', 'box', 'box', 'hexagon', 'hexagon', 'hexagon', 'hexagon', 'hexagon']
#     in_main_model = set([episode[3] for sequence in state_sequences.values() for episode in sequence])
#     total_victims = set([attacker_victim.split('->')[1] for attacker_victim in state_sequences.keys()])  # Victim IPs

#     objectives = _get_objective_nodes(state_sequences)

#     for victim in total_victims:
#         print('!!! Rendering AGs for Victim', victim)
#         for objective in objectives:
#             print('\t!!!! Objective', objective)
#             # Get the variants of current objective and attempts per team
#             team_attack_attempts, observed_obj = _get_attack_attempts(state_sequences, victim, objective, in_main_model)

#             # If no team has obtained this objective or has targeted this victim, don't generate its AG
#             if sum([len(attempt) for attempt in team_attack_attempts.values()]) == 0:
#                 continue
            

#             ag_name = objective.replace('|', '').replace('_', '').replace('-', '').replace('(', '').replace(')', '')
#             lines = [(0, 'digraph ' + ag_name + ' {'),
#                      (0, 'rankdir="BT"; \n graph [ nodesep="0.1", ranksep="0.02"] \n node [ fontname=Arial, ' +
#                       'fontsize=24, penwidth=3]; \n edge [ fontname=Arial, fontsize=20,penwidth=5 ];')]
#             root_node = _translate(objective, root=victim)
#             lines.append((0, '"' + root_node + '" [shape=doubleoctagon, style=filled, fillcolor=salmon];'))
#             lines.append((0, '{ rank = max; "' + root_node + '"}'))

#             # For each variant of objective, add a link to the root node, and determine if it's sink
#             for obj_variant in list(observed_obj):
#                 lines.append((0, '"' + _translate(obj_variant) + '" -> "' + root_node + '"'))
#                 if _is_severe_sink(obj_variant, sev_sinks):
#                     lines.append((0, '"' + _translate(obj_variant) + '" [style="filled,dotted", fillcolor= salmon]'))
#                 else:
#                     lines.append((0, '"' + _translate(obj_variant) + '" [style=filled, fillcolor= salmon]'))

#             # All obj variants have the same rank
#             lines.append((0, '{ rank=same; "' + '" "'.join([_translate(obj) for obj in observed_obj]) + '"}'))

#             node_signatures = dict()
#             already_addressed = set()
#             for team_attacker, attempts in team_attack_attempts.items():  # For each attacker that obtains the objective
#                 color = tcols[team_attacker.split('-')[0]]  # Team color
#                 # _print_unique_attempts(team_attacker, attempts)

#                 for attempt in attempts:
#                     # Record signatures
#                     # for action in attempt:  # action = (vert_name, start_time, end_time, signs, timestamps)
#                     #     if action[0] not in node_signatures.keys():
#                     #         node_signatures[action[0]] = set()
#                     #     node_signatures[action[0]].update(action[3])
#                     for action in attempt:
#                         # action = (vert_name, start, end, service, signature, func, addr, length, data)
#                         sigs = action[4]                    # index 4 = signature 不變
#                         if len(action) >= 9:
#                             func, addr, length, data = action[5:9]
#                         else:
#                             func = addr = length = data = None   # 舊格式
#                         tip = str(sigs)
#                         if func is not None:             # 有 Modbus 細節才顯示
#                             tip += f"\nFC={func} addr={addr} len={length} data={data}"
#                         node_signatures.setdefault(action[0], set()).add(tip)
#                     # Create nodes for the AG
#                     for vid, action in enumerate(attempt):  # Iterate over each action in an attempt
#                         vname = action[0]
#                         if vid == 0:  # If first action
#                             if 'Sink' in vname:  # If sink, make dotted TODO: this check is always False
#                                 lines.append(
#                                     (0, '"' + _translate(vname) + '" [style="dotted,filled", fillcolor= yellow]'))
#                             else:
#                                 if _is_severe_sink(vname, sev_sinks):  # If med- or high-sev sink, make dotted
#                                     lines.append(
#                                         (0, '"' + _translate(vname) + '" [style="dotted,filled", fillcolor= yellow]'))
#                                     already_addressed.add(vname.split('|')[2])
#                                 else:  # Else, normal starting node
#                                     lines.append((0, '"' + _translate(vname) + '" [style=filled, fillcolor= yellow]'))
#                         else:  # For other actions
#                             if 'Sink' in vname:  # TODO: this check is always false
#                                 # Take all AG lines so far, and if it was ever defined before, redefine it to be dotted
#                                 already_dotted = False
#                                 for line in lines:
#                                     if (_translate(vname) in line[1]) and ('dotted' in line[1]) and (
#                                             '->' not in line[1]):
#                                         already_dotted = True
#                                         break
#                                 if already_dotted:
#                                     continue
#                                 partial = '"' + _translate(vname) + '" [style="dotted'  # Redefine here
#                                 if not sum([True if partial in line[1] else False for line in lines]):
#                                     lines.append((0, partial + '"]'))

#                     # Create edges (transitions) for the AG
#                     bigram = zip(attempt, attempt[1:])  # Make bigrams (sliding window of 2)
#                     for vid, ((vname1, time1, _, _, ts1), (vname2, _, _, _, ts2)) in enumerate(bigram):
#                         edge_line = _create_edge_line(vid, vname1, vname2, ts1, ts2, color, team_attacker.split('-')[1])
#                         lines.append((time1, edge_line))

#             # Go over all vertices again and define their shapes + make high-sev sink states dotted
#             for vname, signatures in node_signatures.items():
#                 mcat = vname.split('|')[0]
#                 mcat = macro_inv[micro2macro['MicroAttackStage.' + mcat]]
#                 shape = shapes[mcat]
#                 # If it's oval, we don't do anything because it is not a high-sev sink
#                 if shape == shapes[0] or vname.split('|')[2] in already_addressed:
#                     lines.append((0, '"' + _translate(vname) + '" [shape=' + shape + ']'))
#                 else:
#                     if _is_severe_sink(vname, sev_sinks):
#                         lines.append((0, '"' + _translate(vname) + '" [style="dotted", shape=' + shape + ']'))
#                     else:
#                         lines.append((0, '"' + _translate(vname) + '" [shape=' + shape + ']'))
#                 # Add a tooltip with signatures
#                 # lines.append((1, '"' + _translate(vname) + '"' + ' [tooltip="' + "\n".join(signatures) + '"]'))
#                 tooltip_text = "\\n".join(map(str, node_signatures[vname]))
#                 lines.append((1, '"' + _translate(vname) + '" [tooltip="' + tooltip_text + '"]'))
#             lines.append((1000, '}'))
#             print('\t     Created')
            
#             # _print_simplicity(ag_name, lines)
#             if save_ag:
#                 out_filename = datafile + '-attack-graph-for-victim-' + victim + '-' + ag_name
#                 out_filepath = dir_name + '/' + out_filename
#                 with open(out_filepath + '.dot', 'w') as outfile:
#                     for line in lines:
#                         outfile.write(str(line[1]) + '\n')

#                 os.system("dot -Tpng " + out_filepath + ".dot -o " + out_filepath + ".png")
#                 os.system("dot -Tsvg " + out_filepath + ".dot -o " + out_filepath + ".svg")
