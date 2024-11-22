from common import *


def getSummary(top_metrics, graph_data, combined_graph_data, sample_data, attack_data, top_n_attack_ids):
    """Takes raw data and outputs an english description of what occurred"""
    #Incident description
    #   Multiple attacks were detected on site _____
    #   Attack IP destinations:
    #       <date1> - <targeted ips>
    #       <date2> - <targeted ips>
    #   Attack timeframe: 
    #       <date1> between <Start Time> and <End Time>
    #       <date1> between <Start Time2> and <End Time2>
    #       <date2> between <Start Time> and <End Time>
    #   Attack Volume: Gbps/PPS/CPS
    #       Max attack rate:
    #           ~<Total Bandwidth>/<rate per second> started at <start time>, ended at <end time> on <Date> - <Attack type>
    #           ~<Total Bandwidth>/<rate per second> started at <start time>, ended at <end time> on <Date> - <Attack type>
    #   Attack Vectors:
    #       <date> - <List of Attack Names>
    #   Impact?:
    #
    #Summary
    #   Radware CyberController Plus has detected and successfully/partially mitigated the multi-vector attack 
    #   Radware successfully mitigated x out y of the total attack volume or 60% of the attack volume(be careful with this)
    #   There was/was not impact during the incident
    #   The impact happened due to…

    first_attack_start = None
    last_attack_end = None
    vectors = set()
    for topkey in ['top_by_bps', 'top_by_pps']:
        for attack in top_metrics[topkey]:
            if attack[1]['Policy'] != 'Packet Anomalies':
                start_time = datetime.datetime.strptime(attack[1]["Start Time"], '%d-%m-%Y %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
                end_time = datetime.datetime.strptime(attack[1]["End Time"], '%d-%m-%Y %H:%M:%S').replace(tzinfo=datetime.timezone.utc)
                first_attack_start = min(first_attack_start, start_time) if first_attack_start else start_time
                last_attack_end = max(last_attack_end, end_time) if last_attack_end else end_time                
            vectors.add(attack[1]["Attack Name"])
    if last_attack_end and first_attack_start:
        elapsed_time = last_attack_end - first_attack_start
        elapsed_days = elapsed_time.days
        elapsed_hours = elapsed_time.seconds // 3600
        elapsed_minutes = (elapsed_time.seconds % 3600) // 60
        elapsed_seconds = elapsed_time.seconds % 60
        elapsed_parts = []
        if elapsed_days > 0:
            elapsed_parts.append(f"{elapsed_days} day{'s' if elapsed_days > 1 else ''}")
        if elapsed_hours > 0:
            elapsed_parts.append(f"{elapsed_hours} hour{'s' if elapsed_hours > 1 else ''}")
        if elapsed_minutes > 0:
            elapsed_parts.append(f"{elapsed_minutes} minute{'s' if elapsed_minutes > 1 else ''}")
        if elapsed_seconds > 0:
            elapsed_parts.append(f"{elapsed_seconds} second{'s' if elapsed_seconds > 1 else ''}")
        elapsed_time = ", ".join(elapsed_parts)
    else:
        elapsed_time = "N/A"
    peak_traffic = highest_aggregate_15_seconds(combined_graph_data)
    peak_traffic['bps'] = "{:,}".format(int(float(graph_data['bps']['dataMap']['maxValue']['trafficValue'])))
    peak_traffic['pps'] = "{:,}".format(int(float(graph_data['pps']['dataMap']['maxValue']['trafficValue'])))
    #peak_traffic = {
    #    'bps': "{:,}".format(int(float(graph_data['bps']['dataMap']['maxValue']['trafficValue']))),
    #    'bps_time': int(graph_data['bps']['dataMap']['maxValue']['timeStamp']),
    #    'pps': "{:,}".format(int(float(graph_data['pps']['dataMap']['maxValue']['trafficValue']))),
    #    'pps_time': int(graph_data['pps']['dataMap']['maxValue']['timeStamp']),
    #    }
    
    attacked_destinations = set()
    attack_sources = set()
    destination_ports = set()
    for sample in sample_data:
        attack_sources.add(sample['sourceAddress'])
        attacked_destinations.add(sample['destAddress'])
        destination_ports.add(sample['destPort'])
    
    attack_sources = list(attack_sources)
    attacked_destinations = list(attacked_destinations)
    destination_ports = list(destination_ports)

    attack_sources.sort(key=lambda ip: tuple(map(int, ip.split('.'))))
    attacked_destinations.sort(key=lambda ip: tuple(map(int, ip.split('.'))))
    destination_ports.sort(key=int)

    included_attacks = 0
    total_attacks = 0
    included_bw = 0
    total_bw = 0
    included_packets = 0
    total_packets = 0
    protocols_bw = {}
    protocols_packets = {}
    for dp,data in attack_data.items():
        for attack in data['data']:
            if attack['row']['attackIpsId'] in top_n_attack_ids:
                included_attacks += 1
                included_bw += int(attack['row'].get('packetBandwidth', 0))
                included_packets += int(attack['row'].get('packetCount', 0))
                protocols_bw[attack['row'].get('protocol',"N/A")] = int(attack['row'].get('packetBandwidth', 0)) + int(protocols_bw.get(attack['row'].get('protocol',"N/A"),0))
                protocols_packets[attack['row'].get('protocol',"N/A")] = int(attack['row'].get('packetCount', 0)) + int(protocols_packets.get(attack['row'].get('protocol',"N/A"),0))
                #protocols_packets[attack['row'].get('protocol',"N/A")] += int(attack['row'].get('packetCount', 0))
            total_attacks += 1
            total_bw += int(attack['row'].get('packetBandwidth', 0))
            total_packets += int(attack['row'].get('packetCount', 0))

    output = f"""
<div style="line-height: 1.5; text-align: center;">
    <table style="width: 80%; margin: 0 auto; border-collapse: collapse;">
        <!-- Attack timeframe -->
        <tr style="border: none;">
            <td style="border: none; text-align: right;"><strong>Attack Timeframe:</strong></td>
            <td style="border: none; text-align: left;">Top {topN} attacks were observed over a <strong>{elapsed_time}</strong> time period from <strong>{first_attack_start.strftime('%d-%m-%Y %H:%M:%S %Z') if first_attack_start else "N/A"}</strong> to <strong>{last_attack_end.strftime('%d-%m-%Y %H:%M:%S %Z') if last_attack_end else "N/A"}</strong></td>
        </tr>

        <!-- Attack Vectors -->
        <tr style="border: none;">
            <td style="border: none; text-align: right;"><strong>Attack Vectors:</strong></td>
            <td style="border: none; text-align: left;">The following attack vectors were observed (highest bandwidth is listed first): <strong>{', '.join(vectors)}</strong></td>
        </tr>

        <!-- Peak Attack Rate -->
        <tr style="border: none;">
            <td style="border: none; text-align: right;"><strong>Peak Attack Rate:</strong></td>
            <td style="border: none; text-align: left;">
                Throughput per second peaked at <strong>{peak_traffic['bps']} kbps</strong>. This occurred at <strong>{datetime.datetime.fromtimestamp(peak_traffic['bps_time']/1000, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S %Z') if peak_traffic['bps_time'] else "N/A"}</strong><br>
                Packets per second peaked at <strong>{peak_traffic['pps']} pps</strong>. This occurred at <strong>{datetime.datetime.fromtimestamp(peak_traffic['pps_time']/1000, tz=datetime.timezone.utc).strftime('%d-%m-%Y %H:%M:%S %Z') if peak_traffic['pps_time'] else "N/A"}</strong>
            </td>
        </tr>

        <!-- Attacked Destinations -->
        <tr style="border: none;">
            <td style="border: none; text-align: right;"><strong>Attacked Destinations:</strong></td>
            <td style="border: none; text-align: left;">
                Attacks were identified against <strong>{len(attacked_destinations)} destination ip addresses</strong> and <strong>{len(destination_ports)} destination ports.</strong><br>
                IPs: {", ".join(attacked_destinations)}<br>
                Ports: {", ".join(destination_ports)}
            </td>
        </tr>

        <!-- Attack Sources -->
        <tr style="border: none;">
            <td style="border: none; text-align: right;"><strong>Attack Sources:</strong></td>
            <td style="border: none; text-align: left;">
                Sampled data includes attacks from at least <strong>{len(attack_sources)} unique source ip addresses</strong><br>
                <!--{", ".join(attack_sources)}-->
            </td>
        </tr>

        <!-- Attack Protocols -->
        <tr style="border: none;">
            <td style="border: none; text-align: right;"><strong>Attack Protocols:</strong></td>
            <td style="border: none; text-align: left;">
                By bandwidth: {", ".join([f"{key}({value / included_bw * 100:.2f}%)" for key, value in protocols_bw.items()])} <br>
                By packet count: {", ".join([f"{key}({value / included_packets * 100:.2f}%)" for key, value in protocols_packets.items()])} <br>
            </td>
        </tr>

        <!-- TopN Analysis -->
        <tr style="border: none;">
            <td style="border: none; text-align: right;"><strong>TopN Coverage:</strong></td>
            <td style="border: none; text-align: left;">
                Of the <strong>{total_attacks} total attacks</strong> observed over the specified time period, this report is filtered based on the <strong>{included_attacks} unique attacks</strong> included in the <strong>Top {topN} bps</strong> and <strong>Top {topN} pps</strong> tables.<br>
                These <strong>{included_attacks} attacks</strong> represent <strong>{(included_bw / total_bw):.2% if total_bw > 0 else "0%"}</strong> of the total attack bandwidth and <strong>{(included_packets / total_packets):.2% if total_packets > 0 else "0%"}</strong> of the total attack packet count.<br>
                The <strong>remaining {total_attacks - included_attacks} attacks</strong> represent <strong>{((total_bw - included_bw) / total_bw):.2% if total_bw > 0 else "0%"}</strong> of the observed attack bandwidth and <strong>{((total_packets - included_packets) / total_packets):.2% if total_packets > 0 else "0%"}</strong> if the observed attack packets.
            </td>
        </tr>
    </table>
</div>
"""
    return output



def highest_aggregate_15_seconds(myData):
    """This function finds the peak 15-second pps and bps time periods in 'combined graphs' data.
    It is currently unused."""
    # Function to round timestamp to the nearest 15 seconds
    def round_to_nearest_15_seconds(timestamp):
        return round(timestamp / 15000) * 15000

    # Dictionary to store aggregated values for each 15-second window
    aggregated_data = {}
    max_pps = 0
    max_bps = 0
    max_pps_time = None
    max_bps_time = None

    for dataset in myData.values():
        for item in dataset["data"]:
            timestamp = item["row"]["timeStamp"]
            rounded_time = round_to_nearest_15_seconds(timestamp)

            # Initialize the aggregated values for this time period if not already present
            if rounded_time not in aggregated_data:
                aggregated_data[rounded_time] = {'Pps': 0, 'Bps': 0}

            # Aggregate "Pps" and "Bps" values for each rounded timestamp
            if "Pps" in item["row"]:
                aggregated_data[rounded_time]['Pps'] += float(item["row"]["Pps"])
            if "Bps" in item["row"]:
                aggregated_data[rounded_time]['Bps'] += float(item["row"]["Bps"])

    # Find the highest aggregate for both "Pps" and "Bps" and track their timestamps
    for timestamp, values in aggregated_data.items():
        if values['Pps'] > max_pps:
            max_pps = values['Pps']
            max_pps_time = timestamp
        if values['Bps'] > max_bps:
            max_bps = values['Bps']
            max_bps_time = timestamp

    return {
        "pps": "{:,}".format(int(max_pps)),
        "bps": "{:,}".format(int(max_bps)),
        "pps_time": max_pps_time,
        "bps_time": max_bps_time
    }