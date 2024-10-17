def generate_sample_data_section(title, sample_data):
    # Generate a sample data table (used for both BPS and PPS)
    html_content = f"<h2>{title}</h2><table border='1' cellpadding='5' cellspacing='0'>"
    html_content += """
        <tr>
            <th>Attack ID</th>
            <th>Source Address</th>
            <th>Source Port</th>
            <th>Destination Address</th>
            <th>Destination Port</th>
        </tr>
    """
    if sample_data:
        for entry in sample_data:
            for attack_id, samples in entry.items():
                for sample in samples:
                    html_content += f"""
                    <tr>
                        <td>{attack_id}</td>
                        <td>{sample.get('sourceAddress', 'N/A')}</td>
                        <td>{sample.get('sourcePort', 'N/A')}</td>
                        <td>{sample.get('destAddress', 'N/A')}</td>
                        <td>{sample.get('destPort', 'N/A')}</td>
                    </tr>
                    """
    else:
        html_content += """
        <tr>
            <td colspan="5">No sample data available</td>
        </tr>
        """

    html_content += "</table>"
    return html_content

def generate_html_report(top_by_bps, top_by_pps, unique_protocols, count_above_threshold, bps_data, pps_data, unique_ips_bps, unique_ips_pps, top_n=10, threshold_gbps=0.02):
    # Generate HTML content for the report
    html_content = f"""
    <html>
    <head>
        <title>Attack Report</title>
        <style>
            table {{
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
            }}
            th, td {{
                border: 1px solid black;
                padding: 8px;
                text-align: left;
            }}
            th {{
                background-color: #f2f2f2;
            }}
            h2 {{
                text-align: center;
            }}
            pre {{
                white-space: pre-wrap; /* Wraps long text and preserves formatting */
            }}
            .above-threshold {{
                background-color: #ffcccc;
            }}
            .collapsible {{
                background-color: #777;
                color: white;
                cursor: pointer;
                padding: 10px;
                width: 100%;
                border: none;
                text-align: left;
                outline: none;
                font-size: 15px;
            }}
            .active, .collapsible:hover {{
                background-color: #555;
            }}
            .content {{
                padding: 0 18px;
                display: none;
                overflow: hidden;
                background-color: #f9f9f9;
            }}
            .copy-button {{
                background-color: #f2f2f2;
                color: black;
                border: None;
                padding: 5px;
                cursor: pointer;
                font-size: 12px;
                font-weight: bold;
                margin-left: 5px;
            }}
        </style>
        <script>
            function toggleContent(id) {{
                var content = document.getElementById(id);
                if (content.style.display === "table-row") {{
                    content.style.display = "none";
                }} else {{
                    content.style.display = "table-row";
                }}
            }}

            function copyColumnData(className) {{
                var text = "";
                var elements = document.getElementsByClassName(className);
                for (var i = 0; i < elements.length; i++) {{
                    text += elements[i].innerText + "\\n";
                }}
                navigator.clipboard.writeText(text).then(function() {{
                    alert("Copied to clipboard");
                }}, function(err) {{
                    alert("Failed to copy");
                }});
            }}
        </script>
    </head>
    <body>
        <h2>Attack Report - Top {top_n} Sorted by Max Attack Rate (BPS)</h2>
        <p>Attack Vectors for the top {top_n} attacks: {', '.join(unique_protocols)}</p>
        <p>Out of the top {top_n} attacks, {count_above_threshold} attacks were greater than {threshold_gbps} Gbps.</p>
        <table>
            <tr>
                <th>Start Time</th>
                <th>End Time</th>
                <th>Attack ID</th>
                <th>BDOS Lifecycle log attack ID</th>
                <th>Device IP</th>
                <th>Policy</th>
                <th>Attack Category</th>
                <th>Attack Name</th>
                <th>Threat Group</th>
                <th>Protocol</th>
                <th>Action</th>
                <th>Attack Status</th>
                <th>Max Attack Rate (Gbps)</th>
                <th>Max Attack Rate (PPS)</th>
                <th>Final Footprint</th>
                <th>BDOS Life Cycle</th>
                <th>Sample Data</th>
            </tr>
    """

    # Add top_by_bps data
    for syslog_id, details in top_by_bps:
        metrics_summary = details.get('metrics_summary', 'N/A')

        # Safely convert Max_Attack_Rate_BPS to float
        max_attack_rate_bps_str = details.get('Max_Attack_Rate_BPS', '0')
        try:
            max_attack_rate_bps = float(max_attack_rate_bps_str)
        except (ValueError, TypeError):
            max_attack_rate_bps = 0.0

        # Row class based on threshold
        row_class = ''

        # Main row
        html_content += f"""
            <tr class="{row_class}">
                <td>{details.get('Start Time', 'N/A')}</td>
                <td>{details.get('End Time', 'N/A')}</td>
                <td>{details.get('Attack ID', 'N/A')}</td>
                <td>{syslog_id}</td>
                <td>{details.get('Device IP', 'N/A')}</td>
                <td>{details.get('Policy', 'N/A')}</td>
                <td>{details.get('Attack Category', 'N/A')}</td>
                <td>{details.get('Attack Name', 'N/A')}</td>
                <td>{details.get('Threat Group', 'N/A')}</td>
                <td>{details.get('Protocol', 'N/A')}</td>
                <td>{details.get('Action', 'N/A')}</td>
                <td>{details.get('Attack Status', 'N/A')}</td>
                <td>{details.get('Max_Attack_Rate_Gbps', 'N/A')}</td>
                <td>{details.get('Max_Attack_Rate_PPS_formatted', 'N/A')}</td>
                <td>{details.get('Final Footprint', 'N/A')}</td>
                <td><pre>{metrics_summary}</pre></td>
                <td><button type="button" class="collapsible" onclick="toggleContent('bps_{details.get('Attack ID', 'N/A')}')">Show Sample Data</button></td>
            </tr>
        """

        # Collapsible row for sample data (initially hidden)
        html_content += f"""
            <tr id="bps_{details.get('Attack ID', 'N/A')}" style="display:none;">
                <td colspan="17">
                    <table>
                        <tr>
                            <th>Source Address <button class="copy-button" onclick="copyColumnData('bps-source-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                            <th>Source Port <button class="copy-button" onclick="copyColumnData('bps-source-port-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                            <th>Destination Address <button class="copy-button" onclick="copyColumnData('bps-dest-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                            <th>Destination Port <button class="copy-button" onclick="copyColumnData('bps-dest-port-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                        </tr>
        """
        # Check if there are sample data
        sample_found = False
        for entry in bps_data:
            for attack_id, samples in entry.items():
                if attack_id == details.get('Attack ID', 'N/A'):
                    if samples:  # If samples exist
                        sample_found = True
                        for sample in samples:
                            html_content += f"""
                            <tr>
                                <td class="bps-source-{details.get('Attack ID', 'N/A')}">{sample.get('sourceAddress', 'N/A')}</td>
                                <td class="bps-source-port-{details.get('Attack ID', 'N/A')}">{sample.get('sourcePort', 'N/A')}</td>
                                <td class="bps-dest-{details.get('Attack ID', 'N/A')}">{sample.get('destAddress', 'N/A')}</td>
                                <td class="bps-dest-port-{details.get('Attack ID', 'N/A')}">{sample.get('destPort', 'N/A')}</td>
                            </tr>
                            """

        if not sample_found:
            html_content += """
                            <tr>
                                <td colspan="4">No sample data available</td>
                            </tr>
            """

        html_content += "</table></td></tr>"

    # Close the attack report table for BPS
    html_content += "</table>"

    # Add PPS report header (similar structure with copy functionality)
    html_content += f"<h2>Attack Report - Top {top_n} Sorted by Max Attack Rate (PPS)</h2>"
    html_content += "<table>"
    html_content += """
            <tr>
                <th>Start Time</th>
                <th>End Time</th>
                <th>Attack ID</th>
                <th>BDOS Lifecycle log attack ID</th>
                <th>Device IP</th>
                <th>Policy</th>
                <th>Attack Category</th>
                <th>Attack Name</th>
                <th>Threat Group</th>
                <th>Protocol</th>
                <th>Action</th>
                <th>Attack Status</th>
                <th>Max Attack Rate (Gbps)</th>
                <th>Max Attack Rate (PPS)</th>
                <th>Final Footprint</th>
                <th>BDOS Life Cycle</th>
                <th>Sample Data</th>
            </tr>
    """

    # Add top_by_pps data
    for syslog_id, details in top_by_pps:
        metrics_summary = details.get('metrics_summary', 'N/A')

        # Safely convert Max_Attack_Rate_PPS to float
        max_attack_rate_pps_str = details.get('Max_Attack_Rate_PPS', '0')
        try:
            max_attack_rate_pps = float(max_attack_rate_pps_str)
        except (ValueError, TypeError):
            max_attack_rate_pps = 0.0

        # Row class based on threshold
        row_class = ''

        # Main row
        html_content += f"""
            <tr class="{row_class}">
                <td>{details.get('Start Time', 'N/A')}</td>
                <td>{details.get('End Time', 'N/A')}</td>
                <td>{details.get('Attack ID', 'N/A')}</td>
                <td>{syslog_id}</td>
                <td>{details.get('Device IP', 'N/A')}</td>
                <td>{details.get('Policy', 'N/A')}</td>
                <td>{details.get('Attack Category', 'N/A')}</td>
                <td>{details.get('Attack Name', 'N/A')}</td>
                <td>{details.get('Threat Group', 'N/A')}</td>
                <td>{details.get('Protocol', 'N/A')}</td>
                <td>{details.get('Action', 'N/A')}</td>
                <td>{details.get('Attack Status', 'N/A')}</td>
                <td>{details.get('Max_Attack_Rate_Gbps', 'N/A')}</td>
                <td>{details.get('Max_Attack_Rate_PPS_formatted', 'N/A')}</td>
                <td>{details.get('Final Footprint', 'N/A')}</td>
                <td><pre>{metrics_summary}</pre></td>
                <td><button type="button" class="collapsible" onclick="toggleContent('pps_{details.get('Attack ID', 'N/A')}')">Show Sample Data</button></td>
            </tr>
        """

        # Collapsible row for sample data (initially hidden)
        html_content += f"""
            <tr id="pps_{details.get('Attack ID', 'N/A')}" style="display:none;">
                <td colspan="17">
                    <table>
                        <tr>
                            <th>Source Address <button class="copy-button" onclick="copyColumnData('pps-source-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                            <th>Source Port <button class="copy-button" onclick="copyColumnData('pps-source-port-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                            <th>Destination Address <button class="copy-button" onclick="copyColumnData('pps-dest-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                            <th>Destination Port <button class="copy-button" onclick="copyColumnData('pps-dest-port-{details.get('Attack ID', 'N/A')}')">Copy</button></th>
                        </tr>
        """
        # Check if there are sample data
        sample_found = False
        for entry in pps_data:
            for attack_id, samples in entry.items():
                if attack_id == details.get('Attack ID', 'N/A'):
                    if samples:  # If samples exist
                        sample_found = True
                        for sample in samples:
                            html_content += f"""
                            <tr>
                                <td class="pps-source-{details.get('Attack ID', 'N/A')}">{sample.get('sourceAddress', 'N/A')}</td>
                                <td class="pps-source-port-{details.get('Attack ID', 'N/A')}">{sample.get('sourcePort', 'N/A')}</td>
                                <td class="pps-dest-{details.get('Attack ID', 'N/A')}">{sample.get('destAddress', 'N/A')}</td>
                                <td class="pps-dest-port-{details.get('Attack ID', 'N/A')}">{sample.get('destPort', 'N/A')}</td>
                            </tr>
                            """

        if not sample_found:
            html_content += """
                            <tr>
                                <td colspan="4">No sample data available</td>
                            </tr>
            """

        html_content += "</table></td></tr>"

    # Close the attack report table for PPS
    html_content += "</table>"
    
    unique_ips_bps = [ip.strip() for ip in unique_ips_bps]
    unique_ips_pps = [ip.strip() for ip in unique_ips_pps]
    combined_unique_ips = list(set(unique_ips_bps + unique_ips_pps))

    # Generate HTML content for combined unique IPs as a table
    html_content += """
    <h2> Unique Sample Source IPs</h2>
    <button onclick="copyIPs()">Copy IPs</button>
    <button onclick="toggleTable()">Show Source IP Table</button>
    <div id="ipTableContainer" style="display: none;">
        <table border="1" style="width: 100%; border-collapse: collapse;">
            <thead>
                <tr>
                    <th style="height: 30px;">Unique IPs</th>
                </tr>
            </thead>
            <tbody>
    """

    # Populate the table with the combined unique IPs
    for ip in combined_unique_ips:
        html_content += f"""
        <tr style="height: 30px;">
            <td>{ip}</td>
        </tr>
        """

    html_content += """
            </tbody>
        </table>
    </div>
    </body>
    <script>
    function copyIPs() {
        // Get all the IPs from the table
        var ipList = "";
        var table = document.querySelector('table');
        for (var i = 1, row; row = table.rows[i]; i++) {
            ipList += row.cells[0].innerText + '\\n'; // Get IP from the first cell
        }
        // Copy the list to clipboard
        navigator.clipboard.writeText(ipList).then(function() {
            alert('IP addresses copied to clipboard!');
        }, function(err) {
            alert('Failed to copy: ', err);
        });
    }

    function toggleTable() {
        var tableContainer = document.getElementById("ipTableContainer");
        if (tableContainer.style.display === "block") {
            tableContainer.style.display = "none";
        } else {
            tableContainer.style.display = "block";
        }
    }
    </script>
    </html>
    """

    return html_content



def get_top_n(syslog_details, top_n=10, threshold_gbps=0.02):
    threshold_bps = threshold_gbps * 1e9

    # Sort by Max_Attack_Rate_BPS and Max_Attack_Rate_PPS
    sorted_by_bps = sorted(
        syslog_details.items(),
        key=lambda item: float(item[1].get('Max_Attack_Rate_BPS', '0').replace(' ', '')),
        reverse=True
    )

    sorted_by_pps = sorted(
        syslog_details.items(),
        key=lambda item: float(item[1].get('Max_Attack_Rate_PPS', '0').replace(' ', '')),
        reverse=True
    )

    # Get top N from both sorted lists
    top_by_bps = sorted_by_bps[:top_n]
    top_by_pps = sorted_by_pps[:top_n]

    # Count how many top BPS exceed the threshold
    count_above_threshold = sum(
        1 for syslog_id, details in top_by_bps
        if float(details.get('Max_Attack_Rate_BPS', '0').replace(' ', '')) > threshold_bps
    )

    # Collect unique protocols from top_by_bps
    unique_protocols = {details.get('Protocol', 'N/A') for syslog_id, details in top_by_bps}

    return top_by_bps, top_by_pps, unique_protocols, count_above_threshold
