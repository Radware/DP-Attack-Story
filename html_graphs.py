import json
import random
from datetime import datetime
import time
import math


# def get_outer_times(data):
#     min_start_time = float('inf')
#     max_end_time = float('0')

#     for key, value in data.items():
#         start_time = datetime.strptime(value['Start Time'], '%d-%m-%Y %H:%M:%S')
#         end_time = datetime.strptime(value['End Time'], '%d-%m-%Y %H:%M:%S')

#         start_epoch = time.mktime(start_time.timetuple())
#         end_epoch = time.mktime(end_time.timetuple())

#         if start_epoch < min_start_time:
#             min_start_time = start_epoch
#         if end_epoch > max_end_time:
#             max_end_time = end_epoch
#     return (min_start_time, max_end_time)


def makeEmptyList(minTime, maxTime, entries):
    '''Initialize our table. First row will be headers. First entry will be "Timestamp". Each row will start with a timestamp value.'''
    out = []
    out.append(["TimeStamp"])
    duration = float(maxTime - minTime)
    interval = float(duration / entries)
    for x in range(0, entries):
        out.append([math.ceil(minTime + (x * interval))])
    pass
    return out


def TEMP_PopulateData():
    return {'metaData': {'totalTime': '0.075 sec.'}, 'data': [{'row': {'timeStamp': '1720444500000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720444800000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720445100000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720445400000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720445700000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720446000000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720446300000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720446600000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720446900000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720447200000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720447500000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720447800000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720448100000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720448400000', 'excluded': '0.0', 'discards': '314.0', 'trafficValue': '689.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720448700000', 'excluded': '0.0', 'discards': '7101.0', 'trafficValue': '7101.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720449000000', 'excluded': '0.0', 'discards': '7015.0', 'trafficValue': '7015.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720449300000', 'excluded': '0.0', 'discards': '7010.0', 'trafficValue': '7010.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720449600000', 'excluded': '0.0', 'discards': '7162.0', 'trafficValue': '7162.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720449900000', 'excluded': '0.0', 'discards': '7087.0', 'trafficValue': '7087.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720450200000', 'excluded': '0.0', 'discards': '7032.0', 'trafficValue': '7032.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720450500000', 'excluded': '0.0', 'discards': '7221.0', 'trafficValue': '7221.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720450800000', 'excluded': '0.0', 'discards': '7047.0', 'trafficValue': '7047.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720451100000', 'excluded': '0.0', 'discards': '7005.6', 'trafficValue': '7005.6', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720451400000', 'excluded': '0.0', 'discards': '7020.6', 'trafficValue': '7020.6', 'challengeIng': '0.0'}}], 'dataMap': {'minValue': {'timeStamp': '1720444500000', 'deviceIp': '155.1.1.7', 'policyName': 'All', 'trafficValue': '0.0'}, 'maxValue': {'timeStamp': '1720450500000', 'deviceIp': '155.1.1.7', 'policyName': 'All', 'trafficValue': '7221.0'}}}


def graphPrerequesites():
    outStr = ""
    #Workaround function to prevent google charts from auto-converting timezones to local time.
    outStr += """
<script type="text/javascript">
    function correctedDate(inputTime) {
    var date = new Date(inputTime);
    var timezoneOffset = date.getTimezoneOffset();
    var adjustedTime = new Date(inputTime + timezoneOffset * 60 * 1000);
    return adjustedTime;
    }
</script>
"""
    return outStr


def createTopGraphsHTML(BPSjson,PPSjson):
    outStr = """
    <script type="text/javascript">
      google.charts.load('current', {'packages':['corechart']});
      google.charts.setOnLoadCallback(drawBPSChart);
      function drawBPSChart() {
        var data = google.visualization.arrayToDataTable([
        [ { label: 'Time', type: 'datetime'}, { label: 'Challenged', type: 'number'}, { label: 'Excluded', type: 'number'}, { label: 'Received', type: 'number'}, { label: 'Dropped', type: 'number'}]"""
    for row in BPSjson['data']:
        #%d-%m-%Y 
        if row['row']['challengeIng'] and row['row']['excluded'] and row['row']['trafficValue'] and {row['row']['discards']}:
            outStr += f",\n        [correctedDate({row['row']['timeStamp']}), {row['row']['challengeIng']}, {row['row']['excluded']}, {row['row']['trafficValue']}, {row['row']['discards']}]"

    outStr += "]);"
    outStr += OptionsHTML("Full Time Range Max BPS (UTC)")
    outStr += """
        var chart = new google.visualization.AreaChart(document.getElementById('bpsChart'));

        chart.draw(data, options);
      }
      google.charts.setOnLoadCallback(drawPPSChart);
      function drawPPSChart() {
        var data = google.visualization.arrayToDataTable([
        [ { label: 'Time', type: 'datetime'}, { label: 'Challenged', type: 'number'}, { label: 'Excluded', type: 'number'}, { label: 'Received', type: 'number'}, { label: 'Dropped', type: 'number'}]"""
    for row in PPSjson['data']:
        #%d-%m-%Y 
        if row['row']['challengeIng'] and row['row']['excluded'] and row['row']['trafficValue'] and {row['row']['discards']}:
            outStr += f",\n        [correctedDate({row['row']['timeStamp']}), {row['row']['challengeIng']}, {row['row']['excluded']}, {row['row']['trafficValue']}, {row['row']['discards']}]"

    outStr += "]);"
    outStr += OptionsHTML("Full Time Range Max PPS (UTC)")
    outStr += """
        var chart = new google.visualization.AreaChart(document.getElementById('ppsChart'));

        chart.draw(data, options);
      }
    </script>

    <div id="bpsChart" style="width: 90%; height: 500px"></div>
    <div id="ppsChart" style="width: 90%; height: 500px"></div>
"""
    return outStr


def OptionsHTML(Title):
    output =  """
        var options = {
            title: '"""
    output += Title
    output +="""',
            curveType: 'function',
            width: '100%',
            legend: { position: 'bottom' },
            annotations: { style: 'line'},
            displayAnnotations: true,
            focusTarget: 'category',
            vAxis: {
                viewWindow: {min:0}
            },
            hAxis: {format: 'HH:mm:ss', slantedText:true, slantedTextAngle:45, title: 'Time (UTC)',},
            series: {
                0: { labelInLegend: 'Challenged', color: "#ff8f00"},
                1: { labelInLegend: 'Excluded', color: "#807be0"},
                2: { labelInLegend: 'Received', color: "#088eb1"},
                3: { labelInLegend: 'Dropped', color: "#f41414"},
            },
            tooltip: {
                isHtml: true,
                format: 'MMM d, y, HH:mm:ss'  // Ensure full date and time are shown in the tooltip
            }
        };"""
    return output
    

def createChart(Title, myData, epoch_from, epoch_to):
 

    name = f'graph_{Title.replace(" ","_").replace("-","_")}'

    # Sort the data by the timestamp
    sorted_data = sorted(myData["data"], key=lambda item: item["row"]["timeStamp"])

    # Extracting timestamps and formatting them as new Date objects in GMT
    timestamps = [int(item["row"]["timeStamp"]) for item in sorted_data]
    #labels = [f"new Date({ts} + (new Date().getTimezoneOffset() * 60000))" for ts in timestamps]
    labels = [f"correctedDate({ts})" for ts in timestamps]

    # Prepare the data for Google Charts
    data_table = [["Timestamp"] + [key for key in sorted_data[0]["row"].keys() if key != "timeStamp" and key != "footprint"]]
    for i, item in enumerate(sorted_data):
        row = [labels[i]]
        for key in data_table[0][1:]:
            value = item["row"].get(key)
            row.append(float(value) if value is not None else None)
        data_table.append(row)

    # Annotations for footprints
    annotations = []
    for idx, item in enumerate(sorted_data):
        if "footprint" in item["row"] and item["row"]["footprint"] is not None:
            annotations.append(f"{{x: {idx + 1}, shortText: 'F', text: 'Footprint detected', color: 'red'}}")

    # Convert data_table to JSON and replace the quotes around Date objects
    json_data = json.dumps(data_table)
    #json_data = json_data.replace('"new Date(', 'new Date(').replace(')"', ')')
    json_data = json_data.replace('"correctedDate(', 'correctedDate(').replace(')"', ')')

    # Generate HTML content dynamically
    html_content = f"""
    <script type="text/javascript">
        //google.charts.load('current', {{'packages':['corechart', 'annotationchart']}});
        google.charts.setOnLoadCallback(drawChart_{name});
        function drawChart_{name}() {{
            var data = google.visualization.arrayToDataTable({json_data});
            var epoch_from = correctedDate({epoch_from});
            var epoch_to = correctedDate({epoch_to});
            var options = {{
                title: '{Title}',
                curveType: 'function',
                legend: {{ position: 'bottom' }},
                annotations: {{
                    style: 'line',
                    textStyle: {{
                        fontSize: 12,
                        bold: true,
                        color: 'red'
                    }},
                    stem: {{
                        color: 'red',
                        length: 8
                    }}
                }},
                alwaysOutside: true,
                displayAnnotations: true,
                focusTarget: 'category',
                vAxis: {{viewWindow: {{min:0}} }},
                hAxis: {{format: 'HH:mm:ss', slantedText:true, slantedTextAngle:45, title: 'Time (UTC)'}},
                series: {{
                    0: {{ color: '#ff8f00' }},
                    1: {{ color: '#807be0' }},
                    2: {{ color: '#088eb1' }},
                    3: {{ color: '#f41414' }},
                    4: {{ color: '#1c91c0' }},
                    5: {{ color: '#43459d' }},
                }}
            }};
            var miniOptions = {{
                title: null,
                width: 100,  
                height: 50, 
                chartArea: {{
                    left: 0,
                    top: 0,
                    width: '100%',
                    height: '100%'
                }},
                legend: {{ position: 'none' }}, // Hide the legend for the mini chart
                focusTarget: null,
                hAxis: {{ 
                    textPosition: 'none', 
                    gridlines: {{ count: 0 }}, 
                    ticks: [],
                    minValue: correctedDate({epoch_from}),
                    maxValue: correctedDate({epoch_to})
                }}, // Hide x-axis text for compactness
                vAxis: {{ 
                    textPosition: 'none', 
                    gridlines: {{ count: 0 }}, 
                    ticks: [], 
                    viewWindow: {{min:0}} }}, // Hide y-axis text for compactness
            }};
            
            function drawChart(containerId, data, options) {{
                var container = document.getElementById(containerId);
                if (container !== null) {{
                    var chart = new google.visualization.LineChart(container);
                    chart.draw(data, options);
                }}
            }}

            // Draw the main chart
            drawChart('{name}-bottom', data, options);

            // Draw the top charts
            drawChart('{name}-top_n_pps', data, options);
            drawChart('{name}-top_n_bps', data, options);

            drawChart('{name}-bpsmini', data, {{ ...options, ...miniOptions }});
            drawChart('{name}-ppsmini', data, {{ ...options, ...miniOptions }});

            var chart_annotations = {json.dumps(annotations)};
            chart_annotations.forEach(function(annotation) {{
                chart.setAnnotation(annotation);
            }});
        }}
    </script>
    <div id="{name}-bottom" style="width: 100%; height: 500px;"></div>
    """
    return html_content


def createCombinedChart(Title, myData):
    # Generate a random ID for the chart name
    rand_ID = random.randrange(100000000, 999999999)
    name = f'draw_{Title.replace(" ","_").replace("-","_")}_{str(rand_ID)}'

    # Function to round timestamp to the nearest 15 seconds
    def round_to_nearest_15_seconds(timestamp):
        return round(timestamp / 15000) * 15000

    # Collect all timestamps from all datasets, rounding them to the nearest 15 seconds
    timestamps = sorted(set(round_to_nearest_15_seconds(item["row"]["timeStamp"]) for dataset in myData.values() for item in dataset["data"]))

    # Initialize data structure for Google Charts
    data_table = [["Timestamp"]]
    dataset_headers = {}

    # Add headers for each dataset and metric
    for dataset_name, dataset in myData.items():
        dataset_headers[dataset_name] = []
        try:
            for key in dataset["data"][0]["row"].keys():
                if key != "timeStamp":
                    column_name = f"{dataset_name.replace('_', '__')}__{key}"
                    data_table[0].append(column_name)
                    dataset_headers[dataset_name].append(column_name)
        except:
            print(f"Unexpected error processing {dataset_name}")
            raise

    # Populate data rows based on rounded timestamps
    for timestamp in timestamps:
        #date_object = f"new Date({timestamp} + (new Date().getTimezoneOffset() * 60000))"
        date_object = f"correctedDate({timestamp})"
        row = [date_object] + [None] * (len(data_table[0]) - 1)
        
        for dataset_name, dataset in myData.items():
            for item in dataset["data"]:
                rounded_time = round_to_nearest_15_seconds(item["row"]["timeStamp"])
                if rounded_time == timestamp:
                    for key, value in item["row"].items():
                        if key != "timeStamp" and value is not None:
                            try:
                                numeric_value = float(value)
                                col_index = data_table[0].index(f"{dataset_name.replace('_', '__')}__{key}")
                                row[col_index] = numeric_value
                            except ValueError:
                                continue
                    break
        
        data_table.append(row)

    # Convert data_table to JSON and replace the quotes around Date objects
    json_data = json.dumps(data_table[1:])
    json_data = json_data.replace('"correctedDate(', 'correctedDate(').replace(')"', ')')


    # Generate HTML content dynamically with checkboxes and Date objects for x-axis
    html_content = f"""
        <script type="text/javascript">
            //google.charts.load('current', {{'packages':['corechart']}});
            google.charts.setOnLoadCallback(drawChart);

            let data;
            let chart;
            let bpsView;
            let ppsView;
            let options = {{
                title: '{Title}',
                curveType: 'function',
                legend: {{
                    position: 'top',
                    textStyle: {{ fontSize: 12 }},
                    maxLines: 6
                }},
                hAxis: {{
                    title: 'Time (UTC)',
                    format: 'HH:mm:ss',
                    slantedText: true,
                    slantedTextAngle: 45
                }},
                vAxis: {{
                    viewWindow: {{min: 0}}  // Ensure the y-axis includes 0
                }},
                focusTarget: 'category',
                interpolateNulls: true,
                tooltip: {{
                    isHtml: true
                }},
                series: {{
                    {", ".join([f"{i}: {{ lineDashStyle: [0, 0] }}" for i in range(len(data_table[0]) - 1)])} 
                }},
                colors: [
                    '#e2431e', // Red
                    '#f1ca3a', // Yellow
                    '#6f9654', // Green
                    '#1c91c0', // Blue
                    '#b2c2c8', // Light Gray
                    '#c94c4d', // Dark Red
                    '#e55b1b', // Orange
                    '#4f81bd', // Light Blue
                    '#b689c5', // Lavender
                    '#9bcf0e', // Lime Green
                    '#9b59b6', // Purple
                    '#34495e', // Dark Blue Gray
                    '#e67e22', // Carrot Orange
                    '#d35400', // Pumpkin
                    '#2980b9', // Bright Blue
                    '#f39c12', // Bright Yellow
                    '#16a085', // Turquoise
                    '#2ecc71', // Emerald Green
                    '#3498db', // Light Sky Blue
                    '#9b59b6', // Amethyst
                    '#34495e', // Dark Slate
                    '#95a5a6', // Gray
                    '#e74c3c', // Red
                    '#ecf0f1', // Cloudy Gray
                    '#8e44ad', // Purple
                    '#f1c40f'  // Bright Yellow
                ],
                animation: {{
                    duration: 1000,    // Time in milliseconds for the animation (1 second here)
                    easing: 'inAndOut',     // Easing function for smooth animation ('in', 'out', 'inAndOut' are common options)
                    startup: false      // Ensures that animation happens on chart load
                }}
            }};

            function drawChart() {{
                data = new google.visualization.DataTable();
                data.addColumn('datetime', 'Time');
                {"".join([f"data.addColumn('number', '{col}');" for col in data_table[0][1:]])}
                data.addRows({json_data});
                data.setColumnProperty(1, 'color', '#e2431e'); 
                data.setColumnProperty(2, 'color', '#f1ca3a'); 
                data.setColumnProperty(3, 'color', '#e2431e'); 
                data.setColumnProperty(4, 'color', '#f1ca3a'); 

                // Create a DataView for the BPS chart (odd columns)
                bpsView = new google.visualization.DataView(data);
                let bpsColumns = [0];  // Start with the timestamp column
                for (let i = 2; i < data.getNumberOfColumns(); i += 2) {{
                    bpsColumns.push(i);
                }}
                bpsView.setColumns(bpsColumns);

                // Create a DataView for the PPS chart (even columns)
                ppsView = new google.visualization.DataView(data);
                let ppsColumns = [0];  // Start with the timestamp column
                for (let i = 1; i < data.getNumberOfColumns(); i += 2) {{
                    ppsColumns.push(i);
                }}
                ppsView.setColumns(ppsColumns);

                chartbps = new google.visualization.LineChart(document.getElementById('{name}-bps'));
                chartbps.draw(bpsView, {{...options, title: options.title + ' - BPS'}});
                chartpps = new google.visualization.LineChart(document.getElementById('{name}-pps'));
                chartpps.draw(ppsView, {{...options, title: options.title + ' - PPS'}});
            }}

            function updateChart() {{
                //let bpsView = new google.visualization.DataView(data);
                //let ppsView = new google.visualization.DataView(data);
                let columns = [];
                {''.join(
                    f'if (document.getElementById("{name}_{header}").checked) {{ columns.push({headerindex}); }}' for headerindex, header in enumerate(dataset_headers.keys())
                )}

                evencolumns = [0, ...columns.map(x => (x+1)*2)];
                oddcolumns  = [0, ...columns.map(x => x*2 + 1)];

                bpsView.setColumns(evencolumns);
                chartbps.draw(bpsView, {{...options, title: options.title + ' - BPS', colors: columns.map(index => options.colors[index])}});
                ppsView.setColumns(oddcolumns);
                chartpps.draw(ppsView, {{...options, title: options.title + ' - PPS', colors: columns.map(index => options.colors[index])}});
                
            }}
        </script>
"""
    
    checkboxes_html = ""
    for header in dataset_headers.keys():
        checkbox_html = (
            f'<label>'
            f'<input type="checkbox" id="{name}_{header}" checked onclick="updateChart()"> '
            f'{header.replace("__", " ").replace("_", " ")}'
            f'</label>'
        )
        checkboxes_html += checkbox_html
    column_count = (
        1 if len(dataset_headers) <= 4 else
        2 if len(dataset_headers) <= 8 else
        3 if len(dataset_headers) < 13 else
        4
    )
    html_content += f"""
        <div style="display: grid; grid-template-columns: repeat({column_count}, 1fr); gap: 10px; row-gap: 3px; width:50%;">
            {checkboxes_html}
        </div>
        <div id="{name}-bps" style="width: 100%; height: 500px;"></div>
        <div id="{name}-pps" style="width: 100%; height: 500px;"></div>
    """
    return html_content

    
