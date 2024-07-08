import json
from datetime import datetime

def createGraphHTML(BPSjson,PPSjson):
    if BPSjson is None:
        print("Setting bps")
        BPSjson = TEMP_PopulateData()

    if PPSjson is None:
        print("setting pps ")
        PPSjson = TEMP_PopulateData()
    #Add HTML head and chart initialization info
    outStr = """
    <script type="text/javascript">
      google.charts.load('current', {'packages':['corechart']});
      google.charts.setOnLoadCallback(drawBPSChart);
      function drawBPSChart() {
        var data = google.visualization.arrayToDataTable([
        [ { label: 'Time', type: 'date'}, { label: 'Challenged', type: 'number'}, { label: 'Excluded', type: 'number'}, { label: 'Received', type: 'number'}, { label: 'Dropped', type: 'number'}]"""
    for row in BPSjson['data']:
        #%d-%m-%Y 
        outStr += f",\n        [new Date({row['row']['timeStamp']}), {row['row']['challengeIng']}, {row['row']['excluded']}, {row['row']['trafficValue']}, {row['row']['discards']}]"

    outStr += "]);"
    outStr += OptionsHTML("BPS")
    outStr += """

        var chart = new google.visualization.AreaChart(document.getElementById('bpsChart'));

        chart.draw(data, options);
      }
      google.charts.setOnLoadCallback(drawPPSChart);
      function drawPPSChart() {
        var data = google.visualization.arrayToDataTable([
        [ { label: 'Time', type: 'date'}, { label: 'Challenged', type: 'number'}, { label: 'Excluded', type: 'number'}, { label: 'Received', type: 'number'}, { label: 'Dropped', type: 'number'}]"""
    for row in PPSjson['data']:
        #%d-%m-%Y 
        outStr += f",\n        [new Date({row['row']['timeStamp']}), {row['row']['challengeIng']}, {row['row']['excluded']}, {row['row']['trafficValue']}, {row['row']['discards']}]"

    outStr += "]);"
    outStr += OptionsHTML("PPS")
    outStr += """
        var chart = new google.visualization.AreaChart(document.getElementById('ppsChart'));

        chart.draw(data, options);
      }
    </script>

    <div id="bpsChart" style="width: 90%; height: 500px"></div>
    <div id="ppsChart" style="width: 90%; height: 500px"></div>
"""
    return outStr

def TEMP_PopulateData():
    return {'metaData': {'totalTime': '0.075 sec.'}, 'data': [{'row': {'timeStamp': '1720444500000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720444800000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720445100000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720445400000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720445700000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720446000000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720446300000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720446600000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720446900000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720447200000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720447500000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720447800000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720448100000', 'excluded': '0.0', 'discards': '0.0', 'trafficValue': '0.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720448400000', 'excluded': '0.0', 'discards': '314.0', 'trafficValue': '689.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720448700000', 'excluded': '0.0', 'discards': '7101.0', 'trafficValue': '7101.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720449000000', 'excluded': '0.0', 'discards': '7015.0', 'trafficValue': '7015.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720449300000', 'excluded': '0.0', 'discards': '7010.0', 'trafficValue': '7010.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720449600000', 'excluded': '0.0', 'discards': '7162.0', 'trafficValue': '7162.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720449900000', 'excluded': '0.0', 'discards': '7087.0', 'trafficValue': '7087.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720450200000', 'excluded': '0.0', 'discards': '7032.0', 'trafficValue': '7032.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720450500000', 'excluded': '0.0', 'discards': '7221.0', 'trafficValue': '7221.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720450800000', 'excluded': '0.0', 'discards': '7047.0', 'trafficValue': '7047.0', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720451100000', 'excluded': '0.0', 'discards': '7005.6', 'trafficValue': '7005.6', 'challengeIng': '0.0'}}, {'row': {'timeStamp': '1720451400000', 'excluded': '0.0', 'discards': '7020.6', 'trafficValue': '7020.6', 'challengeIng': '0.0'}}], 'dataMap': {'minValue': {'timeStamp': '1720444500000', 'deviceIp': '155.1.1.7', 'policyName': 'All', 'trafficValue': '0.0'}, 'maxValue': {'timeStamp': '1720450500000', 'deviceIp': '155.1.1.7', 'policyName': 'All', 'trafficValue': '7221.0'}}}

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
            vAxis: {viewWindow: {min:0} },
            hAxis: {format: 'hh:mm:ss', slantedText:true, slantedTextAngle:45},
            series: {
                0: { labelInLegend: 'Challenged', color: "#ff8f00"},
                1: { labelInLegend: 'Excluded', color: "#807be0"},
                2: { labelInLegend: 'Received', color: "#088eb1"},
                3: { labelInLegend: 'Dropped', color: "#f41414"},
            },
        };"""
    return output
    