import common


def getSummary(data):
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
    