# splunk-detections
A custom Splunk detection rule and scheduled alert designed to hunt for indicators of compromise (IoCs) associated with the recent threat actor infrastructure targeting cryptocurrency platforms (Binance security incident). The rule leverages Sysmon endpoint telemetry (EventCode=1 Process Creation) to cross-reference incoming endpoint executions.
