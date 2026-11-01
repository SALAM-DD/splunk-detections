# splunk-detections
A custom Splunk detection rule and scheduled alert designed to hunt for indicators of compromise (IoCs) associated with the recent threat actor infrastructure targeting cryptocurrency platforms (Binance security incident). The rule leverages Sysmon endpoint telemetry (EventCode=1 Process Creation) to cross-reference incoming endpoint executions.

# Splunk Threat Detection: Binance Incident Indicators

## Overview
This repository contains custom Splunk detection rules built to hunt for indicators of compromise (IoCs) associated with the recent threat actor activity targeting cryptocurrency infrastructure (Binance incident).

## Rule Details
* **Alert Name:** Threat Intel Match - Binance Breach
* **Data Source:** Sysmon (EventCode 1 - Process Creation)
* **Severity:** High
* **Mitreattack Mapping:** Defense Evasion / Execution

## SPL Query
```splunk
index=endpoint (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1) 
(sha256="60b3c1e2ec3100caf4fde734cfd514717acf58abf7d4480196831db4aa5f08" 
 OR sha256="5b40b73934c1583144f141d8483e227529f67157e26c6012bsbd082e3fd7e0b03"
 OR sha1="8e67006585e49f51db96604487138e688df732d3"
 ...)
| table _time, host, user, Image, CommandLine, sha256, sha1

