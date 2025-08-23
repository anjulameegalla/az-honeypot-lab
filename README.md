# SIEM Honeypot Lab featuring Microsoft Sentinel to analyse real-world attack data


## Lab overview

![overview.png](/res/overview.png)

## Azure resources

**Windows VM**

- Name - HoneyVM
- Resource group (RG) - honeypot-lab
- Image - Windows 10 Pro, x64 Gen1
- Size - standard_B2s
- VNets - default

**NSG > Advanced > Configure NSG >**

- NSG name - HoneyVM-nsg
- Source port ranges - * (allow all)
- Destination port ranges - * (allow all)
- Priority - 100

**Log Analytics workspace**

- Name - law-honeypot
- RG - honeypot-lab

**MS Defender for Cloud > Management > Environment settings >** 

- Find Azure subscription 1 > law-honeypot

Settings > Defender plans >

- Turn on Servers  plan

Settings > Data collection >

- Turn on All events

**Log Analytics workspace > law-honeypot > Classic > Virtual Machines (deprecated) >**

- Select HoneyVM, then CONNECT

**MS Sentinel**

- Add law-honeypot to MS Sentinel

Connect to HoneyVM via RDP

- Turn Windows firewall OFF

![rdp.png](res/rdp.png)

## GeoLocation API

Get API key from IP Geolocation.io:  [https://ipgeolocation.io/ip-location-api.html](https://ipgeolocation.io/ip-location-api.html)

![geolocationapi.png](res/geolocationapi.png)

## Windows - PowerShell ISE script

- ### Find pwsh script in scripts folder

---

Collect failed_rdp file 

- Browse C:/ > Program Data > failed_rdp.log

**law-honeypot > Tables > Create new custom log (MMA-based) >**

- Sample log - Select failed_rdp.log
- Collection paths - Windows | C:\ProgramData\failed_rdp.log
- Custom log name - FAILED_RDP_GEO_CL

**law-honeypot > Logs >**

## Custom Log creation Query (KQL)

```sql
FAILED_RDP_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by timestamp, label, country, state, sourcehost, username, destination, longitude, latitude
```

### Query output :

![log-query.png](res/log-query.png)

**MS Sentinel >  Threat Management > Workbooks > New workbook > Add query >**

- Log Analytics workspace - law-honeypot
- Visualization - Map
- Size - Full

## Custom Map creation Query (KQL)

```sql
FAILED_RDP_GEO_CL 
| extend username = extract(@"username:([^,]+)", 1, RawData),
         timestamp = extract(@"timestamp:([^,]+)", 1, RawData),
         latitude = extract(@"latitude:([^,]+)", 1, RawData),
         longitude = extract(@"longitude:([^,]+)", 1, RawData),
         sourcehost = extract(@"sourcehost:([^,]+)", 1, RawData),
         state = extract(@"state:([^,]+)", 1, RawData),
         label = extract(@"label:([^,]+)", 1, RawData),
         destination = extract(@"destinationhost:([^,]+)", 1, RawData),
         country = extract(@"country:([^,]+)", 1, RawData)
| where destination != "samplehost"
| where sourcehost != ""
| summarize event_count=count() by latitude, longitude, sourcehost, label, destination, country
```

## **Map of incoming attacks after few hours (built custom logs including geodata)**

![sentinel-map](res/sentinel-map.png)

---

<h2>PowerShell Code Explanation</h2>

- ### Credits - [CyberfolioChronicles](https://github.com/CyberfolioChronicles/Azure_Sentinel_Lab)



1. **API Key and Log File Setup:**

   $API_KEY = "8f8ecb5c9ff74f6da202bad2ee784dc2"   
   $LOGFILE_NAME = "failed_rdp.log"   
   $LOGFILE_PATH = "C:\ProgramData\$($LOGFILE_NAME)"

- `API_KEY`: This variable stores the API key obtained from "https://ipgeolocation.io/" to access their geolocation service.
- `LOGFILE_NAME`: The name of the log file.
- `LOGFILE_PATH`: The full path where the log file will be stored.

2. **XML Filter for Event Viewer:**
   
   $XMLFilter = @' *[System[(EventID='4625')]] '@

- This XML filter is used to retrieve specific events from the Windows Event Viewer (Security log) with EventID '4625', which typically indicates failed RDP login attempts.

3. **Creating Sample Log Entries:**

   Function write-Sample-Log() {
       # ... (sample log entries for training purposes)
   }

- This function creates sample log entries that will be used to "train" the log analytics workspace's extraction feature.

4. **Checking and Creating Log File:**

   if ((Test-Path $LOGFILE_PATH) -eq $false) {
       New-Item -ItemType File -Path $LOGFILE_PATH
       write-Sample-Log
   }

- Checks if the log file exists. If not, it creates a new log file and writes sample log entries using the `write-Sample-Log` function.

5. **Infinite Loop to Monitor Event Viewer:**

   while ($true) {
       # ... (code inside the loop to continuously check Event Viewer)
   }

- This sets up an infinite loop to continuously check the Event Viewer for failed RDP login attempts.

6. **Event Processing:**

   foreach ($event in $events) {
       # ... (code to process each event and extract relevant information)
   }

- Processes each event retrieved from the Event Viewer, extracts relevant information such as timestamp, event ID, source and destination host, username, and source IP.

7. **Geolocation Retrieval and Logging:**
   
   if ($event.properties[19].Value.Length -ge 5) {
       # ... (code to retrieve geolocation based on IP address and log the information)
   }

- Checks if the event contains a valid source IP address, then uses the IP address to retrieve geolocation information using the "https://api.ipgeolocation.io/" API, and logs the relevant information.

This script continuously monitors failed RDP login attempts in the Windows Event Viewer, extracts relevant details, fetches geolocation information for the source IP addresses, and logs this information into a custom log file.

Of course! Here are the explanations with headlines for each part:

8. **Extracting Date and Time Components**

$month = $event.TimeCreated.Month
if ("$($event.TimeCreated.Month)".Length -eq 1) {
    $month = "0$($event.TimeCreated.Month)"
}

- Extracts the month from the event timestamp and ensures a two-digit representation.

9. **Formatting the Timestamp**

$timestamp = "$($year)-$($month)-$($day) $($hour):$($minute):$($second)"

- Constructs a timestamp in the format: "YYYY-MM-DD HH:MM:SS" using the extracted date and time components.

10. **Extracting Event Information**

$eventId = $event.Id
$destinationHost = $event.MachineName
$username = $event.properties[5].Value
$sourceHost = $event.properties[11].Value
$sourceIp = $event.properties[19].Value

- Extracts relevant information from the event, such as Event ID, destination host, username, source host, and source IP.

11. **Checking Log File and Timestamp**

$log_contents = Get-Content -Path $LOGFILE_PATH
if (-Not ($log_contents -match "$($timestamp)") -or ($log_contents.Length -eq 0)) {
    # ... (code inside this block)
}
else {
    # ... (code to handle when the entry already exists in the log file)
}

- Checks if the log entry with the current timestamp already exists or if the log file is empty.

12. **Processing Geolocation Data and Writing to Log file**
  Start-Sleep -Seconds 1

                # Make web request to the geolocation API
                # For more info: https://ipgeolocation.io/documentation/ip-geolocation-api.html
                $API_ENDPOINT = "https://api.ipgeolocation.io/ipgeo?apiKey=$($API_KEY)&ip=$($sourceIp)"
                $response = Invoke-WebRequest -UseBasicParsing -Uri $API_ENDPOINT

                # Pull Data from the API response, and store them in variables
                $responseData = $response.Content | ConvertFrom-Json
                $latitude = $responseData.latitude
                $longitude = $responseData.longitude
                $state_prov = $responseData.state_prov
                if ($state_prov -eq "") { $state_prov = "null" }
                $country = $responseData.country_name
                if ($country -eq "") {$country -eq "null"}

                # Write all gathered data to the custom log file. It will look something like this:
                #
                "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov), country:$($country),label:$($country) - $($sourceIp),timestamp:$($timestamp)" | Out-File $LOGFILE_PATH -Append -Encoding utf8

                Write-Host -BackgroundColor Black -ForegroundColor Magenta "latitude:$($latitude),longitude:$($longitude),destinationhost:$($destinationHost),username:$($username),sourcehost:$($sourceIp),state:$($state_prov),label:$($country) - $($sourceIp),timestamp:$($timestamp)"
            }

- Contains the code to retrieve geolocation data based on the source IP and process the retrieved information.
- Constructs a log entry with extracted event and geolocation information and writes it to the log file.

13. **Handling Existing Log Entry**

else {
    # ... (code to handle when the entry already exists in the log file)
}

- Contains code to handle the case when an entry with the current timestamp already exists in the log file. In this provided code, it's left empty and does nothing.
