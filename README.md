# Azure Honeypot Lab featuring Microsoft Sentinel as the SIEM


## Lab overview

![overview.png](/res/overview.png)

---

## Azure resources

### Windows VM

- Name - HoneyVM
- Resource group (RG) - honeypot-lab
- Image - Windows 10 Pro, x64 Gen1
- Size - standard_B2s
- VNets - default

### NSG > Advanced > Configure NSG >

- NSG name - HoneyVM-nsg
- Source port ranges - * (allow all)
- Destination port ranges - * (allow all)
- Priority - 100

### Log Analytics workspace

- Name - law-honeypot
- RG - honeypot-lab

### MS Defender for Cloud > Management > Environment settings >

- Find Azure subscription 1 > law-honeypot

Settings > Defender plans >

- Turn on Servers  plan

Settings > Data collection >

- Turn on All events

### Log Analytics workspace > law-honeypot > Classic > Virtual Machines (deprecated) >

- Select HoneyVM, then CONNECT

### MS Sentinel

- Add law-honeypot to MS Sentinel

### Connect to HoneyVM via RDP

- Turn Windows firewall OFF*

---

## GeoLocation API

#### Get API key from [ipgeolocation.io](https://ipgeolocation.io/ip-location-api.html) / [Documentation](https://ipgeolocation.io/documentation/ip-geolocation-api.html)
#### or
#### Get API key from [ip2location.io](https://www.ip2location.io/) / [Documentation](https://www.ip2location.io/ip2location-documentation)


## Windows - PowerShell ISE script

#### Powershell script for ![ipgeolocation.io](scripts/ipgeolocation_api.ps1) API
#### Powershell script for ![ip2location.io](scripts/ip2location_api.ps1) API

---

#### Collect failed_rdp file 

- Browse C:/ > Program Data > failed_rdp.log

### law-honeypot > Tables > Create new custom log (MMA-based) >

- Sample log - Select failed_rdp.log
- Collection paths - Windows / C:\ProgramData\failed_rdp.log
- Custom log name - FAILED_RDP_GEO_CL

### law-honeypot > Logs >

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

---

### MS Sentinel >  Threat Management > Workbooks > New workbook > Add query >

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

![sentinel-map1](res/sentinel-map1.png)

---


### Find in-Depth PowerShell Code Explanation on [CyberfolioChronicles](https://github.com/CyberfolioChronicles/Azure_Sentinel_Lab).


---

- ### Browse az-honeypot-lab [GitHub Repo](https://github.com/anjulameegalla/az-honeypot-lab/) here.