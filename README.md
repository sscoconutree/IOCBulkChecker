# IOCBulkChecker
GUI-based bulk IOC tool checker that uses VirusTotal and AbuseIPDB API.

This is an improved version of previous bulk analysis tools from this repository as it supports analysis of **IPv4**, **IPv6**, **URLs**, **Domains** and **Hashes (MD5, SHA-1, SHA-256)**.
Due to some API key limitations (e.g. VirusTotal) there's a sleep timer in between the scans per hashes.

![image](https://github.com/sscoconutree/IOCBulkChecker/assets/59388557/14d1058a-2b65-46ec-948f-5805f34d84c9)
![image](https://github.com/sscoconutree/IOCBulkChecker/assets/59388557/51a26750-d43b-4982-b527-56e15215c91b)

<h3>How to use:</h3>

1. Clone this repository.
2. Edit ```app.js``` file and put your VirusTotal API key on the ```vt_api``` field and AbuseIPDB API key on the ```ab_api``` field.
3. Run the following: ```node app.js```
4. Open ```localhost:3000```

# CHANGELOGS

<h3>v1.2</h3>
* Added direct link report of IOCs on VirusTotal and AbuseIPDB in the output.

<h3>v1.1</h3>
* Fixed URL analysis by performing POST request to the server first before proceeding with the GET request to retrieve the report. This is to ensure flexibility of URL inputs for analysis.

<h3>v1.0</h3>
* First release.
