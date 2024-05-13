# IOCBulkChecker
GUI-based bulk IOC tool checker that supports VirusTotal and AbuseIPDB API.

This is an improved version of previous bulk analysis tools from this repository as it supports analysis of **IPv4**, **IPv6** and **Hash (MD5, SHA-1, SHA-256)**.
Due to some API key limitations (e.g. VirusTotal) there's a sleep timer in between the scans per hashes.

![image](https://github.com/sscoconutree/IOCBulkChecker/assets/59388557/5214ea79-7fd4-425e-9577-984a07811579)

<h3>How to use:</h3>

1. Clone this repository.
2. Edit ```app.js``` file and put your VirusTotal API key on the ```vt_api``` field and AbuseIPDB API key on the ```ab_api``` field.
3. Run the following: ```node app.js```
4. Open ```localhost:3000```

# CHANGELOGS

<h3>v1.0</h3>
* First release.
