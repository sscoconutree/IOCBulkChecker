# IOCBulkChecker
GUI-based bulk IOC tool checker that supports VirusTotal and AbuseIPDB API.

This is an improved version of previous bulk analysis tools I have done as it supports analysis of IPv4, IPv6 and Hash (MD5, SHA-1, SHA-256).
Due to some API key limitations (e.g. VirusTotal) there's a sleep timer in between the scans per hashes.

![image](https://github.com/sscoconutree/IOCBulkChecker/assets/59388557/34235e1e-9738-4da7-ba03-1221ad6d89fc)


<h3>How to use:</h3>

1. Clone this repository.
2. Edit ```app.js``` file and put your VirusTotal API key on the ```vt_api``` field and AbuseIPDB API key on the ```ab_api``` field.
3. Run the following: ```node app.js```
4. Open ```localhost:3000```

# CHANGELOGS

<h3>v1.0</h3>
* First release.
