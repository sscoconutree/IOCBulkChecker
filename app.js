const express = require('express');
const fetch = require('node-fetch');
const base64url = require('base64url');
const { sleep, isIPv4Address, isIPv6Address, isHash, isURL, isDomain } = require('./helpers');

const app = express();
const vt_api = 'VT_API_KEY'; // PUT YOUR VirusTotal API KEY HERE
const ab_api = 'ABUSEIPDB_API_KEY'; // PUT YOUR AbuseIPDB API KEY HERE

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

const maxApiRequests = 500;

app.post('/checkEntries', async (req, res) => {
    let apiRequestCount = 0;

    if (apiRequestCount >= maxApiRequests) {
        return res.status(500).json({ success: false, message: 'API request limit exceeded' });
    }

    const { entries } = req.body;
    const numEntries = entries.length;

    for (let i = 0; i < numEntries; i++) {
        const trimmedEntry = entries[i].trim();

        if (isIPv4Address(trimmedEntry)) {
            
            const ip = trimmedEntry;
            const url = `https://www.virustotal.com/api/v3/ip_addresses/${ip}`;
            
            try {
                const response = await fetch(url, {
                    headers: {
                        'x-apikey': vt_api
                    }
                });

                const data = await response.json();
                res.write(JSON.stringify({ type: 'IPv4', entry: ip, result: data }) + '\n');
            } catch (error) {
                console.error(`Error occurred while checking IP ${ip}:`, error);
                res.write(JSON.stringify({ type: 'IPv4', entry: ip, error: `Error occurred while checking IP ${ip}.` }) + '\n');
            }
        }

        if (isIPv6Address(trimmedEntry)) {
            
            const ip = trimmedEntry;

            try {
                const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}`, {
                    headers: {
                        Key: ab_api,
                        Accept: 'application/json'
                    }
                });

                const responseData = await response.json();

                if (response.ok) {
                    res.write(JSON.stringify({ type: 'IPv6', entry: ip, result: responseData }) + '\n');
                } else {
                    throw new Error(`Error occurred while checking IPv6 address ${ip}: ${responseData.errors[0].detail}`);
                }
            } catch (error) {
                console.error(`Error occurred while checking IPv6 address ${ip}:`, error);
                res.write(JSON.stringify({ type: 'IPv6', entry: ip, error: `Error occurred while checking IPv6 address ${ip}.` }) + '\n');
            }
        }

        if (isURL(trimmedEntry) && !isIPv6Address(trimmedEntry) && !isIPv4Address(trimmedEntry) && !isHash(trimmedEntry)) {
            const input_url = trimmedEntry;
            const url_id = base64url(input_url);
            
            const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
            
            try {
                const vt_response = await fetch('https://www.virustotal.com/api/v3/urls', {
                    method: 'POST',
                    headers: {
                        'x-apikey': vt_api,
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: new URLSearchParams({
                        url: input_url,
                    }),
                });
        
                if (vt_response.ok) {

                    await sleep(8500);
        
                    try {
                        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${url_id}`, {
                            headers: {
                                'x-apikey': vt_api,
                            },
                        });
        
                        if (response.ok) {
                            const data = await response.json();
                            res.write(JSON.stringify({ type: 'URL', entry: input_url, result: data }) + '\n');
                        } else {
                            const data = await response.json();
                            res.write(JSON.stringify({ type: 'URLerror', entry: input_url, result: data }) + '\n');
                        }
                    } catch (error) {
                        res.write(JSON.stringify({ type: 'URL', entry: input_url, error: `Error fetching scan results for URL: "${input_url}"` }) + '\n');
                    }
                } else {
                    const vt_data = await vt_response.json();
                    res.write(JSON.stringify({ type: 'URL', entry: input_url, error: `Error submitting URL to VirusTotal: ${vt_data.error.message}` }) + '\n');
                }
            } catch (error) {
                res.write(JSON.stringify({ type: 'URL', entry: input_url, error: `Error submitting URL to VirusTotal: ${error.message}` }) + '\n');
            }
        }
                

        if (isDomain(trimmedEntry) && !isURL(trimmedEntry) && !isIPv6Address(trimmedEntry) && !isIPv4Address(trimmedEntry) && !isHash(trimmedEntry)) {

            const domain = trimmedEntry;

            try {
                const response = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
                    headers: {
                        'x-apikey': vt_api
                    }
                });
        
                if (response.ok) {
                    const data = await response.json();
                    res.write(JSON.stringify({ type: 'Domain', entry: domain, result: data }) + '\n');
                     
                } else if (!response.ok) {
                    
                    const data = await response.json();
                    res.write(JSON.stringify({ type: 'Domainerror', entry: domain, result: data }) + '\n');
                }
            
            } catch (error) {
                res.write(JSON.stringify({ type: 'Domain', entry: domain, error: `No records found for the domain: "${domain}"` }) + '\n');
            }

        }
        
        
        if (!isIPv4Address(trimmedEntry) && !isIPv6Address(trimmedEntry) && isHash(trimmedEntry)) {
            
            const hash = trimmedEntry;
            let hashType;

            switch (hash.length) {
                case 32:
                    hashType = 'MD5';
                    break;
                case 40:
                    hashType = 'SHA-1';
                    break;
                case 64:
                    hashType = 'SHA-256';
                    break;
                default:
                    hashType = 'Unknown';
            }

            try {
                const response = await fetch(`https://www.virustotal.com/vtapi/v2/file/report?apikey=${vt_api}&resource=${hash}`);
                apiRequestCount++;

                const result = await response.json();

                let status, enginesDetected;
                if (typeof result.positives === 'undefined') {
                    status = 'Unknown';
                } else if (result.positives !== 0) {
                    status = 'Malicious';
                    enginesDetected = result.positives;
                } else {
                    status = 'Clean';
                }

                const formattedResult = {
                    hash: hash,
                    type: hashType,
                    status: status,
                    enginesDetected: enginesDetected
                };

                res.write(JSON.stringify({ type: 'Hash', entry: hash, result: formattedResult }) + '\n');
            } catch (error) {
                console.error(`Error occurred while checking hash ${hash}:`, error);
                res.write(JSON.stringify({ type: 'Hash', entry: hash, error: `Error occurred while checking hash ${hash}.` }) + '\n');
            }
        }

        if (numEntries >= 4 && i < numEntries - 1) {
            await sleep(15000); 
        }
    }

    res.end(); 
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
