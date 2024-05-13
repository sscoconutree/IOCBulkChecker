const express = require('express');
const fetch = require('node-fetch');
const { sleep, isIPv4Address, isIPv6Address, isHash } = require('./helpers');

const app = express();
const vt_api = '5825f4fc8fba52674f640f126a1ff538f5cb0c87553ee2e662cd916d4fab037d';
const ab_api = '981ec3e0f36f48edc2e70497544f6969e48850da0d25cab031553cdcf45087fd8e0b99a836cfbbad';

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
