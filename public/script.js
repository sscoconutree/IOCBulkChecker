document.addEventListener('DOMContentLoaded', () => {
    const hashInput = document.getElementById('hashInput');
    const checkButton = document.getElementById('checkButton');
    const characterCounter = document.getElementById('characterCounter');
    const analysisResultContainer = document.getElementById('analysisResult');
    let copyButton = null;
    const maxLines = 500;
    const uniqueResults = new Set(); 

    characterCounter.textContent = `(0/${maxLines})`;

    hashInput.addEventListener('input', () => {
        let inputText = hashInput.value;
        let lines = inputText.split('\n').filter(line => line.trim() !== '');

        if (lines.length > maxLines) {
            lines = lines.slice(0, maxLines);
            inputText = lines.join('\n');
            hashInput.value = inputText;
        }

        const lineCount = lines.length;
        characterCounter.textContent = `(${lineCount}/${maxLines})`;

        checkButton.disabled = lineCount === 0 || lineCount > maxLines;
    });

    checkButton.addEventListener('click', async () => {
        const inputText = hashInput.value.trim();
        if (inputText === '') {
            return;
        }

        resetUI();

        let lines = inputText.split('\n').filter(line => line.trim() !== '');
        lines = lines.slice(0, maxLines);
        const uniqueLines = Array.from(new Set(lines));

        hashInput.disabled = true;
        checkButton.disabled = true;

        try {
            const response = await fetch('/checkEntries', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ entries: uniqueLines })
            });

            if (!response.ok && response.status(500) && response.status(404) && response.status(429)) {
                throw new Error(`Server returned ${response.status}`);
            }

            const reader = response.body.getReader();
            let result = '';

            while (true) {
                const { done, value } = await reader.read();

                if (done) {
                    break;
                }

                result += new TextDecoder().decode(value);
                const lines = result.split('\n');

                for (const line of lines) {
                    if (line.trim() !== '') {
                        const parsedResult = JSON.parse(line);
                        console.log('Received Result:', parsedResult); 

                        const resultString = JSON.stringify(parsedResult);
                        if (!uniqueResults.has(resultString)) {
                            uniqueResults.add(resultString);

                            displayAnalysisResult(parsedResult);

                            showCopyButton();
                        }
                    }
                }
            }

        } catch (error) {
            console.error('Error occurred:', error);
            flashErrorMessage('API limit has been reached or there\'s no connection to the server. Please try again later.');
        } finally {
            hashInput.disabled = false;
            checkButton.disabled = false;
        }
    });

    function resetUI() {
        analysisResultContainer.innerHTML = '';
        uniqueResults.clear();
        removeCopyButton();
    }

    function displayAnalysisResult(result) {
        const listItem = document.createElement('li');

        if (result.type === 'Hash') {
            if (result.result.status === 'Malicious') {
                listItem.textContent = `Hash: ${result.result.hash} (${result.result.type}) - ${result.result.enginesDetected} security vendors flagged this file as malicious`;
                listItem.style.color = 'red';
            } else if (result.result.status === 'Clean') {
                listItem.textContent = `Hash: ${result.result.hash} (${result.result.type}) - Clean`;
                listItem.style.color = 'green';
            } else {
                listItem.textContent = `Hash: ${result.result.hash} (${result.result.type}) - No matches found`;
                listItem.style.color = 'gray';
            }
        } else if (result.type === 'IPv4') {
            const ipv4Data = result.result.data;
            const ipv4Detection = ipv4Data.attributes.last_analysis_stats.malicious;

            listItem.textContent = `IPv4 Address: ${ipv4Data.id} - ${ipv4Detection} security vendors flagged this IP address as malicious`;

            if (ipv4Detection > 0) {
                listItem.style.color = 'red';
            } else {
                listItem.style.color = 'green';
            }
        } else if (result.type === 'IPv6') {
            
            const ipv6Data = result.result;
            const abuseConfidenceScore = ipv6Data.data.abuseConfidenceScore;
            listItem.textContent = `IPv6 Address: ${ipv6Data.data.ipAddress} - Abuse Confidence Score: ${abuseConfidenceScore}%`;

            if (abuseConfidenceScore > 0) {
                listItem.style.color = 'red';
            } else {
                listItem.style.color = 'green';
            }
        } else if (result.type === 'URL') {
        
            const URLdata = result.result.data;
            const URLdetection = URLdata.attributes.last_analysis_stats.malicious;
    
            listItem.textContent = `URL: ${URLdata.attributes.url} - ${URLdetection} security vendors flagged this URL as malicious`;
    
            if (URLdetection > 0) {
                    listItem.style.color = 'red';
                } else {
                    listItem.style.color = 'green';
            }
          
        } else if (result.type === 'URLerror') {
            const URLerror = result.result; 
        
            if (URLerror.error && URLerror.error.code === 'NotFoundError') {
                const errorMessage = URLerror.error.message;
                
                const base64EncodedString = errorMessage.split(' ')[1].replace(/"/g, ''); 
                
                const decodedMessage = atob(base64EncodedString);
        
                listItem.textContent = `URL not found: "${decodedMessage}"`;
                listItem.style.color = 'gray';
            } 

        } else if (result.type === 'Domain') {

            const Domaindata = result.result.data;
            const Domaindetection = Domaindata.attributes.last_analysis_stats.malicious;

            listItem.textContent = `Domain: ${Domaindata.id} - ${Domaindetection} security vendors flagged this domain as malicious`;

            if (Domaindetection > 0) {
                listItem.style.color = 'red';
            } else {
                listItem.style.color = 'green';
            }

        } else if (result.type === 'Domainerror') {

            const Domainerror = result.result;

            if (Domainerror.error && Domainerror.error.code === 'InvalidArgumentError') {
                const Domainerrmessage = Domainerror.error.message;

                const matches = Domainerrmessage.match(/"b'(.*?)'"/);
                let domain = '';

                if (matches && matches.length > 1) {
                    domain = matches[1]; 
                }

                listItem.textContent = `Domain not found: "${domain}"`;
                listItem.style.color = 'gray';

            }
        }
        
        
        analysisResultContainer.appendChild(listItem);
    }

    function showCopyButton() {
        if (!copyButton) {
            copyButton = document.createElement('button');
            copyButton.textContent = 'Copy Results';
            copyButton.classList.add('copyButton');
            copyButton.addEventListener('click', () => {
                const textToCopy = Array.from(analysisResultContainer.children)
                    .map(li => li.textContent)
                    .join('\n');
                copyToClipboard(textToCopy);
            });

            analysisResultContainer.parentNode.appendChild(copyButton);
        }
    }

    function removeCopyButton() {
        if (copyButton && copyButton.parentNode) {
            copyButton.parentNode.removeChild(copyButton);
            copyButton = null;
        }
    }

    function flashErrorMessage(message) {
        const flashMessage = document.createElement('div');
        flashMessage.textContent = message;
        flashMessage.classList.add('flashMessage');
        document.body.appendChild(flashMessage);

        setTimeout(() => {
            flashMessage.remove();
        }, 4000);
    }

    function copyToClipboard(text) {
        navigator.clipboard.writeText(text)
            .then(() => {
                showCopyMessage();
            })
            .catch(err => {
                console.error('Failed to copy:', err);
            });
    }

    function showCopyMessage() {
        const copyMessage = document.createElement('div');
        copyMessage.textContent = 'Results copied to clipboard';
        copyMessage.classList.add('copyMessage');
        document.body.appendChild(copyMessage);

        setTimeout(() => {
            copyMessage.style.opacity = '0';
            setTimeout(() => {
                copyMessage.remove();
            }, 1000);
        }, 2000);
    }
});
