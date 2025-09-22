// Handle form submission
document.getElementById('hashForm').addEventListener('submit', handleSubmit);

async function handleSubmit(event) {
    event.preventDefault();
    const hashes = document.getElementById('hashInput').value
        .split('\n')
        .map(h => h.trim())
        .filter(h => h);
    
    if (hashes.length === 0) {
        showError('Please enter at least one hash');
        return;
    }

    const crackOption = document.getElementById('crackOption').checked;
    const resultsDiv = document.getElementById('results');
    
    if (crackOption) {
        resultsDiv.innerHTML = '<p class="loading">🔍 Identifying and attempting to crack hashes... This may take a while.</p>';
    } else {
        resultsDiv.innerHTML = '<p class="loading">Identifying hashes...</p>';
    }

    try {
        const results = [];
        for (const hash of hashes) {
            const result = await identifyHash(hash, crackOption);
            results.push({ hash, ...result });
        }
        displayResults(results);
    } catch (error) {
        showError('Failed to identify hashes. Please try again.');
        console.error('Error:', error);
    }
}

async function identifyHash(hash, crack = false) {
    try {
        const response = await fetch('/.netlify/functions/identify-hash', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hash, crack })
        });
        
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        
        return await response.json();
    } catch (error) {
        console.error('Error identifying hash:', error);
        return { 
            hash,
            type: 'error',
            error: error.message || 'Failed to identify hash',
            hashcat: 'N/A',
            john: 'N/A'
        };
    }
}

function displayResults(results) {
    const resultsDiv = document.getElementById('results');
    
    if (!results || results.length === 0) {
        resultsDiv.innerHTML = '<p class="no-results">No results found</p>';
        return;
    }

    const hasCrackResults = results.some(r => r.crack);
    
    resultsDiv.innerHTML = `
        <div class="results-container">
            <h2>Results:</h2>
            <table>
                <thead>
                    <tr>
                        <th>Hash</th>
                        <th>Type</th>
                        <th>Hashcat Mode</th>
                        <th>John Format</th>
                        ${hasCrackResults ? '<th>Cracked Password</th><th>Method</th>' : ''}
                        <th>Copy</th>
                    </tr>
                </thead>
                <tbody>
                    ${results.map(result => `
                        <tr class="${result.error ? 'error' : (result.crack && result.crack.cracked ? 'cracked' : '')}">
                            <td class="hash-cell">${escapeHtml(result.hash)}</td>
                            <td>${result.error ? '❌ Error' : escapeHtml(result.type)}</td>
                            <td>${escapeHtml(result.hashcat || 'N/A')}</td>
                            <td>${escapeHtml(result.john || 'N/A')}</td>
                            ${hasCrackResults ? `
                                <td class="crack-result">
                                    ${result.crack ? 
                                        (result.crack.cracked ? 
                                            `<span class="cracked-password">🔓 ${escapeHtml(result.crack.password)}</span>` : 
                                            '<span class="not-cracked">🔒 Not cracked</span>'
                                        ) : 
                                        '<span class="not-attempted">-</span>'
                                    }
                                </td>
                                <td class="crack-method">
                                    ${result.crack ? 
                                        (result.crack.cracked ? 
                                            `<span class="method-${result.crack.method}">${escapeHtml(result.crack.method.replace('_', ' '))}</span>
                                             <br><small>${result.crack.timeElapsed}ms</small>` : 
                                            `<span class="failed">${escapeHtml(result.crack.message || 'Failed')}</span>`
                                        ) : 
                                        '-'
                                    }
                                </td>
                            ` : ''}
                            <td>
                                <button onclick="copyToClipboard('${escapeHtml(result.hash)}')" 
                                        class="copy-btn" 
                                        title="Copy hash to clipboard">
                                    📋
                                </button>
                                ${result.crack && result.crack.cracked ? `
                                    <button onclick="copyToClipboard('${escapeHtml(result.crack.password)}')" 
                                            class="copy-btn copy-password" 
                                            title="Copy password to clipboard">
                                        🔑
                                    </button>
                                ` : ''}
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function showError(message) {
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = `<p class="error-message">${escapeHtml(message)}</p>`;
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Show feedback
        const button = event.target.tagName === 'BUTTON' ? event.target : event.target.closest('button');
        if (button) {
            const originalText = button.textContent;
            button.textContent = '✓';
            button.classList.add('copied');
            setTimeout(() => {
                button.textContent = originalText;
                button.classList.remove('copied');
            }, 2000);
        }
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}

function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return unsafe;
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Make copyToClipboard available globally
window.copyToClipboard = copyToClipboard;
