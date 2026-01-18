// script.js - OSINT Tool Functions

function checkUsername() {
    const username = document.getElementById('usernameInput').value.trim();
    const resultsDiv = document.getElementById('usernameResults');
    
    if (!username) {
        resultsDiv.innerHTML = '<p style="color: #ff6b6b;">Please enter a username</p>';
        return;
    }
    
    resultsDiv.innerHTML = '<p style="color: #00d4ff;">Checking availability across platforms...</p>';
    
    const platforms = [
        { name: 'GitHub', url: `https://github.com/${username}`, color: '#6cc644' },
        { name: 'Twitter/X', url: `https://twitter.com/${username}`, color: '#1da1f2' },
        { name: 'Instagram', url: `https://instagram.com/${username}`, color: '#e4405f' },
        { name: 'Reddit', url: `https://reddit.com/user/${username}`, color: '#ff4500' },
        { name: 'YouTube', url: `https://youtube.com/@${username}`, color: '#ff0000' },
        { name: 'TikTok', url: `https://tiktok.com/@${username}`, color: '#00f2ea' },
        { name: 'LinkedIn', url: `https://linkedin.com/in/${username}`, color: '#0077b5' }
    ];
    
    setTimeout(() => {
        let html = '<h4 style="color: #00ffcc; margin-bottom: 1rem;">Platform Links:</h4>';
        html += '<div style="display: grid; gap: 0.5rem;">';
        
        platforms.forEach(platform => {
            html += `
                <div style="padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: 5px; border-left: 3px solid ${platform.color};">
                    <strong style="color: ${platform.color};">${platform.name}:</strong> 
                    <a href="${platform.url}" target="_blank" style="color: #00d4ff; text-decoration: none;">${platform.url}</a>
                </div>
            `;
        });
        
        html += '</div>';
        html += '<p style="margin-top: 1rem; color: #a0a0a0; font-size: 0.9rem;"><em>Click links to check if profile exists (educational purposes only)</em></p>';
        
        resultsDiv.innerHTML = html;
    }, 1000);
}

function analyzeDomain() {
    const domain = document.getElementById('domainInput').value.trim();
    const resultsDiv = document.getElementById('domainResults');
    
    if (!domain) {
        resultsDiv.innerHTML = '<p style="color: #ff6b6b;">Please enter a domain</p>';
        return;
    }
    
    resultsDiv.innerHTML = '<p style="color: #00d4ff;">Analyzing domain information...</p>';
    
    setTimeout(() => {
        let html = '<h4 style="color: #00ffcc; margin-bottom: 1rem;">Domain Analysis Tools:</h4>';
        html += '<div style="display: grid; gap: 0.75rem;">';
        
        const tools = [
            { name: 'WHOIS Lookup', url: `https://who.is/whois/${domain}` },
            { name: 'DNS Records', url: `https://mxtoolbox.com/SuperTool.aspx?action=a:${domain}` },
            { name: 'SSL Certificate', url: `https://crt.sh/?q=${domain}` },
            { name: 'Wayback Machine', url: `https://web.archive.org/web/*/${domain}` }
        ];
        
        tools.forEach(tool => {
            html += `
                <div style="padding: 0.75rem; background: rgba(0,212,255,0.1); border-radius: 5px;">
                    <strong style="color: #00ffcc;">${tool.name}:</strong> 
                    <a href="${tool.url}" target="_blank" style="color: #00d4ff; text-decoration: none;">${tool.url}</a>
                </div>
            `;
        });
        
        html += '</div>';
        resultsDiv.innerHTML = html;
    }, 1000);
}

function analyzeIP() {
    const ip = document.getElementById('ipInput').value.trim();
    const resultsDiv = document.getElementById('ipResults');
    
    if (!ip) {
        resultsDiv.innerHTML = '<p style="color: #ff6b6b;">Please enter an IP address</p>';
        return;
    }
    
    // Basic IP validation
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipPattern.test(ip)) {
        resultsDiv.innerHTML = '<p style="color: #ff6b6b;">Please enter a valid IP address</p>';
        return;
    }
    
    resultsDiv.innerHTML = '<p style="color: #00d4ff;">Analyzing IP address...</p>';
    
    setTimeout(() => {
        let html = '<h4 style="color: #00ffcc; margin-bottom: 1rem;">IP Analysis Tools:</h4>';
        html += '<div style="display: grid; gap: 0.75rem;">';
        
        const tools = [
            { name: 'IP Location', url: `https://www.ip2location.com/${ip}` },
            { name: 'IP WHOIS', url: `https://who.is/whois-ip/ip-address/${ip}` },
            { name: 'Shodan', url: `https://www.shodan.io/host/${ip}` },
            { name: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${ip}` }
        ];
        
        tools.forEach(tool => {
            html += `
                <div style="padding: 0.75rem; background: rgba(0,212,255,0.1); border-radius: 5px;">
                    <strong style="color: #00ffcc;">${tool.name}:</strong> 
                    <a href="${tool.url}" target="_blank" style="color: #00d4ff; text-decoration: none;">${tool.url}</a>
                </div>
            `;
        });
        
        html += '</div>';
        resultsDiv.innerHTML = html;
    }, 1000);
}

// Initialize tooltips and additional functionality
document.addEventListener('DOMContentLoaded', function() {
    console.log('Zyros-OSINT Platform Loaded');
    console.log('Educational OSINT tools ready for ethical research');
});
