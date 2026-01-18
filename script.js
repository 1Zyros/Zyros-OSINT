// script.js - OSINT Tool Functions

// ============================================
// DISCORD OSINT TOOL - AUTO FETCH DATA
// ============================================
async function analyzeDiscord() {
    const discordInput = document.getElementById('discordInput').value.trim();
    const resultsDiv = document.getElementById('discordResults');
    
    if (!discordInput) {
        resultsDiv.innerHTML = '<p style="color: #ff6b6b;">⚠️ Please enter a Discord User ID or Username</p>';
        return;
    }
    
    resultsDiv.innerHTML = '<p style="color: #00d4ff;">🔍 Fetching public Discord information...</p>';
    
    // Check if input is a numeric ID (17-19 digits)
    const isNumericID = /^\d{17,19}$/.test(discordInput);
    const userId = isNumericID ? discordInput : null;
    
    if (!userId) {
        resultsDiv.innerHTML = `
            <div style="padding: 1rem; background: rgba(255,193,7,0.1); border-radius: 8px; border-left: 4px solid #ffc107;">
                <p style="color: #ffc107; margin: 0;">💡 <strong>Please enter a numeric User ID (17-19 digits)</strong></p>
                <p style="color: #a0a0a0; margin: 0.5rem 0 0 0; font-size: 0.9rem;">Right-click a user in Discord → Copy User ID (Developer Mode must be enabled)</p>
            </div>
        `;
        return;
    }
    
    try {
        // Fetch user data from Discord API proxy
        let userData = null;
        let error = null;
        
        try {
            const response = await fetch(`https://discordlookup.mesalytic.moe/v1/user/${userId}`);
            if (response.ok) {
                userData = await response.json();
            }
        } catch (e) {
            error = 'API temporarily unavailable';
        }
        
        // Build results HTML
        let html = '<h4 style="color: #00ffcc; margin-bottom: 1rem;">📊 Discord User Analysis:</h4>';
        
        // Basic Account Information (always available from ID)
        const creationDate = getDiscordCreationDate(userId);
        const accountAge = getAccountAge(creationDate);
        
        html += `
            <div style="padding: 1.5rem; background: rgba(88,101,242,0.1); border-radius: 10px; border-left: 4px solid #5865F2; margin-bottom: 1rem;">
                <h4 style="color: #5865F2; margin-bottom: 1rem;">📋 Account Information</h4>
                <div style="display: grid; gap: 0.75rem;">
                    <div style="padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: 5px;">
                        <strong style="color: #00ffcc;">User ID:</strong> 
                        <span style="color: #c0c0c0; font-family: monospace; user-select: all;">${userId}</span>
                    </div>
                    <div style="padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: 5px;">
                        <strong style="color: #00ffcc;">Account Created:</strong> 
                        <span style="color: #c0c0c0;">${creationDate.toLocaleString('en-US', { 
                            weekday: 'long', 
                            year: 'numeric', 
                            month: 'long', 
                            day: 'numeric', 
                            hour: '2-digit', 
                            minute: '2-digit' 
                        })}</span>
                    </div>
                    <div style="padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: 5px;">
                        <strong style="color: #00ffcc;">Account Age:</strong> 
                        <span style="color: #c0c0c0;">${accountAge}</span>
                    </div>
        `;
        
        // Fetched User Data
        if (userData) {
            if (userData.username) {
                html += `
                    <div style="padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: 5px;">
                        <strong style="color: #00ffcc;">Current Username:</strong> 
                        <span style="color: #c0c0c0;">${escapeHtml(userData.username)}</span>
                        ${userData.global_name ? `<br><strong style="color: #00ffcc;">Display Name:</strong> <span style="color: #c0c0c0;">${escapeHtml(userData.global_name)}</span>` : ''}
                    </div>
                `;
            }
            
            if (userData.avatar) {
                const avatarUrl = `https://cdn.discordapp.com/avatars/${userId}/${userData.avatar}.${userData.avatar.startsWith('a_') ? 'gif' : 'png'}?size=256`;
                html += `
                    <div style="padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: 5px;">
                        <strong style="color: #00ffcc;">Avatar:</strong><br>
                        <img src="${avatarUrl}" alt="Avatar" style="width: 128px; height: 128px; border-radius: 50%; margin-top: 0.5rem; border: 3px solid #5865F2;">
                        <br><a href="${avatarUrl}" target="_blank" style="color: #00d4ff; font-size: 0.9rem; text-decoration: none;">🔗 View Full Size</a>
                    </div>
                `;
            }
            
            // Badges
            if (userData.public_flags || userData.flags) {
                const flags = userData.public_flags || userData.flags;
                const badges = getDiscordBadges(flags);
                if (badges.length > 0) {
                    html += `
                        <div style="padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: 5px;">
                            <strong style="color: #00ffcc;">Badges:</strong><br>
                            <div style="margin-top: 0.5rem; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                                ${badges.map(badge => `<span style="background: rgba(88,101,242,0.2); padding: 0.25rem 0.75rem; border-radius: 15px; font-size: 0.85rem; color: #c0c0c0;">${badge}</span>`).join('')}
                            </div>
                        </div>
                    `;
                }
            }
            
            // Banner
            if (userData.banner) {
                const bannerUrl = `https://cdn.discordapp.com/banners/${userId}/${userData.banner}.${userData.banner.startsWith('a_') ? 'gif' : 'png'}?size=600`;
                html += `
                    <div style="padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: 5px;">
                        <strong style="color: #00ffcc;">Profile Banner:</strong><br>
                        <img src="${bannerUrl}" alt="Banner" style="width: 100%; max-width: 400px; border-radius: 8px; margin-top: 0.5rem;">
                    </div>
                `;
            } else if (userData.accent_color) {
                html += `
                    <div style="padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: 5px;">
                        <strong style="color: #00ffcc;">Banner Color:</strong> 
                        <span style="display: inline-block; width: 30px; height: 30px; background: #${userData.accent_color.toString(16).padStart(6, '0')}; border-radius: 5px; vertical-align: middle; margin-left: 0.5rem; border: 2px solid #fff;"></span>
                        <span style="color: #c0c0c0; margin-left: 0.5rem;">#${userData.accent_color.toString(16).padStart(6, '0').toUpperCase()}</span>
                    </div>
                `;
            }
            
            // Bot status
            if (userData.bot) {
                html += `
                    <div style="padding: 0.75rem; background: rgba(88,101,242,0.2); border-radius: 5px;">
                        <strong style="color: #5865F2;">🤖 This is a Bot Account</strong>
                    </div>
                `;
            }
        }
        
        html += `
                </div>
            </div>
        `;
        
        // Connected Accounts & Social Links
        html += `
            <div style="padding: 1.5rem; background: rgba(0,0,0,0.3); border-radius: 10px; margin-bottom: 1rem;">
                <h4 style="color: #00ffcc; margin-bottom: 1rem;">🔗 Find Connected Social Media</h4>
                <p style="color: #a0a0a0; font-size: 0.9rem; margin-bottom: 1rem;">Search for this user across different platforms:</p>
                <div style="display: grid; gap: 0.75rem;">
        `;
        
        const searchQuery = userData?.username || userId;
        
        const socialTools = [
            { 
                name: 'Username Search (Sherlock)', 
                url: `https://whatsmyname.app/?q=${searchQuery}`,
                icon: '🔍',
                color: '#4285f4',
                desc: 'Search username across 400+ sites'
            },
            { 
                name: 'GitHub Search', 
                url: `https://github.com/search?q=${searchQuery}&type=users`,
                icon: '💻',
                color: '#6cc644',
                desc: 'Find GitHub profiles'
            },
            { 
                name: 'Twitter/X Search', 
                url: `https://twitter.com/search?q="${searchQuery}"`,
                icon: '🐦',
                color: '#1da1f2',
                desc: 'Search mentions on Twitter'
            },
            { 
                name: 'Reddit Search', 
                url: `https://www.reddit.com/search/?q=${searchQuery}`,
                icon: '🤖',
                color: '#ff4500',
                desc: 'Search Reddit for username'
            },
            { 
                name: 'Steam Profile', 
                url: `https://steamcommunity.com/search/users/#text=${searchQuery}`,
                icon: '🎮',
                color: '#171a21',
                desc: 'Find Steam profiles'
            }
        ];
        
        socialTools.forEach(tool => {
            html += `
                <div style="padding: 0.75rem; background: rgba(0,212,255,0.05); border-radius: 8px; border-left: 3px solid ${tool.color};">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <strong style="color: ${tool.color};">${tool.icon} ${tool.name}</strong>
                            <p style="color: #808080; font-size: 0.85rem; margin: 0.25rem 0 0 0;">${tool.desc}</p>
                        </div>
                        <a href="${tool.url}" target="_blank" style="color: #00d4ff; text-decoration: none; font-weight: bold; white-space: nowrap; margin-left: 1rem;">Open →</a>
                    </div>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
        
        // Additional OSINT Tools
        html += `
            <div style="padding: 1.5rem; background: rgba(0,0,0,0.3); border-radius: 10px; margin-bottom: 1rem;">
                <h4 style="color: #00ffcc; margin-bottom: 1rem;">🛠️ Advanced OSINT Tools</h4>
                <div style="display: grid; gap: 0.75rem;">
        `;
        
        const osintTools = [
            { 
                name: 'Discord.id - Username History', 
                url: `https://discord.id/?prefill=${userId}`,
                desc: 'Track username changes and avatar history',
                color: '#5865F2'
            },
            { 
                name: 'Discord Lookup - Mutual Servers', 
                url: `https://discordlookup.com/user/${userId}`,
                desc: 'Find mutual servers and connections',
                color: '#7289da'
            },
            { 
                name: 'Lookup.guru - Public Servers', 
                url: `https://lookup.guru/${userId}`,
                desc: 'See public server memberships',
                color: '#43b581'
            },
            { 
                name: 'Discord Snowflake Decoder', 
                url: `https://snowsta.mp/${userId}`,
                desc: 'Decode timestamp from Discord ID',
                color: '#99aab5'
            }
        ];
        
        osintTools.forEach(tool => {
            html += `
                <div style="padding: 1rem; background: rgba(0,212,255,0.05); border-radius: 8px; border-left: 3px solid ${tool.color};">
                    <div style="margin-bottom: 0.5rem;">
                        <strong style="color: ${tool.color}; font-size: 1.05rem;">${tool.name}</strong>
                        <p style="color: #808080; font-size: 0.85rem; margin: 0.25rem 0;">${tool.desc}</p>
                    </div>
                    <a href="${tool.url}" target="_blank" style="color: #00d4ff; text-decoration: none; font-size: 0.9rem;">
                        🔗 Open Tool
                    </a>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
        
        // Privacy Notice
        html += `
            <div style="margin-top: 1rem; padding: 1rem; background: rgba(255,193,7,0.1); border-radius: 8px; border-left: 4px solid #ffc107;">
                <p style="color: #ffc107; margin: 0; font-size: 0.9rem;">
                    ⚠️ <strong>Privacy Notice:</strong> Only publicly available information is displayed. 
                    Use responsibly and ethically for legitimate research purposes only.
                </p>
            </div>
        `;
        
        resultsDiv.innerHTML = html;
        
    } catch (error) {
        console.error('Error fetching Discord data:', error);
        resultsDiv.innerHTML = `
            <div style="padding: 1rem; background: rgba(255,107,107,0.1); border-radius: 8px; border-left: 4px solid #ff6b6b;">
                <p style="color: #ff6b6b; margin: 0;">
                    ❌ <strong>Error fetching data.</strong> The user may have privacy settings enabled, or the API is temporarily unavailable.
                </p>
            </div>
        `;
    }
}

// Helper function to get Discord account creation date from User ID
function getDiscordCreationDate(userId) {
    const DISCORD_EPOCH = 1420070400000;
    const timestamp = (BigInt(userId) >> 22n) + BigInt(DISCORD_EPOCH);
    return new Date(Number(timestamp));
}

// Helper function to calculate account age
function getAccountAge(creationDate) {
    const now = new Date();
    const diff = now - creationDate;
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));
    const years = Math.floor(days / 365);
    const months = Math.floor((days % 365) / 30);
    const remainingDays = days % 30;
    
    let ageString = '';
    if (years > 0) ageString += `${years} year${years > 1 ? 's' : ''}, `;
    if (months > 0) ageString += `${months} month${months > 1 ? 's' : ''}, `;
    ageString += `${remainingDays} day${remainingDays !== 1 ? 's' : ''}`;
    
    return ageString.trim();
}

// Helper function to decode Discord badges
function getDiscordBadges(flags) {
    const badges = [];
    const badgeFlags = {
        1: '⚔️ Discord Staff',
        2: '👥 Partnered Server Owner',
        4: '🎉 HypeSquad Events',
        8: '🐛 Bug Hunter Level 1',
        64: '🏠 HypeSquad Bravery',
        128: '🏠 HypeSquad Brilliance',
        256: '🏠 HypeSquad Balance',
        512: '⭐ Early Supporter',
        16384: '🐛 Bug Hunter Level 2',
        131072: '🤖 Verified Bot Developer',
        262144: '👨‍💻 Early Verified Bot Developer',
        4194304: '🔨 Active Developer'
    };
    
    for (const [flag, badge] of Object.entries(badgeFlags)) {
        if ((flags & parseInt(flag)) === parseInt(flag)) {
            badges.push(badge);
        }
    }
    
    return badges;
}

// Helper function to escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}


// ============================================
// USERNAME AVAILABILITY CHECKER
// ============================================
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
        { name: 'LinkedIn', url: `https://linkedin.com/in/${username}`, color: '#0077b5' },
        { name: 'Twitch', url: `https://twitch.tv/${username}`, color: '#9146ff' },
        { name: 'Steam', url: `https://steamcommunity.com/id/${username}`, color: '#171a21' }
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


// ============================================
// DOMAIN INFORMATION LOOKUP
// ============================================
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
            { name: 'Wayback Machine', url: `https://web.archive.org/web/*/${domain}` },
            { name: 'Security Report', url: `https://www.virustotal.com/gui/domain/${domain}` }
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


// ============================================
// IP ADDRESS GEOLOCATION
// ============================================
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
            { name: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${ip}` },
            { name: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${ip}` }
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


// ============================================
// INITIALIZE
// ============================================
document.addEventListener('DOMContentLoaded', function() {
    console.log('✅ Zyros-OSINT Platform Loaded');
    console.log('🔍 Educational OSINT tools ready for ethical research');
    console.log('⚠️ All tools for legitimate research purposes only');
});


// ============================================
// THREAT ACTOR & BREACH ATTRIBUTION
// ============================================
async function analyzeThreatActor() {
    const username = document.getElementById('threatActorInput').value.trim();
    const resultsDiv = document.getElementById('threatActorResults');
    
    if (!username) {
        resultsDiv.innerHTML = '<p style="color: #ff6b6b;">⚠️ Please enter a username or handle</p>';
        return;
    }
    
    resultsDiv.innerHTML = '<p style="color: #00d4ff;">🔍 Searching threat intelligence databases and cybercrime forums...</p>';
    
    setTimeout(() => {
        let html = '<h4 style="color: #ff453a; margin-bottom: 1rem;">⚠️ Threat Actor Intelligence Report:</h4>';
        
        // Search Profile
        html += `
            <div style="padding: 1.5rem; background: rgba(255,69,58,0.1); border-radius: 10px; border-left: 4px solid #ff453a; margin-bottom: 1rem;">
                <h4 style="color: #ff453a; margin-bottom: 1rem;">🎯 Search Target</h4>
                <div style="padding: 0.75rem; background: rgba(0,0,0,0.3); border-radius: 5px;">
                    <strong style="color: #00ffcc;">Username/Handle:</strong> 
                    <span style="color: #c0c0c0; font-family: monospace;">${escapeHtml(username)}</span>
                </div>
            </div>
        `;
        
        // Known Breach Databases & Forums
        html += `
            <div style="padding: 1.5rem; background: rgba(0,0,0,0.3); border-radius: 10px; margin-bottom: 1rem;">
                <h4 style="color: #ff453a; margin-bottom: 1rem;">🔎 Breach & Cybercrime Database Search</h4>
                <p style="color: #a0a0a0; font-size: 0.9rem; margin-bottom: 1rem;">Search for this username in known breach databases and hacker forums:</p>
                <div style="display: grid; gap: 0.75rem;">
        `;
        
        const breachDatabases = [
            {
                name: 'BreachForums Archive Search',
                url: `https://www.google.com/search?q=site:breachforums.st "${username}"`,
                icon: '💀',
                color: '#ff453a',
                desc: 'Search BreachForums for mentions of this username'
            },
            {
                name: 'RaidForums Archive',
                url: `https://www.google.com/search?q=site:raidforums.com "${username}" OR site:raid.lol "${username}"`,
                icon: '🏴‍☠️',
                color: '#ff6b6b',
                desc: 'Search archived RaidForums posts'
            },
            {
                name: 'Exploit.in Search',
                url: `https://www.google.com/search?q=site:exploit.in "${username}"`,
                icon: '🎭',
                color: '#e74c3c',
                desc: 'Russian-speaking cybercrime forum'
            },
            {
                name: 'XSS.is Forum Search',
                url: `https://www.google.com/search?q=site:xss.is "${username}"`,
                icon: '⚡',
                color: '#c0392b',
                desc: 'Underground hacking marketplace'
            },
            {
                name: 'Nulled.to Search',
                url: `https://www.google.com/search?q=site:nulled.to "${username}"`,
                icon: '🔓',
                color: '#e67e22',
                desc: 'Cracking and fraud forum'
            },
            {
                name: 'GitHub Code Search',
                url: `https://github.com/search?q="${username}"+breach+OR+leak+OR+dump&type=code`,
                icon: '💻',
                color: '#6cc644',
                desc: 'Search for breach claims in GitHub repos'
            }
        ];
        
        breachDatabases.forEach(db => {
            html += `
                <div style="padding: 1rem; background: rgba(255,69,58,0.05); border-radius: 8px; border-left: 3px solid ${db.color};">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div style="flex: 1;">
                            <strong style="color: ${db.color};">${db.icon} ${db.name}</strong>
                            <p style="color: #808080; font-size: 0.85rem; margin: 0.25rem 0 0 0;">${db.desc}</p>
                        </div>
                        <a href="${db.url}" target="_blank" style="color: #ff453a; text-decoration: none; font-weight: bold; white-space: nowrap; margin-left: 1rem;">Search →</a>
                    </div>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
        
        // Paste Sites & Leak Repositories
        html += `
            <div style="padding: 1.5rem; background: rgba(0,0,0,0.3); border-radius: 10px; margin-bottom: 1rem;">
                <h4 style="color: #ff453a; margin-bottom: 1rem;">📄 Paste Sites & Leak Dumps</h4>
                <p style="color: #a0a0a0; font-size: 0.9rem; margin-bottom: 1rem;">Check if this user has posted or been mentioned in data dumps:</p>
                <div style="display: grid; gap: 0.75rem;">
        `;
        
        const pasteSites = [
            {
                name: 'Pastebin Search',
                url: `https://www.google.com/search?q=site:pastebin.com "${username}" (breach OR leak OR dump)`,
                icon: '📋',
                color: '#02a95c'
            },
            {
                name: 'Rentry Search',
                url: `https://www.google.com/search?q=site:rentry.co OR site:rentry.org "${username}"`,
                icon: '📝',
                color: '#3498db'
            },
            {
                name: 'Ghostbin Search',
                url: `https://www.google.com/search?q=site:ghostbin.com "${username}"`,
                icon: '👻',
                color: '#95a5a6'
            },
            {
                name: 'Telegram Breach Channels',
                url: `https://www.google.com/search?q=site:t.me "${username}" (database OR breach OR leak)`,
                icon: '✈️',
                color: '#0088cc'
            }
        ];
        
        pasteSites.forEach(site => {
            html += `
                <div style="padding: 0.75rem; background: rgba(255,69,58,0.05); border-radius: 8px; border-left: 3px solid ${site.color};">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong style="color: ${site.color};">${site.icon} ${site.name}</strong>
                        <a href="${site.url}" target="_blank" style="color: #ff453a; text-decoration: none; font-weight: bold; white-space: nowrap; margin-left: 1rem;">Check →</a>
                    </div>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
        
        // Social Media & Reputation Check
        html += `
            <div style="padding: 1.5rem; background: rgba(0,0,0,0.3); border-radius: 10px; margin-bottom: 1rem;">
                <h4 style="color: #ff453a; margin-bottom: 1rem;">🌐 Social Media Reputation Search</h4>
                <p style="color: #a0a0a0; font-size: 0.9rem; margin-bottom: 1rem;">Check for mentions in security communities and social media:</p>
                <div style="display: grid; gap: 0.75rem;">
        `;
        
        const socialChecks = [
            {
                name: 'Twitter/X Cybersecurity Search',
                url: `https://twitter.com/search?q="${username}" (hacker OR breach OR leak OR cybercrime)&f=live`,
                icon: '🐦',
                color: '#1da1f2'
            },
            {
                name: 'Reddit InfoSec Communities',
                url: `https://www.reddit.com/search/?q="${username}" (breach OR hack OR compromised)`,
                icon: '🤖',
                color: '#ff4500'
            },
            {
                name: 'YouTube Security Channel Search',
                url: `https://www.youtube.com/results?search_query="${username}"+breach+OR+hack`,
                icon: '📺',
                color: '#ff0000'
            },
            {
                name: 'Medium Security Articles',
                url: `https://www.google.com/search?q=site:medium.com "${username}" (breach OR hack OR vulnerability)`,
                icon: '📰',
                color: '#00ab6c'
            }
        ];
        
        socialChecks.forEach(check => {
            html += `
                <div style="padding: 0.75rem; background: rgba(255,69,58,0.05); border-radius: 8px; border-left: 3px solid ${check.color};">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <strong style="color: ${check.color};">${check.icon} ${check.name}</strong>
                        <a href="${check.url}" target="_blank" style="color: #ff453a; text-decoration: none; font-weight: bold; white-space: nowrap; margin-left: 1rem;">Search →</a>
                    </div>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
        
        // Threat Intelligence Platforms
        html += `
            <div style="padding: 1.5rem; background: rgba(0,0,0,0.3); border-radius: 10px; margin-bottom: 1rem;">
                <h4 style="color: #ff453a; margin-bottom: 1rem;">🛡️ Threat Intelligence Platforms</h4>
                <p style="color: #a0a0a0; font-size: 0.9rem; margin-bottom: 1rem;">Professional threat intelligence databases:</p>
                <div style="display: grid; gap: 0.75rem;">
        `;
        
        const threatIntel = [
            {
                name: 'IntelX Search',
                url: `https://intelx.io/?s=${encodeURIComponent(username)}`,
                icon: '🔍',
                color: '#2c3e50',
                desc: 'Search darknet, paste sites, and breach databases'
            },
            {
                name: 'Dehashed',
                url: `https://dehashed.com/search?query="${username}"`,
                icon: '🔓',
                color: '#e74c3c',
                desc: 'Breach database search engine'
            },
            {
                name: 'LeakCheck',
                url: `https://leakcheck.io/search/${encodeURIComponent(username)}`,
                icon: '💧',
                color: '#3498db',
                desc: 'Data breach search and monitoring'
            },
            {
                name: 'Have I Been Pwned',
                url: `https://haveibeenpwned.com/`,
                icon: '🔐',
                color: '#f39c12',
                desc: 'Check if username appears in known breaches'
            }
        ];
        
        threatIntel.forEach(intel => {
            html += `
                <div style="padding: 1rem; background: rgba(255,69,58,0.05); border-radius: 8px; border-left: 3px solid ${intel.color};">
                    <div style="margin-bottom: 0.5rem;">
                        <strong style="color: ${intel.color}; font-size: 1.05rem;">${intel.icon} ${intel.name}</strong>
                        <p style="color: #808080; font-size: 0.85rem; margin: 0.25rem 0;">${intel.desc}</p>
                    </div>
                    <a href="${intel.url}" target="_blank" style="color: #ff453a; text-decoration: none; font-size: 0.9rem;">
                        🔗 Check Database
                    </a>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
        
        // Advanced OSINT Techniques
        html += `
            <div style="padding: 1.5rem; background: rgba(0,0,0,0.3); border-radius: 10px; margin-bottom: 1rem;">
                <h4 style="color: #ff453a; margin-bottom: 1rem;">🔬 Advanced Investigation Techniques</h4>
                <div style="display: grid; gap: 0.5rem;">
                    <div style="padding: 0.75rem; background: rgba(0,0,0,0.2); border-radius: 5px;">
                        <strong style="color: #00ffcc;">Google Dork:</strong>
                        <code style="background: rgba(0,0,0,0.5); padding: 0.25rem 0.5rem; border-radius: 3px; display: inline-block; margin-top: 0.25rem; color: #00d4ff; font-size: 0.9rem;">
                            "${username}" (breach OR leak OR dump OR database) -site:linkedin.com -site:facebook.com
                        </code>
                    </div>
                    <div style="padding: 0.75rem; background: rgba(0,0,0,0.2); border-radius: 5px;">
                        <strong style="color: #00ffcc;">IRC Archive Search:</strong>
                        <a href="https://www.google.com/search?q=site:logs.ircd.chat+OR+site:irclog.whitequark.org+%22${username}%22" target="_blank" style="color: #ff453a; text-decoration: none; margin-left: 0.5rem;">Search IRC Logs →</a>
                    </div>
                    <div style="padding: 0.75rem; background: rgba(0,0,0,0.2); border-radius: 5px;">
                        <strong style="color: #00ffcc;">Wayback Machine:</strong>
                        <a href="https://web.archive.org/web/*/${username}" target="_blank" style="color: #ff453a; text-decoration: none; margin-left: 0.5rem;">Check Archive →</a>
                    </div>
                </div>
            </div>
        `;
        
        // Warning Notice
        html += `
            <div style="margin-top: 1rem; padding: 1rem; background: rgba(255,193,7,0.1); border-radius: 8px; border-left: 4px solid #ffc107;">
                <p style="color: #ffc107; margin: 0; font-size: 0.9rem;">
                    ⚠️ <strong>Legal Notice:</strong> This tool is for security research and threat intelligence purposes only. 
                    Accessing cybercrime forums or engaging with threat actors may be illegal in your jurisdiction. 
                    Use responsibly and in compliance with all applicable laws.
                </p>
            </div>
        `;
        
        html += `
            <div style="margin-top: 1rem; padding: 1rem; background: rgba(255,69,58,0.1); border-radius: 8px; border-left: 4px solid #ff453a;">
                <p style="color: #ff453a; margin: 0; font-size: 0.9rem;">
                    🔴 <strong>Disclaimer:</strong> The presence of a username in search results does not confirm criminal activity. 
                    Always verify information through official channels and law enforcement when appropriate.
                </p>
            </div>
        `;
        
        resultsDiv.innerHTML = html;
    }, 1000);
}
