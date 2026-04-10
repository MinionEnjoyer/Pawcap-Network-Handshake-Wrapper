// Pawcap Web Interface - Frontend JavaScript

const API_BASE = window.location.origin;
let updateInterval;
let feedInterval;
let feedEnabled = false;
let serverUptime = 0; // Server uptime in seconds from API
let handshakeUpdateCounter = 0;
let scannerSynced = false; // Prevent toggle desync on page load
let pendingToggles = {};   // Track in-flight toggle API calls to prevent polling overwrite
let statusPollBusy = false; // Prevent overlapping status polls

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
    console.log('Pawcap initializing...');
    
    loadSavedTheme();
    
    // Set dynamic footer information
    const currentIP = window.location.hostname;
    updateFooter(currentIP);
    
    updateStatus();
    updateHandshakes();
    updateBlacklist();
    updateWhitelist();
    startAutoUpdate();
});

// Update footer with dynamic information
async function updateFooter(ip) {
    try {
        // Get system info from API
        const response = await fetch(`${API_BASE}/api/status`);
        if (response.ok) {
            const data = await response.json();
            const username = data.system?.username || 'user';
            const hostname = data.system?.hostname || 'pawcap';
            
            document.getElementById('userHost').textContent = `${username}@${hostname}`;
            document.getElementById('userIP').textContent = `${username}@${ip}`;
        } else {
            document.getElementById('userHost').textContent = 'user@pawcap';
            document.getElementById('userIP').textContent = `user@${ip}`;
        }
    } catch (error) {
        console.error('Failed to update footer:', error);
    }
}

// Start automatic updates
function startAutoUpdate() {
    updateInterval = setInterval(async () => {
        updateStatus();
        updateUptime();
        handshakeUpdateCounter++;
        if (handshakeUpdateCounter >= 5) {
            handshakeUpdateCounter = 0;
            // Serialize slow-poll fetches to avoid concurrent request pileup
            await updateHandshakes();
            await updateBlacklist();
            await updateWhitelist();
            if (document.getElementById('socialToggle').checked) {
                await updateFriends();
            }
        }
    }, 2000); // Update every 2 seconds
}

// Update system status
async function updateStatus() {
    if (statusPollBusy) return; // Previous poll still in-flight — skip to prevent thread pileup
    statusPollBusy = true;
    try {
        const response = await fetch(`${API_BASE}/api/status`);
        if (!response.ok) throw new Error('API not responding');
        
        const data = await response.json();
        
        // Update stats cards
        document.getElementById('networksScanned').textContent = data.stats.networks_scanned || 0;
        document.getElementById('handshakesCaptured').textContent = data.stats.handshakes_captured || 0;
        
        if (data.stats.candidates !== undefined) {
            const el = document.getElementById('candidateCount');
            if (el) el.textContent = data.stats.candidates;
        }
        if (data.stats.success_rate !== undefined) {
            const el = document.getElementById('successRate');
            if (el) el.textContent = data.stats.success_rate + '%';
        }
        
        // Update server uptime from API
        if (data.system && data.system.uptime !== undefined) {
            serverUptime = data.system.uptime;
        }
        
        // Update header health (battery + temp + drive)
        updateHeaderHealth(data.battery, data.system?.cpu_temp, data.disk);
        
        // Update Scanner Activity card
        const phase = data.activity.scan_phase || '';
        const modeText = phase ? `${data.activity.mode || 'Scanning'} [${phase}]` : (data.activity.mode || 'Scanning');
        document.getElementById('mode').textContent = modeText;
        document.getElementById('channel').textContent = data.activity.channel || '--';
        document.getElementById('candidatesInline').textContent = data.stats.candidates || 0;
        document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
        
        // Update Auth Activity card
        document.getElementById('authHandshakes').textContent = data.stats.handshakes_captured || 0;
        document.getElementById('authSuccessRate').textContent = (data.stats.success_rate || 0) + '%';
        document.getElementById('authDeauths').textContent = data.stats.deauths_sent || 0;
        document.getElementById('authPassive').textContent = data.stats.passive_captures || 0;
        
        // Update GPS info in Auth Activity
        if (data.gps) {
            document.getElementById('gpsStatus').textContent = data.gps.fix ? 'Locked' : 'No Fix';
            document.getElementById('latitude').textContent = data.gps.latitude || '--';
            document.getElementById('longitude').textContent = data.gps.longitude || '--';
            document.getElementById('satellites').textContent = data.gps.satellites || '--';
        }
        
        // Update learning stats
        if (data.learning) {
            const el1 = document.getElementById('lifetimeHandshakes');
            const el2 = document.getElementById('knownNetworks');
            const el3 = document.getElementById('repeatOffenders');
            if (el1) el1.textContent = data.learning.lifetime_handshakes || 0;
            if (el2) el2.textContent = data.learning.known_networks || 0;
            if (el3) el3.textContent = data.learning.repeat_offenders || 0;
        }
        
        // Sync scanner toggle with actual state (with desync protection)
        if (data.activity.scanner_running !== undefined) {
            document.getElementById('scannerToggle').checked = data.activity.scanner_running;
            scannerSynced = true;
        }
        
        // Sync organic mode toggle
        if (data.activity.organic_mode !== undefined) {
            document.getElementById('organicToggle').checked = data.activity.organic_mode;
        }
        
        // Sync social mode toggle (skip if toggle API call is in flight)
        if (data.activity.social_mode !== undefined && !pendingToggles.social) {
            const socialToggle = document.getElementById('socialToggle');
            socialToggle.checked = data.activity.social_mode;
            document.getElementById('socialSection').style.display = data.activity.social_mode ? 'block' : 'none';
        }
        
        // Sync find friends toggle (skip if toggle API call is in flight)
        if (data.activity.find_friends_mode !== undefined && !pendingToggles.findFriends) {
            document.getElementById('findFriendsToggle').checked = data.activity.find_friends_mode;
        }
        
        // Sync pack mode toggle (skip if toggle API call is in flight)
        if (data.activity.pack_mode !== undefined && !pendingToggles.packMode) {
            document.getElementById('packModeToggle').checked = data.activity.pack_mode;
        }
        
        // Update device name in name panel + settings input
        if (data.device_name) {
            const nameDisplay = document.getElementById('deviceNameDisplay');
            if (nameDisplay) nameDisplay.textContent = data.device_name.toUpperCase();
            const nameInput = document.getElementById('deviceNameInput');
            if (nameInput && !nameInput.matches(':focus')) {
                nameInput.value = data.device_name;
            }
        }

        // Update character mood (skip if toggled off for battery saving)
        if (data.mood && characterEnabled) {
            document.getElementById('characterFace').textContent = data.mood.face;
            document.getElementById('characterMood').textContent = data.mood.state;
            document.getElementById('characterMessage').textContent = data.mood.message;
            document.getElementById('characterPanel').className = 'character-panel mood-' + data.mood.state;
        }
        
        // Update interface status inside Scanner Activity card
        if (data.interfaces) {
            updateInterfaceList(data.interfaces);
        }
        
        // Update recent captures
        if (data.recent_captures && data.recent_captures.length > 0) {
            updateCaptureList(data.recent_captures);
        }
        
    } catch (error) {
        console.error('Failed to update status:', error);
    } finally {
        statusPollBusy = false;
    }
}

// Update battery, CPU temp, and drive stat cards
function updateHeaderHealth(battery, cpuTemp, disk) {
    // Battery stat card
    if (battery && battery.available) {
        const cap = battery.capacity || 0;
        const volt = battery.voltage ? battery.voltage.toFixed(2) : '--';
        const charging = battery.charging;
        
        const battValue = document.getElementById('battStatValue');
        const battLabel = document.getElementById('battStatLabel');
        battValue.textContent = cap + '%';
        battLabel.textContent = volt + 'V' + (charging ? ' CHG' : '');
        
        // Color code the value
        battValue.style.color = '';
        if (charging) {
            battValue.style.color = 'var(--success)';
        } else if (cap <= 20) {
            battValue.style.color = 'var(--primary)';
        } else if (cap <= 50) {
            battValue.style.color = '#ff9900';
        }
    }
    
    // CPU Temperature stat card
    if (cpuTemp !== null && cpuTemp !== undefined) {
        const tempValue = document.getElementById('tempStatValue');
        tempValue.textContent = cpuTemp + 'C';
        
        // Color code by temperature
        tempValue.style.color = '';
        if (cpuTemp >= 70) {
            tempValue.style.color = 'var(--primary)';
        } else if (cpuTemp >= 55) {
            tempValue.style.color = '#ff9900';
        }
    }
    
    // Drive stat card
    if (disk && disk.available) {
        const driveValue = document.getElementById('driveStatValue');
        const driveLabel = document.getElementById('driveStatLabel');
        const usedGb = disk.used_gb;
        const freeGb = disk.free_gb;
        const totalGb = disk.total_gb;
        const usedPct = Math.round((usedGb / totalGb) * 100);
        
        driveValue.textContent = freeGb + 'G';
        driveLabel.textContent = usedGb + 'G used / ' + totalGb + 'G';
        
        // Color code by usage
        driveValue.style.color = '';
        if (usedPct >= 90) {
            driveValue.style.color = 'var(--primary)';
        } else if (usedPct >= 75) {
            driveValue.style.color = '#ff9900';
        }
    }
}

// Update interface list
function updateInterfaceList(interfaces) {
    const interfaceList = document.getElementById('interfaceList');
    
    if (!interfaces || interfaces.length === 0) {
        interfaceList.innerHTML = '<p class="empty-state">No interfaces active...</p>';
        return;
    }
    
    interfaceList.innerHTML = interfaces.map(iface => {
        const statusClass = iface.status === 'CAPTURING' ? 'capturing' : 'scanning';
        const targetInfo = iface.target ? `
            <div class="target-info">
                <strong>Target:</strong> ${iface.target.ssid} (${iface.target.bssid})<br>
                <strong>Elapsed:</strong> ${iface.target.elapsed}s
                ${iface.target.deauthing ? '<span class="deauth-indicator">DEAUTH</span>' : ''}
            </div>
        ` : '';
        
        // Adapter hardware info (chipset, bands)
        const hw = iface.hw || {};
        const chipset = hw.chipset && hw.chipset !== 'unknown' ? hw.chipset : '';
        const bands = (hw.bands || []).join(' + ');
        const hwLine = chipset || bands ? `
            <div class="interface-hw">
                ${chipset ? `<span class="hw-chipset">${chipset}</span>` : ''}
                ${bands ? `<span class="hw-bands">${bands}</span>` : ''}
            </div>
        ` : '';
        
        return `
            <div class="interface-item">
                <div class="interface-header">
                    <span class="interface-name">${iface.name}</span>
                    <span class="interface-status-badge ${statusClass}">${iface.status}</span>
                </div>
                <div class="interface-details">
                    <strong>Role:</strong> ${iface.type || 'Scanner'}<br>
                    <strong>Channel:</strong> ${iface.channel} ${getBand(iface.channel) ? '(' + getBand(iface.channel) + ')' : ''}
                    ${hwLine}
                    ${targetInfo}
                </div>
            </div>
        `;
    }).join('');
}

// Update capture list
function updateCaptureList(captures) {
    const captureList = document.getElementById('captureList');
    
    if (captures.length === 0) {
        captureList.innerHTML = '<p class="empty-state">No captures yet...</p>';
        return;
    }
    
    captureList.innerHTML = captures.map(capture => {
        const clients = capture.clients !== undefined ? capture.clients : '--';
        const scoreTag = capture.score !== undefined ? 
            `<span class="network-score">SCORE: ${capture.score}</span>` : '';
        const clientTag = clients > 0 ? 
            `<span class="network-clients">${clients} client${clients !== 1 ? 's' : ''}</span>` : '';
        
        return `
            <div class="capture-item">
                <div class="capture-header">
                    <strong>${capture.ssid}</strong> ${scoreTag} ${clientTag}
                </div>
                <small>Ch ${capture.channel} ${getBand(capture.channel)} | Signal: ${capture.signal}dBm | ${capture.encryption || ''} | ${capture.timestamp}</small>
            </div>
        `;
    }).join('');
}

// Update handshakes list
async function updateHandshakes() {
    try {
        const response = await fetch(`${API_BASE}/api/handshakes`);
        if (!response.ok) return;
        
        const handshakes = await response.json();
        const handshakeList = document.getElementById('handshakeList');
        
        if (!handshakes || handshakes.length === 0) {
            handshakeList.innerHTML = '<p class="empty-state">No handshakes captured yet...</p>';
            return;
        }
        
        handshakeList.innerHTML = handshakes.map(hs => {
            // Database stores UTC timestamps without timezone indicator
            const utcTimestamp = hs.timestamp.replace(' ', 'T') + 'Z';
            const date = new Date(utcTimestamp);
            const timeStr = date.toLocaleString();
            const badges = [];
            
            badges.push('<span class="handshake-badge captured">CAPTURED</span>');
            if (hs.cracked) {
                badges.push('<span class="handshake-badge cracked">CRACKED</span>');
            }
            if (hs.gps_fix) {
                badges.push('<span class="handshake-badge gps">GPS</span>');
            }
            
            const channelInfo = hs.channel ? 
                `<br><strong>Channel:</strong> ${hs.channel} ${getBand(hs.channel)}` : '';
            const gpsInfo = hs.gps_fix ? 
                `<br><strong>GPS:</strong> ${hs.latitude.toFixed(6)}, ${hs.longitude.toFixed(6)}` : '';
            const passwordInfo = hs.cracked && hs.password ? 
                `<br><strong>Password:</strong> ${hs.password}` : '';
            
            return `
                <div class="handshake-item">
                    <div class="handshake-info">
                        <div class="handshake-ssid">${hs.ssid}</div>
                        <div class="handshake-bssid">${hs.bssid}</div>
                        <div class="handshake-meta">
                            <strong>Captured:</strong> ${timeStr}${channelInfo}${gpsInfo}${passwordInfo}
                        </div>
                    </div>
                    <div class="handshake-status">
                        ${badges.join('')}
                    </div>
                </div>
            `;
        }).join('');
        
    } catch (error) {
        console.error('Failed to update handshakes:', error);
    }
}

// Update uptime
function updateUptime() {
    // Use server uptime (in seconds) instead of page load time
    const hours = Math.floor(serverUptime / 3600);
    const minutes = Math.floor((serverUptime % 3600) / 60);
    const seconds = serverUptime % 60;
    
    document.getElementById('uptime').textContent = 
        `${pad(hours)}:${pad(minutes)}:${pad(seconds)}`;
    
    // Increment for smooth counting between API updates
    serverUptime++;
}

// Format large numbers
function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

// Pad numbers with leading zero
function pad(num) {
    return num.toString().padStart(2, '0');
}

// Get frequency band from channel number
function getBand(channel) {
    const ch = parseInt(channel);
    if (isNaN(ch) || ch <= 0) return '';
    if (ch <= 14) return '2.4GHz';
    return '5GHz';
}

// Control functions for scanner
async function toggleScanner(enabled) {
    // Don't act until we've synced with actual scanner state from API
    if (!scannerSynced) return;
    
    try {
        const endpoint = enabled ? '/api/control/start' : '/api/control/stop';
        const response = await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST'
        });
        
        if (response.ok) {
            console.log(`Scanner ${enabled ? 'started' : 'stopped'}`);
        } else {
            console.error('Failed to toggle scanner');
            document.getElementById('scannerToggle').checked = !enabled;
        }
    } catch (error) {
        console.error('Error toggling scanner:', error);
        document.getElementById('scannerToggle').checked = !enabled;
    }
}

async function toggleGPS(enabled) {
    try {
        const response = await fetch(`${API_BASE}/api/control/gps`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ enabled: enabled })
        });
        
        if (response.ok) {
            console.log(`GPS ${enabled ? 'enabled' : 'disabled'}`);
        } else {
            console.error('Failed to toggle GPS');
            // Revert toggle on failure
            document.getElementById('gpsToggle').checked = !enabled;
        }
    } catch (error) {
        console.error('Error toggling GPS:', error);
        document.getElementById('gpsToggle').checked = !enabled;
    }
}

async function toggleOrganic(enabled) {
    try {
        const response = await fetch(`${API_BASE}/api/control/organic`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        if (!response.ok) {
            console.error('Failed to toggle organic mode:', response.status);
            document.getElementById('organicToggle').checked = !enabled;
        }
    } catch (error) {
        console.error('Failed to toggle organic mode:', error);
        document.getElementById('organicToggle').checked = !enabled;
    }
}

async function toggleSocial(enabled) {
    const section = document.getElementById('socialSection');
    const toggle = document.getElementById('socialToggle');
    section.style.display = enabled ? 'block' : 'none';
    pendingToggles.social = true;
    try {
        const response = await fetch(`${API_BASE}/api/control/social`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        if (response.ok) {
            if (enabled) updateFriends();
        } else {
            console.error('Failed to toggle social mode:', response.status);
            toggle.checked = !enabled;
            section.style.display = enabled ? 'none' : 'block';
        }
    } catch (error) {
        console.error('Failed to toggle social mode:', error);
        toggle.checked = !enabled;
        section.style.display = enabled ? 'none' : 'block';
    } finally {
        pendingToggles.social = false;
    }
}

async function updateFriends() {
    try {
        const response = await fetch(`${API_BASE}/api/social/friends`);
        if (!response.ok) return;

        const friends = await response.json();
        const container = document.getElementById('socialList');
        if (!container) return;

        if (!friends || friends.length === 0) {
            container.innerHTML = '<p class="empty-state">No friends nearby yet...</p>';
            return;
        }

        container.innerHTML = friends.map(friend => {
            const typeBadge = friend.type === 'pwnagotchi'
                ? '<span class="social-badge social-badge-pwnagotchi">PWN</span>'
                : '<span class="social-badge social-badge-pawcap">PAWCAP</span>';
            const packBadge = friend.in_pack
                ? '<span class="social-badge social-badge-pack">PACK</span>'
                : '';

            const lastSeen = typeof friend.last_seen === 'number'
                ? new Date(friend.last_seen * 1000).toLocaleTimeString()
                : friend.last_seen || '--';

            return `
                <div class="social-item${friend.in_pack ? ' pack-member' : ''}">
                    <div class="social-face">${friend.face || ''}</div>
                    <div class="social-info">
                        <div class="social-header">
                            <strong>${friend.name}</strong> ${typeBadge} ${packBadge}
                        </div>
                        <small>Signal: ${friend.signal}dBm | Met ${friend.count}x | v${friend.version} | ${friend.pwnd_tot} captures | Last: ${lastSeen}</small>
                    </div>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.error('Failed to update friends:', error);
    }
}

// Find Friends toggle
async function toggleFindFriends(enabled) {
    const toggle = document.getElementById('findFriendsToggle');
    pendingToggles.findFriends = true;
    try {
        const response = await fetch(`${API_BASE}/api/control/find-friends`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        if (!response.ok) {
            console.error('Failed to toggle find friends:', response.status);
            toggle.checked = !enabled;
        }
    } catch (error) {
        console.error('Failed to toggle find friends:', error);
        toggle.checked = !enabled;
    } finally {
        pendingToggles.findFriends = false;
    }
}

// Pack Mode toggle
async function togglePackMode(enabled) {
    const toggle = document.getElementById('packModeToggle');
    pendingToggles.packMode = true;
    try {
        // Auto-enable social if turning on pack mode
        if (enabled && !document.getElementById('socialToggle').checked) {
            document.getElementById('socialToggle').checked = true;
            await toggleSocial(true);
            // If social failed to enable, abort pack mode
            if (!document.getElementById('socialToggle').checked) {
                toggle.checked = false;
                return;
            }
        }
        const response = await fetch(`${API_BASE}/api/control/pack-mode`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        if (!response.ok) {
            console.error('Failed to toggle pack mode:', response.status);
            toggle.checked = !enabled;
        }
    } catch (error) {
        console.error('Failed to toggle pack mode:', error);
        toggle.checked = !enabled;
    } finally {
        pendingToggles.packMode = false;
    }
}

// Update device name
async function updateDeviceName() {
    const input = document.getElementById('deviceNameInput');
    const name = (input.value || '').trim();
    if (!name) {
        alert('Name cannot be empty.');
        return;
    }
    if (name.length > 32) {
        alert('Name must be 32 characters or less.');
        return;
    }
    try {
        const response = await fetch(`${API_BASE}/api/settings/name`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name })
        });
        const result = await response.json();
        if (response.ok) {
            input.value = result.name;
        } else {
            alert(result.message || 'Failed to update name.');
        }
    } catch (error) {
        console.error('Failed to update device name:', error);
        alert('Failed to update device name.');
    }
}

let characterEnabled = true;

function toggleCharacter(enabled) {
    characterEnabled = enabled;
    const row = document.getElementById('characterRow');
    row.style.display = enabled ? 'flex' : 'none';
}

// Settings toggle
function toggleSettings(enabled) {
    document.getElementById('settingsSection').style.display = enabled ? 'block' : 'none';
    // Show/hide Find Friends toggle (only visible in settings mode)
    const ffRow = document.getElementById('findFriendsRow');
    if (ffRow) ffRow.style.display = enabled ? 'flex' : 'none';
    updateWhitelist();
}

// Theme customization
const themeDefaults = {
    '--primary': '#ff0000',
    '--bg-dark': '#1a1a1a',
    '--card-bg': '#ffffff',
    '--text-dark': '#000000',
    '--success': '#00cc00'
};

// Preset themes
const PRESET_THEMES = {
    'Redline': {
        '--primary': '#ff0000', '--bg-dark': '#1a1a1a',
        '--card-bg': '#ffffff', '--text-dark': '#000000', '--success': '#00cc00'
    },
    'Forest': {
        '--primary': '#3b6255', '--bg-dark': '#1e2a24',
        '--card-bg': '#e2dfda', '--text-dark': '#2a3530', '--success': '#8ba49a'
    },
    'Oasis': {
        '--primary': '#cb7a5c', '--bg-dark': '#5c757a',
        '--card-bg': '#e9e2d8', '--text-dark': '#3b3226', '--success': '#757f64'
    },
    'Professional': {
        '--primary': '#2563eb', '--bg-dark': '#1e293b',
        '--card-bg': '#ffffff', '--text-dark': '#1e293b', '--success': '#16a34a'
    },
    'Subaru': {
        '--primary': '#003399', '--bg-dark': '#0a1628',
        '--card-bg': '#f0f4f8', '--text-dark': '#0a1628', '--success': '#00843d'
    },
    'Ferrari': {
        '--primary': '#dc0000', '--bg-dark': '#1a1000',
        '--card-bg': '#fff8e1', '--text-dark': '#1a1000', '--success': '#ffd700'
    }
};

const themePickerMap = {
    '--primary': 'settingPrimary',
    '--bg-dark': 'settingBg',
    '--card-bg': 'settingCard',
    '--text-dark': 'settingText',
    '--success': 'settingSuccess'
};

function hexToRgba(hex, alpha) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
}

function updateThemeColor(variable, value) {
    const root = document.documentElement;
    root.style.setProperty(variable, value);
    
    // Update derived variables
    if (variable === '--primary') {
        root.style.setProperty('--primary-glow', hexToRgba(value, 0.2));
        root.style.setProperty('--primary-glow-light', hexToRgba(value, 0.1));
        // Darken for hover states
        const r = Math.max(0, parseInt(value.slice(1, 3), 16) - 40);
        const g = Math.max(0, parseInt(value.slice(3, 5), 16) - 40);
        const b = Math.max(0, parseInt(value.slice(5, 7), 16) - 40);
        root.style.setProperty('--primary-dark', `#${r.toString(16).padStart(2,'0')}${g.toString(16).padStart(2,'0')}${b.toString(16).padStart(2,'0')}`);
    }
    if (variable === '--card-bg') {
        // Slightly darker alt background
        const r = Math.max(0, parseInt(value.slice(1, 3), 16) - 6);
        const g = Math.max(0, parseInt(value.slice(3, 5), 16) - 6);
        const b = Math.max(0, parseInt(value.slice(5, 7), 16) - 6);
        root.style.setProperty('--card-bg-alt', `#${r.toString(16).padStart(2,'0')}${g.toString(16).padStart(2,'0')}${b.toString(16).padStart(2,'0')}`);
    }
    if (variable === '--bg-dark') {
        // Darker variant for gradient
        const r = Math.max(0, parseInt(value.slice(1, 3), 16) - 26);
        const g = Math.max(0, parseInt(value.slice(3, 5), 16) - 26);
        const b = Math.max(0, parseInt(value.slice(5, 7), 16) - 26);
        root.style.setProperty('--bg-darker', `#${r.toString(16).padStart(2,'0')}${g.toString(16).padStart(2,'0')}${b.toString(16).padStart(2,'0')}`);
    }
    
    // Save to localStorage
    const saved = JSON.parse(localStorage.getItem('pawcapTheme') || '{}');
    saved[variable] = value;
    localStorage.setItem('pawcapTheme', JSON.stringify(saved));
}

function loadSavedTheme() {
    const saved = JSON.parse(localStorage.getItem('pawcapTheme') || '{}');
    for (const [variable, value] of Object.entries(saved)) {
        updateThemeColor(variable, value);
        // Set color picker to saved value
        const pickerId = themePickerMap[variable];
        if (pickerId) {
            const picker = document.getElementById(pickerId);
            if (picker) picker.value = value;
        }
    }
    renderThemeSelector();
}

function resetTheme() {
    localStorage.removeItem('pawcapTheme');
    localStorage.removeItem('pawcapThemePreset');
    const root = document.documentElement;
    // Clear all inline styles to revert to CSS defaults
    root.removeAttribute('style');
    // Reset color pickers
    for (const [variable, pickerId] of Object.entries(themePickerMap)) {
        const picker = document.getElementById(pickerId);
        if (picker) picker.value = themeDefaults[variable];
    }
    renderThemeSelector();
}

// Apply a preset or custom theme by name
function applyPresetTheme(name) {
    const customThemes = JSON.parse(localStorage.getItem('pawcapCustomThemes') || '{}');
    const theme = PRESET_THEMES[name] || customThemes[name];
    if (!theme) return;

    for (const [variable, value] of Object.entries(theme)) {
        updateThemeColor(variable, value);
        const pickerId = themePickerMap[variable];
        if (pickerId) {
            const picker = document.getElementById(pickerId);
            if (picker) picker.value = value;
        }
    }

    localStorage.setItem('pawcapThemePreset', name);
    renderThemeSelector();
}

// Save current color picker values as a named custom theme
function saveCustomTheme() {
    const name = prompt('Enter a name for your custom theme:');
    if (!name || !name.trim()) return;

    const trimmed = name.trim();
    const theme = {};
    for (const [variable, pickerId] of Object.entries(themePickerMap)) {
        const picker = document.getElementById(pickerId);
        if (picker) theme[variable] = picker.value;
    }

    const customThemes = JSON.parse(localStorage.getItem('pawcapCustomThemes') || '{}');
    customThemes[trimmed] = theme;
    localStorage.setItem('pawcapCustomThemes', JSON.stringify(customThemes));
    localStorage.setItem('pawcapThemePreset', trimmed);
    renderThemeSelector();
}

// Delete a custom theme
function deleteCustomTheme(name) {
    const customThemes = JSON.parse(localStorage.getItem('pawcapCustomThemes') || '{}');
    delete customThemes[name];
    localStorage.setItem('pawcapCustomThemes', JSON.stringify(customThemes));

    if (localStorage.getItem('pawcapThemePreset') === name) {
        applyPresetTheme('Redline');
    }
    renderThemeSelector();
}

// Build theme selector buttons dynamically
function renderThemeSelector() {
    const container = document.getElementById('themeSelectorContainer');
    if (!container) return;

    const activePreset = localStorage.getItem('pawcapThemePreset') || 'Redline';
    const customThemes = JSON.parse(localStorage.getItem('pawcapCustomThemes') || '{}');

    let html = '';

    // Built-in presets
    for (const [name, colors] of Object.entries(PRESET_THEMES)) {
        const isActive = (name === activePreset) ? ' active' : '';
        html += `<button class="theme-preset-btn${isActive}" onclick="applyPresetTheme('${name}')">
            <span class="theme-preview" style="background: ${colors['--bg-dark']}; border-color: ${colors['--primary']};">
                <span class="theme-dot" style="background: ${colors['--primary']};"></span>
                <span class="theme-dot" style="background: ${colors['--card-bg']};"></span>
                <span class="theme-dot" style="background: ${colors['--success']};"></span>
            </span>
            <span class="theme-name">${name}</span>
        </button>`;
    }

    // Custom themes
    for (const [name, colors] of Object.entries(customThemes)) {
        const isActive = (name === activePreset) ? ' active' : '';
        const safeName = name.replace(/'/g, "\\'");
        html += `<button class="theme-preset-btn${isActive}" onclick="applyPresetTheme('${safeName}')">
            <span class="theme-preview" style="background: ${colors['--bg-dark']}; border-color: ${colors['--primary']};">
                <span class="theme-dot" style="background: ${colors['--primary']};"></span>
                <span class="theme-dot" style="background: ${colors['--card-bg']};"></span>
                <span class="theme-dot" style="background: ${colors['--success']};"></span>
            </span>
            <span class="theme-name">${name}</span>
            <span class="theme-delete" onclick="event.stopPropagation(); deleteCustomTheme('${safeName}')">&times;</span>
        </button>`;
    }

    container.innerHTML = html;
}

// Feed toggle and polling
function toggleFeed(enabled) {
    feedEnabled = enabled;
    const feedSection = document.getElementById('feedSection');
    
    if (enabled) {
        feedSection.style.display = 'block';
        updateFeed();
        feedInterval = setInterval(updateFeed, 2000);
    } else {
        feedSection.style.display = 'none';
        if (feedInterval) {
            clearInterval(feedInterval);
            feedInterval = null;
        }
    }
}

async function updateFeed() {
    try {
        const response = await fetch(`${API_BASE}/api/activity`);
        if (!response.ok) return;
        
        const entries = await response.json();
        const feedList = document.getElementById('feedList');
        
        if (!entries || entries.length === 0) {
            feedList.innerHTML = '<p class="empty-state">No activity yet...</p>';
            return;
        }
        
        // Show last 50 entries
        const recent = entries.slice(-50);
        feedList.innerHTML = recent.map(entry => {
            const levelClass = entry.level || 'INFO';
            return `<div class="feed-entry ${levelClass}"><span class="feed-time">${entry.timestamp}</span> <span class="feed-level">[${entry.level}]</span> ${entry.message}</div>`;
        }).join('');
        
        // Auto-scroll to bottom
        feedList.scrollTop = feedList.scrollHeight;
        
    } catch (error) {
        console.error('Failed to update feed:', error);
    }
}

// Update blacklisted networks
async function updateBlacklist() {
    try {
        const response = await fetch(`${API_BASE}/api/blacklisted`);
        if (!response.ok) return;

        const networks = await response.json();
        const container = document.getElementById('blacklistList');
        const clearBtn = document.getElementById('clearBlacklistBtn');
        if (!container) return;

        if (!networks || networks.length === 0) {
            container.innerHTML = '<p class="empty-state">No blacklisted networks...</p>';
            if (clearBtn) clearBtn.style.display = 'none';
            return;
        }
        
        // Show clear button when there are blacklisted networks
        if (clearBtn) clearBtn.style.display = 'block';

        container.innerHTML = networks.map(net => {
            const reason = net.last_failure_reason || 'unknown';
            const failures = net.consecutive_failures || 0;
            const attempts = net.total_attempts || 0;
            const successes = net.total_successes || 0;

            const bands = (net.attempted_bands || []).join('+') || '?';
            const retraceTag = net.retrace_pending
                ? ' <span class="blacklist-retrace">5GHz retrace pending</span>'
                : '';

            return `
                <div class="blacklist-item">
                    <div class="blacklist-header">
                        <strong>${net.ssid}</strong>
                        <span class="blacklist-badge">${failures} fails</span>${retraceTag}
                    </div>
                    <small>${net.bssid} | Ch ${net.channel || '?'} | ${bands}GHz | ${net.encryption || '?'} | ${attempts} attempts, ${successes} captures | Last: ${reason}</small>
                </div>
            `;
        }).join('');
    } catch (error) {
        console.error('Failed to update blacklist:', error);
    }
}

// Clear blacklist
async function clearBlacklist() {
    if (!confirm('Clear all blacklisted networks? This will reset their failure counts.')) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/blacklist/clear`, {
            method: 'POST'
        });
        
        if (response.ok) {
            const result = await response.json();
            console.log(`Cleared ${result.cleared} blacklisted networks`);
            updateBlacklist();
        }
    } catch (error) {
        console.error('Failed to clear blacklist:', error);
    }
}

// Update whitelist (protected networks)
async function updateWhitelist() {
    try {
        const response = await fetch(`${API_BASE}/api/whitelist`);
        if (!response.ok) return;

        const ssids = await response.json();
        const container = document.getElementById('whitelist');
        if (!container) return;

        const settingsOpen = document.getElementById('settingsToggle')?.checked;

        if (!ssids || ssids.length === 0) {
            container.innerHTML = settingsOpen
                ? '<p class="empty-state">No protected networks. Add one below.</p>'
                : '<p class="empty-state">No protected networks configured.</p>';
        } else {
            container.innerHTML = ssids.map(ssid => {
                const removeBtn = settingsOpen
                    ? `<span class="whitelist-remove" onclick="removeWhitelist('${ssid.replace(/'/g, "\\'")}')">&times;</span>`
                    : '';
                return `<span class="badge">${ssid}${removeBtn}</span>`;
            }).join('');
        }

        // Show/hide the add form based on settings toggle
        const addForm = document.getElementById('whitelistAddForm');
        if (addForm) addForm.style.display = settingsOpen ? 'flex' : 'none';
    } catch (error) {
        console.error('Failed to update whitelist:', error);
    }
}

async function addWhitelist() {
    const input = document.getElementById('whitelistInput');
    const ssid = (input.value || '').trim();
    if (!ssid) return;

    try {
        const response = await fetch(`${API_BASE}/api/whitelist`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ssid })
        });
        if (response.ok) {
            input.value = '';
            updateWhitelist();
        } else {
            const result = await response.json();
            alert(result.message || 'Failed to add network.');
        }
    } catch (error) {
        console.error('Failed to add whitelist entry:', error);
    }
}

async function removeWhitelist(ssid) {
    // Remove immediately from the DOM for instant feedback
    const container = document.getElementById('whitelist');
    if (container) {
        container.querySelectorAll('.badge').forEach(el => {
            if (el.textContent.replace('×', '').trim() === ssid) el.remove();
        });
    }

    try {
        const response = await fetch(`${API_BASE}/api/whitelist`, {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ssid })
        });
        if (!response.ok) {
            updateWhitelist(); // Revert visual on failure
        }
    } catch (error) {
        console.error('Failed to remove whitelist entry:', error);
        updateWhitelist(); // Revert visual on error
    }
}

// Handle page visibility changes
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        clearInterval(updateInterval);
        if (feedInterval) clearInterval(feedInterval);
    } else {
        startAutoUpdate();
        if (feedEnabled) {
            feedInterval = setInterval(updateFeed, 2000);
        }
    }
});
