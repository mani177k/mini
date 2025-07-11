 class ThreatDetector {
            constructor() {
                this.scanning = false;
                this.threats = [];
                this.metrics = {
                    filesScanned: 0,
                    activeConnections: Math.floor(Math.random() * 50) + 10,
                    blockedAttempts: 0,
                    bandwidth: 0,
                    suspiciousIPs: 0,
                    ddosAttempts: 0,
                    portScans: 0,
                    failedLogins: 0,
                    bruteForce: 0,
                    sqlInjection: 0,
                    xssAttempts: 0
                };
                this.init();
            }

            init() {
                this.updateLastScan();
                this.startMonitoring();
                this.simulateNetworkActivity();
            }

            updateLastScan() {
                const now = new Date();
                document.getElementById('lastScan').textContent = now.toLocaleTimeString();
            }

            startFullScan() {
                if (this.scanning) return;
                
                this.scanning = true;
                const scanBtn = document.getElementById('scanBtn');
                scanBtn.innerHTML = '<div class="loading"></div> Scanning...';
                
                this.updateStatus('systemStatus', 'warning', 'Scanning in Progress...');
                
                // Simulate scanning process
                let progress = 0;
                const scanInterval = setInterval(() => {
                    progress += Math.random() * 20;
                    this.metrics.filesScanned = Math.floor(progress * 10);
                    document.getElementById('filesScanned').textContent = this.metrics.filesScanned;
                    
                    if (progress >= 100) {
                        clearInterval(scanInterval);
                        this.completeScan();
                    }
                }, 500);
            }

            completeScan() {
                this.scanning = false;
                document.getElementById('scanBtn').innerHTML = '🔍 Start Full Scan';
                this.updateStatus('systemStatus', 'safe', 'Scan Complete - System Secure');
                this.updateLastScan();
                
                // Randomly generate some threats
                if (Math.random() > 0.7) {
                    this.generateRandomThreat();
                }
            }

            generateRandomThreat() {
                const threatTypes = [
                    { type: 'Malware', desc: 'Suspicious file detected', severity: 'high' },
                    { type: 'Phishing', desc: 'Phishing attempt blocked', severity: 'medium' },
                    { type: 'Port Scan', desc: 'Unauthorized port scanning detected', severity: 'low' },
                    { type: 'DDoS', desc: 'Distributed denial of service attempt', severity: 'high' },
                    { type: 'SQL Injection', desc: 'SQL injection attempt detected', severity: 'medium' },
                    { type: 'XSS Attack', desc: 'Cross-site scripting attempt blocked', severity: 'medium' },
                    { type: 'Brute Force', desc: 'Brute force login attempt detected', severity: 'high' }
                ];

                const threat = threatTypes[Math.floor(Math.random() * threatTypes.length)];
                this.logThreat(threat.type, threat.desc, threat.severity);
                this.updateMetrics(threat.type);
            }

            logThreat(type, description, severity) {
                const logEntry = document.createElement('div');
                logEntry.className = `log-entry ${severity}`;
                logEntry.innerHTML = `
                    <div class="threat-type">${type}</div>
                    <div>${description}</div>
                    <div class="log-time">${new Date().toLocaleString()}</div>
                `;

                const threatLog = document.getElementById('threatLog');
                if (threatLog.children.length === 1 && threatLog.children[0].tagName === 'P') {
                    threatLog.innerHTML = '';
                }
                
                threatLog.insertBefore(logEntry, threatLog.firstChild);
                
                // Keep only last 10 entries
                while (threatLog.children.length > 10) {
                    threatLog.removeChild(threatLog.lastChild);
                }

                // Update status indicators
                this.updateThreatStatus(type, severity);
            }

            updateThreatStatus(type, severity) {
                if (type === 'Malware') {
                    this.updateStatus('malwareStatus', severity === 'high' ? 'danger' : 'warning', 
                                    severity === 'high' ? 'Malware Detected!' : 'Potential Threat');
                } else if (type.includes('Network') || type === 'DDoS' || type === 'Port Scan') {
                    this.updateStatus('networkStatus', severity === 'high' ? 'danger' : 'warning', 
                                    severity === 'high' ? 'Network Under Attack' : 'Suspicious Activity');
                }
            }

            updateStatus(elementId, status, text) {
                const dot = document.getElementById(elementId);
                const textElement = document.getElementById(elementId.replace('Status', 'StatusText'));
                
                dot.className = `status-dot status-${status}`;
                textElement.textContent = text;
            }

            updateMetrics(threatType) {
                switch(threatType) {
                    case 'DDoS':
                        this.metrics.ddosAttempts++;
                        document.getElementById('ddosAttempts').textContent = this.metrics.ddosAttempts;
                        break;
                    case 'Port Scan':
                        this.metrics.portScans++;
                        document.getElementById('portScans').textContent = this.metrics.portScans;
                        break;
                    case 'Brute Force':
                        this.metrics.bruteForce++;
                        this.metrics.failedLogins += Math.floor(Math.random() * 5) + 1;
                        document.getElementById('bruteForce').textContent = this.metrics.bruteForce;
                        document.getElementById('failedLogins').textContent = this.metrics.failedLogins;
                        break;
                    case 'SQL Injection':
                        this.metrics.sqlInjection++;
                        document.getElementById('sqlInjection').textContent = this.metrics.sqlInjection;
                        break;
                    case 'XSS Attack':
                        this.metrics.xssAttempts++;
                        document.getElementById('xssAttempts').textContent = this.metrics.xssAttempts;
                        break;
                }
                
                this.metrics.blockedAttempts++;
                document.getElementById('blockedAttempts').textContent = this.metrics.blockedAttempts;
            }

            simulateNetworkActivity() {
                setInterval(() => {
                    // Simulate bandwidth usage
                    this.metrics.bandwidth = (Math.random() * 100).toFixed(1);
                    document.getElementById('bandwidth').textContent = this.metrics.bandwidth + ' MB/s';
                    
                    // Occasionally add suspicious IPs
                    if (Math.random() > 0.9) {
                        this.metrics.suspiciousIPs++;
                        document.getElementById('suspiciousIPs').textContent = this.metrics.suspiciousIPs;
                    }
                    
                    // Update active connections
                    this.metrics.activeConnections += Math.floor(Math.random() * 6) - 3;
                    this.metrics.activeConnections = Math.max(1, this.metrics.activeConnections);
                    document.getElementById('activeConnections').textContent = this.metrics.activeConnections;
                }, 3000);
            }

            startMonitoring() {
                // Simulate random threat detection
                setInterval(() => {
                    if (Math.random() > 0.85 && !this.scanning) {
                        this.generateRandomThreat();
                    }
                }, 10000);
            }

            updateThreats() {
                alert('Threat database updated successfully!\n\nNew signatures: 1,247\nUpdated rules: 89\nLast update: ' + new Date().toLocaleString());
            }

            generateReport() {
                const report = `
CYBERSECURITY THREAT REPORT
Generated: ${new Date().toLocaleString()}

SYSTEM STATUS:
- Files Scanned: ${this.metrics.filesScanned}
- Active Connections: ${this.metrics.activeConnections}
- Blocked Attempts: ${this.metrics.blockedAttempts}

THREAT METRICS:
- DDoS Attempts: ${this.metrics.ddosAttempts}
- Port Scans: ${this.metrics.portScans}
- Brute Force Attempts: ${this.metrics.bruteForce}
- Failed Logins: ${this.metrics.failedLogins}
- SQL Injection Attempts: ${this.metrics.sqlInjection}
- XSS Attempts: ${this.metrics.xssAttempts}

NETWORK SECURITY:
- Current Bandwidth: ${this.metrics.bandwidth} MB/s
- Suspicious IPs: ${this.metrics.suspiciousIPs}

RECOMMENDATIONS:
- Regular system updates recommended
- Monitor suspicious IP addresses
- Implement stronger authentication methods
- Enable advanced threat protection
                `;
                
                alert(report);
            }

            clearLogs() {
                document.getElementById('threatLog').innerHTML = 
                    '<p style="color: #888; text-align: center;">No threats detected. System is secure.</p>';
                
                // Reset some metrics
                this.metrics.suspiciousIPs = 0;
                this.metrics.ddosAttempts = 0;
                this.metrics.portScans = 0;
                this.metrics.bruteForce = 0;
                this.metrics.sqlInjection = 0;
                this.metrics.xssAttempts = 0;
                
                // Update display
                document.getElementById('suspiciousIPs').textContent = '0';
                document.getElementById('ddosAttempts').textContent = '0';
                document.getElementById('portScans').textContent = '0';
                document.getElementById('bruteForce').textContent = '0';
                document.getElementById('sqlInjection').textContent = '0';
                document.getElementById('xssAttempts').textContent = '0';
                
                // Reset status indicators
                this.updateStatus('malwareStatus', 'safe', 'No Threats Detected');
                this.updateStatus('networkStatus', 'safe', 'Network Secure');
            }
        }

        // Initialize the threat detector
        const detector = new ThreatDetector();

        // Global functions for buttons
        function startFullScan() {
            detector.startFullScan();
        }

        function updateThreats() {
            detector.updateThreats();
        }

        function generateReport() {
            detector.generateReport();
        }

        function clearLogs() {
            detector.clearLogs();
        }

        // Simulate receiving threat data from backend
        function fetchThreatsFromBackend() {
            // This would typically make an AJAX call to your PHP backend
            fetch('threat_detector.php?action=getThreats')
                .then(response => response.json())
                .then(data => {
                    if (data.threats) {
                        data.threats.forEach(threat => {
                            detector.logThreat(threat.type, threat.description, threat.severity);
                        });
                    }
                })
                .catch(error => console.log('Backend connection not available'));
        }

        // Check for new threats every 30 seconds
        setInterval(fetchThreatsFromBackend, 30000);