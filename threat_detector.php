<?php
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

// Database configuration
class Database {
    private $host = 'localhost';
    private $db_name = 'cyber_security';
    private $username = 'root';
    private $password = '';
    private $conn;

    public function connect() {
        $this->conn = null;
        try {
            $this->conn = new PDO("mysql:host=" . $this->host . ";dbname=" . $this->db_name, 
                                 $this->username, $this->password);
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch(PDOException $e) {
            echo "Connection error: " . $e->getMessage();
        }
        return $this->conn;
    }
}

// Threat Detection Class
class ThreatDetector {
    private $conn;
    private $threats_table = 'threats';
    private $logs_table = 'threat_logs';
    private $metrics_table = 'security_metrics';

    public function __construct($db) {
        $this->conn = $db;
        $this->createTables();
    }

    // Create necessary database tables
    private function createTables() {
        // Threats table
        $threats_sql = "CREATE TABLE IF NOT EXISTS {$this->threats_table} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            threat_type VARCHAR(100) NOT NULL,
            description TEXT NOT NULL,
            severity ENUM('low', 'medium', 'high') NOT NULL,
            ip_address VARCHAR(45),
            user_agent TEXT,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status ENUM('active', 'resolved', 'false_positive') DEFAULT 'active',
            INDEX idx_threat_type (threat_type),
            INDEX idx_severity (severity),
            INDEX idx_detected_at (detected_at)
        )";

        // Threat logs table
        $logs_sql = "CREATE TABLE IF NOT EXISTS {$this->logs_table} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            threat_id INT,
            action_taken VARCHAR(255),
            admin_user VARCHAR(100),
            log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (threat_id) REFERENCES {$this->threats_table}(id) ON DELETE CASCADE
        )";

        // Security metrics table
        $metrics_sql = "CREATE TABLE IF NOT EXISTS {$this->metrics_table} (
            id INT AUTO_INCREMENT PRIMARY KEY,
            metric_name VARCHAR(100) NOT NULL,
            metric_value INT DEFAULT 0,
            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY unique_metric (metric_name)
        )";

        try {
            $this->conn->exec($threats_sql);
            $this->conn->exec($logs_sql);
            $this->conn->exec($metrics_sql);
            $this->initializeMetrics();
        } catch(PDOException $e) {
            error_log("Table creation error: " . $e->getMessage());
        }
    }

    // Initialize default metrics
    private function initializeMetrics() {
        $default_metrics = [
            'total_scans' => 0,
            'threats_detected' => 0,
            'threats_blocked' => 0,
            'malware_detected' => 0,
            'phishing_attempts' => 0,
            'ddos_attempts' => 0,
            'sql_injection_attempts' => 0,
            'xss_attempts' => 0,
            'brute_force_attempts' => 0,
            'port_scan_attempts' => 0,
            'suspicious_ips' => 0,
            'failed_logins' => 0
        ];

        foreach ($default_metrics as $metric => $value) {
            $sql = "INSERT IGNORE INTO {$this->metrics_table} (metric_name, metric_value) VALUES (?, ?)";
            $stmt = $this->conn->prepare($sql);
            $stmt->execute([$metric, $value]);
        }
    }

    // Log a new threat
    public function logThreat($threat_type, $description, $severity, $ip_address = null, $user_agent = null) {
        $sql = "INSERT INTO {$this->threats_table} (threat_type, description, severity, ip_address, user_agent) 
                VALUES (?, ?, ?, ?, ?)";
        
        try {
            $stmt = $this->conn->prepare($sql);
            $result = $stmt->execute([$threat_type, $description, $severity, $ip_address, $user_agent]);
            
            if ($result) {
                $threat_id = $this->conn->lastInsertId();
                $this->updateMetrics($threat_type);
                $this->logAction($threat_id, "Threat detected and logged", "system");
                return $threat_id;
            }
        } catch(PDOException $e) {
            error_log("Error logging threat: " . $e->getMessage());
        }
        return false;
    }

    // Update security metrics
    private function updateMetrics($threat_type) {
        $metrics_to_update = ['threats_detected', 'threats_blocked'];
        
        // Map threat types to specific metrics
        $threat_metrics = [
            'malware' => 'malware_detected',
            'phishing' => 'phishing_attempts',
            'ddos' => 'ddos_attempts',
            'sql_injection' => 'sql_injection_attempts',
            'xss' => 'xss_attempts',
            'brute_force' => 'brute_force_attempts',
            'port_scan' => 'port_scan_attempts'
        ];

        $threat_type_lower = strtolower(str_replace(' ', '_', $threat_type));
        if (isset($threat_metrics[$threat_type_lower])) {
            $metrics_to_update[] = $threat_metrics[$threat_type_lower];
        }

        foreach ($metrics_to_update as $metric) {
            $sql = "UPDATE {$this->metrics_table} SET metric_value = metric_value + 1 WHERE metric_name = ?";
            $stmt = $this->conn->prepare($sql);
            $stmt->execute([$metric]);
        }
    }

    // Log an action
    public function logAction($threat_id, $action, $admin_user) {
        $sql = "INSERT INTO {$this->logs_table} (threat_id, action_taken, admin_user) VALUES (?, ?, ?)";
        try {
            $stmt = $this->conn->prepare($sql);
            return $stmt->execute([$threat_id, $action, $admin_user]);
        } catch(PDOException $e) {
            error_log("Error logging action: " . $e->getMessage());
        }
        return false;
    }

    // Get recent threats
    public function getRecentThreats($limit = 10) {
        $sql = "SELECT * FROM {$this->threats_table} 
                ORDER BY detected_at DESC 
                LIMIT ?";
        
        try {
            $stmt = $this->conn->prepare($sql);
            $stmt->bindValue(1, $limit, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch(PDOException $e) {
            error_log("Error fetching threats: " . $e->getMessage());
        }
        return [];
    }

    // Get threat statistics
    public function getThreatStats() {
        $stats = [];
        
        // Get total threats by severity
        $sql = "SELECT severity, COUNT(*) as count FROM {$this->threats_table} GROUP BY severity";
        try {
            $stmt = $this->conn->query($sql);
            $severity_stats = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($severity_stats as $stat) {
                $stats[$stat['severity'] . '_threats'] = $stat['count'];
            }
        } catch(PDOException $e) {
            error_log("Error fetching severity stats: " . $e->getMessage());
        }

        // Get threats by type
        $sql = "SELECT threat_type, COUNT(*) as count FROM {$this->threats_table} 
                GROUP BY threat_type ORDER BY count DESC LIMIT 5";
        try {
            $stmt = $this->conn->query($sql);
            $stats['top_threats'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        } catch(PDOException $e) {
            error_log("Error fetching threat type stats: " . $e->getMessage());
        }

        // Get metrics
        $sql = "SELECT metric_name, metric_value FROM {$this->metrics_table}";
        try {
            $stmt = $this->conn->query($sql);
            $metrics = $stmt->fetchAll(PDO::FETCH_ASSOC);
            foreach ($metrics as $metric) {
                $stats[$metric['metric_name']] = $metric['metric_value'];
            }
        } catch(PDOException $e) {
            error_log("Error fetching metrics: " . $e->getMessage());
        }

        return $stats;
    }

    // Simulate threat detection (for demo purposes)
    public function simulateThreats() {
        $sample_threats = [
            ['type' => 'Malware', 'desc' => 'Trojan.Generic detected in system32', 'severity' => 'high'],
            ['type' => 'Phishing', 'desc' => 'Suspicious email with malicious link blocked', 'severity' => 'medium'],
            ['type' => 'DDoS', 'desc' => 'Distributed denial of service attack detected', 'severity' => 'high'],
            ['type' => 'SQL Injection', 'desc' => 'SQL injection attempt on login form', 'severity' => 'medium'],
            ['type' => 'XSS', 'desc' => 'Cross-site scripting attempt blocked', 'severity' => 'medium'],
            ['type' => 'Brute Force', 'desc' => 'Multiple failed login attempts detected', 'severity' => 'high'],
            ['type' => 'Port Scan', 'desc' => 'Unauthorized port scanning activity', 'severity' => 'low'],
            ['type' => 'Malware', 'desc' => 'Suspicious executable file quarantined', 'severity' => 'medium'],
        ];

        $threats_added = [];
        $num_threats = rand(1, 3);
        
        for ($i = 0; $i < $num_threats; $i++) {
            $threat = $sample_threats[array_rand($sample_threats)];
            $ip = $this->generateRandomIP();
            $user_agent = $this->generateRandomUserAgent();
            
            $threat_id = $this->logThreat($threat['type'], $threat['desc'], $threat['severity'], $ip, $user_agent);
            if ($threat_id) {
                $threats_added[] = [
                    'id' => $threat_id,
                    'type' => $threat['type'],
                    'description' => $threat['desc'],
                    'severity' => $threat['severity'],
                    'ip_address' => $ip,
                    'detected_at' => date('Y-m-d H:i:s')
                ];
            }
        }
        
        return $threats_added;
    }

    // Generate random IP for simulation
    private function generateRandomIP() {
        return rand(1, 255) . '.' . rand(1, 255) . '.' . rand(1, 255) . '.' . rand(1, 255);
    }

    // Generate random user agent for simulation
    private function generateRandomUserAgent() {
        $user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'curl/7.68.0',
            'python-requests/2.25.1',
            'Wget/1.20.3'
        ];
        return $user_agents[array_rand($user_agents)];
    }

    // Network monitoring simulation
    public function getNetworkStats() {
        return [
            'active_connections' => rand(15, 50),
            'bandwidth_usage' => round(rand(10, 1000) / 10, 1),
            'blocked_ips' => rand(0, 25),
            'firewall_blocks' => rand(50, 500),
            'intrusion_attempts' => rand(0, 10)
        ];
    }

    // System health check
    public function performHealthCheck() {
        $health = [
            'database_status' => 'healthy',
            'last_update' => date('Y-m-d H:i:s'),
            'total_threats' => 0,
            'system_load' => rand(10, 80),
            'memory_usage' => rand(30, 90),
            'disk_usage' => rand(40, 85)
        ];

        try {
            $sql = "SELECT COUNT(*) as total FROM {$this->threats_table}";
            $stmt = $this->conn->query($sql);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            $health['total_threats'] = $result['total'];
        } catch(PDOException $e) {
            $health['database_status'] = 'error';
            error_log("Health check error: " . $e->getMessage());
        }

        return $health;
    }

    // Clean old threat data
    public function cleanOldThreats($days = 30) {
        $sql = "DELETE FROM {$this->threats_table} WHERE detected_at < DATE_SUB(NOW(), INTERVAL ? DAY)";
        try {
            $stmt = $this->conn->prepare($sql);
            $stmt->execute([$days]);
            return $stmt->rowCount();
        } catch(PDOException $e) {
            error_log("Error cleaning old threats: " . $e->getMessage());
        }
        return 0;
    }
}

// API Handler
try {
    $database = new Database();
    $db = $database->connect();
    $detector = new ThreatDetector($db);

    $action = $_GET['action'] ?? '';
    
    switch($action) {
        case 'getThreats':
            $limit = $_GET['limit'] ?? 10;
            $threats = $detector->getRecentThreats($limit);
            echo json_encode(['success' => true, 'threats' => $threats]);
            break;

        case 'getStats':
            $stats = $detector->getThreatStats();
            echo json_encode(['success' => true, 'stats' => $stats]);
            break;

        case 'simulateThreats':
            $threats = $detector->simulateThreats();
            echo json_encode(['success' => true, 'new_threats' => $threats]);
            break;

        case 'getNetworkStats':
            $network_stats = $detector->getNetworkStats();
            echo json_encode(['success' => true, 'network' => $network_stats]);
            break;

        case 'healthCheck':
            $health = $detector->performHealthCheck();
            echo json_encode(['success' => true, 'health' => $health]);
            break;

        case 'logThreat':
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $input = json_decode(file_get_contents('php://input'), true);
                $threat_id = $detector->logThreat(
                    $input['type'] ?? 'Unknown',
                    $input['description'] ?? 'No description',
                    $input['severity'] ?? 'medium',
                    $_SERVER['REMOTE_ADDR'] ?? null,
                    $_SERVER['HTTP_USER_AGENT'] ?? null
                );
                echo json_encode(['success' => $threat_id !== false, 'threat_id' => $threat_id]);
            } else {
                echo json_encode(['success' => false, 'error' => 'POST method required']);
            }
            break;

        case 'cleanOld':
            $days = $_GET['days'] ?? 30;
            $cleaned = $detector->cleanOldThreats($days);
            echo json_encode(['success' => true, 'cleaned_records' => $cleaned]);
            break;

        default:
            // Default response with system status
            $health = $detector->performHealthCheck();
            $stats = $detector->getThreatStats();
            $network = $detector->getNetworkStats();
            
            echo json_encode([
                'success' => true,
                'message' => 'Cyber Security API is running',
                'timestamp' => date('Y-m-d H:i:s'),
                'health' => $health,
                'stats' => $stats,
                'network' => $network
            ]);
            break;
    }

} catch(Exception $e) {
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => 'Internal server error',
        'message' => $e->getMessage()
    ]);
}
?>