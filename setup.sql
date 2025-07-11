-- Cyber Security Database Setup
-- Create database and tables for threat detection system

-- Create database
CREATE DATABASE IF NOT EXISTS cyber_security;
USE cyber_security;

-- Create threats table
CREATE TABLE IF NOT EXISTS threats (
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
    INDEX idx_detected_at (detected_at),
    INDEX idx_status (status)
);

-- Create threat logs table
CREATE TABLE IF NOT EXISTS threat_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    threat_id INT,
    action_taken VARCHAR(255),
    admin_user VARCHAR(100),
    log_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (threat_id) REFERENCES threats(id) ON DELETE CASCADE,
    INDEX idx_threat_id (threat_id),
    INDEX idx_log_time (log_time)
);

-- Create security metrics table
CREATE TABLE IF NOT EXISTS security_metrics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    metric_name VARCHAR(100) NOT NULL,
    metric_value INT DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    UNIQUE KEY unique_metric (metric_name),
    INDEX idx_metric_name (metric_name)
);

-- Create network monitoring table
CREATE TABLE IF NOT EXISTS network_monitoring (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    request_count INT DEFAULT 1,
    last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_blocked BOOLEAN DEFAULT FALSE,
    threat_level ENUM('low', 'medium', 'high') DEFAULT 'low',
    country_code VARCHAR(2),
    
    UNIQUE KEY unique_ip (ip_address),
    INDEX idx_ip_address (ip_address),
    INDEX idx_threat_level (threat_level),
    INDEX idx_blocked (is_blocked)
);

-- Create firewall rules table
CREATE TABLE IF NOT EXISTS firewall_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    rule_name VARCHAR(100) NOT NULL,
    rule_type ENUM('allow', 'deny', 'monitor') NOT NULL,
    source_ip VARCHAR(45),
    destination_port INT,
    protocol ENUM('tcp', 'udp', 'icmp', 'all') DEFAULT 'all',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_rule_type (rule_type),
    INDEX idx_active (is_active),
    INDEX idx_source_ip (source_ip)
);

-- Create system alerts table
CREATE TABLE IF NOT EXISTS system_alerts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    alert_type VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    severity ENUM('info', 'warning', 'critical') NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    acknowledged_by VARCHAR(100),
    acknowledged_at TIMESTAMP NULL,
    
    INDEX idx_alert_type (alert_type),
    INDEX idx_severity (severity),
    INDEX idx_read (is_read),
    INDEX idx_created (created_at)
);

-- Insert initial security metrics
INSERT INTO security_metrics (metric_name, metric_value) VALUES
('total_scans', 0),
('threats_detected', 0),
('threats_blocked', 0),
('malware_detected', 0),
('phishing_attempts', 0),
('ddos_attempts', 0),
('sql_injection_attempts', 0),
('xss_attempts', 0),
('brute_force_attempts', 0),
('port_scan_attempts', 0),
('suspicious_ips', 0),
('failed_logins', 0),
('successful_blocks', 0),
('quarantined_files', 0),
('system_uptime_hours', 0)
ON DUPLICATE KEY UPDATE metric_name = metric_name;

-- Insert sample firewall rules
INSERT INTO firewall_rules (rule_name, rule_type, destination_port, protocol) VALUES
('Block SSH Brute Force', 'deny', 22, 'tcp'),
('Monitor HTTP Traffic', 'monitor', 80, 'tcp'),
('Monitor HTTPS Traffic', 'monitor', 443, 'tcp'),
('Block FTP Access', 'deny', 21, 'tcp'),
('Allow DNS Queries', 'allow', 53, 'udp'),
('Block Telnet', 'deny', 23, 'tcp'),
('Monitor Database Access', 'monitor', 3306, 'tcp'),
('Block SMTP Relay', 'deny', 25, 'tcp')
ON DUPLICATE KEY UPDATE rule_name = rule_name;

-- Insert sample threat data for demonstration
INSERT INTO threats (threat_type, description, severity, ip_address) VALUES
('Malware', 'Suspicious executable file detected in downloads folder', 'high', '192.168.1.100'),
('Phishing', 'Email with suspicious links blocked by spam filter', 'medium', '203.0.113.45'),
('Port Scan', 'Unauthorized port scanning detected from external IP', 'low', '198.51.100.23'),
('SQL Injection', 'SQL injection attempt detected on login form', 'medium', '203.0.113.67'),
('DDoS', 'Distributed denial of service attack in progress', 'high', '198.51.100.89'),
('Brute Force', 'Multiple failed SSH login attempts detected', 'high', '203.0.113.12'),
('XSS', 'Cross-site scripting attempt blocked', 'medium', '192.168.1.200'),
('Malware', 'Trojan horse detected in email attachment', 'high', '198.51.100.156');

-- Insert corresponding threat logs
INSERT INTO threat_logs (threat_id, action_taken, admin_user) VALUES
(1, 'File quarantined and user notified', 'system'),
(2, 'Email moved to spam folder', 'system'),
(3, 'IP address added to monitoring list', 'admin'),
(4, 'Request blocked and logged', 'system'),
(5, 'Traffic filtered and rate limited', 'system'),
(6, 'IP temporarily blocked', 'system'),
(7, 'Script execution prevented', 'system'),
(8, 'Attachment removed and sender blocked', 'system');

-- Update metrics based on sample data
UPDATE security_metrics SET metric_value = 3 WHERE metric_name = 'malware_detected';
UPDATE security_metrics SET metric_value = 1 WHERE metric_name = 'phishing_attempts';
UPDATE security_metrics SET metric_value = 1 WHERE metric_name = 'ddos_attempts';
UPDATE security_metrics SET metric_value = 1 WHERE metric_name = 'sql_injection_attempts';
UPDATE security_metrics SET metric_value = 1 WHERE metric_name = 'xss_attempts';
UPDATE security_metrics SET metric_value = 1 WHERE metric_name = 'brute_force_attempts';
UPDATE security_metrics SET metric_value = 1 WHERE metric_name = 'port_scan_attempts';
UPDATE security_metrics SET metric_value = 8 WHERE metric_name = 'threats_detected';
UPDATE security_metrics SET metric_value = 8 WHERE metric_name = 'threats_blocked';

-- Create stored procedures for common operations

DELIMITER //

-- Procedure to get threat summary
CREATE PROCEDURE GetThreatSummary()
BEGIN
    SELECT 
        threat_type,
        COUNT(*) as total_count,
        SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) as high_severity,
        SUM(CASE WHEN severity = 'medium' THEN 1 ELSE 0 END) as medium_severity,
        SUM(CASE WHEN severity = 'low' THEN 1 ELSE 0 END) as low_severity,
        MAX(detected_at) as latest_detection
    FROM threats 
    GROUP BY threat_type
    ORDER BY total_count DESC;
END //

-- Procedure to get recent activity
CREATE PROCEDURE GetRecentActivity(IN hours_back INT)
BEGIN
    SELECT 
        t.threat_type,
        t.description,
        t.severity,
        t.ip_address,
        t.detected_at,
        tl.action_taken
    FROM threats t
    LEFT JOIN threat_logs tl ON t.id = tl.threat_id
    WHERE t.detected_at >= DATE_SUB(NOW(), INTERVAL hours_back HOUR)
    ORDER BY t.detected_at DESC;
END //

-- Procedure to block IP address
CREATE PROCEDURE BlockIPAddress(IN ip_addr VARCHAR(45), IN reason TEXT)
BEGIN
    DECLARE ip_exists INT DEFAULT 0;
    
    SELECT COUNT(*) INTO ip_exists FROM network_monitoring WHERE ip_address = ip_addr;
    
    IF ip_exists > 0 THEN
        UPDATE network_monitoring 
        SET is_blocked = TRUE, threat_level = 'high'
        WHERE ip_address = ip_addr;
    ELSE
        INSERT INTO network_monitoring (ip_address, is_blocked, threat_level)
        VALUES (ip_addr, TRUE, 'high');
    END IF;
    
    INSERT INTO system_alerts (alert_type, message, severity)
    VALUES ('IP_BLOCKED', CONCAT('IP address ', ip_addr, ' has been blocked. Reason: ', reason), 'warning');
END //

-- Procedure to clean old data
CREATE PROCEDURE CleanOldData(IN days_to_keep INT)
BEGIN
    DECLARE deleted_threats INT DEFAULT 0;
    DECLARE deleted_logs INT DEFAULT 0;
    
    DELETE FROM threats WHERE detected_at < DATE_SUB(NOW(), INTERVAL days_to_keep DAY);
    SET deleted_threats = ROW_COUNT();
    
    DELETE FROM system_alerts WHERE created_at < DATE_SUB(NOW(), INTERVAL days_to_keep DAY) AND is_read = TRUE;
    SET deleted_logs = ROW_COUNT();
    
    INSERT INTO system_alerts (alert_type, message, severity)
    VALUES ('CLEANUP_COMPLETED', 
            CONCAT('Cleanup completed. Deleted ', deleted_threats, ' old threats and ', deleted_logs, ' old alerts.'), 
            'info');
END //

DELIMITER ;

-- Create views for easy data access

-- View for active threats
CREATE VIEW active_threats AS
SELECT 
    id,
    threat_type,
    description,
    severity,
    ip_address,
    detected_at,
    TIMESTAMPDIFF(MINUTE, detected_at, NOW()) as minutes_ago
FROM threats 
WHERE status = 'active'
ORDER BY detected_at DESC;

-- View for threat statistics
CREATE VIEW threat_statistics AS
SELECT 
    DATE(detected_at) as detection_date,
    threat_type,
    severity,
    COUNT(*) as count
FROM threats
WHERE detected_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
GROUP BY DATE(detected_at), threat_type, severity
ORDER BY detection_date DESC, count DESC;

-- View for blocked IPs
CREATE VIEW blocked_ips AS
SELECT 
    ip_address,
    request_count,
    threat_level,
    last_request,
    TIMESTAMPDIFF(HOUR, last_request, NOW()) as hours_since_last_request
FROM network_monitoring
WHERE is_blocked = TRUE
ORDER BY last_request DESC;

-- Create triggers for automatic metric updates

DELIMITER //

CREATE TRIGGER update_metrics_after_threat
AFTER INSERT ON threats
FOR EACH ROW
BEGIN
    UPDATE security_metrics SET metric_value = metric_value + 1 WHERE metric_name = 'threats_detected';
    
    CASE NEW.threat_type
        WHEN 'Malware' THEN
            UPDATE security_metrics SET metric_value = metric_value + 1 WHERE metric_name = 'malware_detected';
        WHEN 'Phishing' THEN
            UPDATE security_metrics SET metric_value = metric_value + 1 WHERE metric_name = 'phishing_attempts';
        WHEN 'DDoS' THEN
            UPDATE security_metrics SET metric_value = metric_value + 1 WHERE metric_name = 'ddos_attempts';
        WHEN 'SQL Injection' THEN
            UPDATE security_metrics SET metric_value = metric_value + 1 WHERE metric_name = 'sql_injection_attempts';
        WHEN 'XSS' THEN
            UPDATE security_metrics SET metric_value = metric_value + 1 WHERE metric_name = 'xss_attempts';
        WHEN 'Brute Force' THEN
            UPDATE security_metrics SET metric_value = metric_value + 1 WHERE metric_name = 'brute_force_attempts';
        WHEN 'Port Scan' THEN
            UPDATE security_metrics SET metric_value = metric_value + 1 WHERE metric_name = 'port_scan_attempts';
        ELSE BEGIN END;
    END CASE;
END //

DELIMITER ;

-- Grant permissions (adjust as needed for your setup)
-- CREATE USER 'cyber_security_user'@'localhost' IDENTIFIED BY 'secure_password_here';
-- GRANT SELECT, INSERT, UPDATE, DELETE ON cyber_security.* TO 'cyber_security_user'@'localhost';
-- FLUSH PRIVILEGES;

-- Display setup completion message
SELECT 'Cyber Security Database Setup Complete!' as message;
SELECT COUNT(*) as sample_threats_inserted FROM threats;
SELECT COUNT(*) as firewall_rules_created FROM firewall_rules;
SELECT COUNT(*) as metrics_initialized FROM security_metrics;