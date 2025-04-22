/// Enhanced logging module for network responses
pub struct EnhancedLogger {
    buffer: MemoryLogBuffer,
    enable_packet_capture: bool,
    packet_log: Arc<Mutex<Vec<PacketLog>>>,
    max_packet_logs: usize,
}

/// Structure to store packet-level logging information
#[derive(Debug, Clone)]
pub struct PacketLog {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub src_ip: String,
    pub dst_ip: String,
    pub protocol: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub flags: Option<String>,
    pub payload_size: usize,
    pub payload_hash: String,
    pub ttl: Option<u8>,
    pub response_time: Option<f64>,
}

impl EnhancedLogger {
    /// Create a new enhanced logger
    pub fn new(max_log_entries: usize, encrypt: bool, enable_packet_capture: bool) -> Self {
        Self {
            buffer: MemoryLogBuffer::new(max_log_entries, encrypt),
            enable_packet_capture,
            packet_log: Arc::new(Mutex::new(Vec::new())),
            max_packet_logs: 1000, // Default to storing up to 1000 packet logs
        }
    }
    
    /// Log a general message
    pub fn log(&self, level: &str, message: &str) {
        self.buffer.log(level, message);
    }
    
    /// Log a network packet (only if packet capture is enabled)
    pub fn log_packet(&self, 
        src_ip: &str, 
        dst_ip: &str, 
        protocol: &str,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        flags: Option<&str>,
        payload: &[u8],
        ttl: Option<u8>,
        response_time: Option<f64>
    ) {
        if !self.enable_packet_capture {
            return;
        }
        
        // Create SHA-256 hash of payload for forensic reference
        // This allows correlating responses without storing the full payload
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(payload);
        let payload_hash = format!("{:x}", hasher.finalize());
        
        let packet_info = PacketLog {
            timestamp: chrono::Utc::now(),
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            protocol: protocol.to_string(),
            src_port,
            dst_port,
            flags: flags.map(|f| f.to_string()),
            payload_size: payload.len(),
            payload_hash,
            ttl,
            response_time,
        };
        
        // Add to packet log with limit
        let mut packet_logs = self.packet_log.lock();
        if packet_logs.len() >= self.max_packet_logs {
            // Remove oldest logs when we reach the limit
            packet_logs.remove(0);
        }
        packet_logs.push(packet_info);
        
        // Also add a standard log entry for important packets
        if payload.len() > 0 && (protocol == "TCP" || protocol == "UDP") {
            let port_info = match (src_port, dst_port) {
                (Some(sp), Some(dp)) => format!("{}:{} -> {}:{}", src_ip, sp, dst_ip, dp),
                _ => format!("{} -> {}", src_ip, dst_ip),
            };
            
            // Log additional info if we have response time (indicates a successful exchange)
            if let Some(resp_time) = response_time {
                self.buffer.log("DEBUG", &format!(
                    "{} {} packet - Size: {}B, Response: {:.2}ms{}",
                    port_info,
                    protocol,
                    payload.len(),
                    resp_time * 1000.0,
                    flags.map(|f| format!(", Flags: {}", f)).unwrap_or_default()
                ));
            }
        }
    }
    
    /// Get packet logs as formatted text
    pub fn format_packet_logs(&self) -> String {
        let packet_logs = self.packet_log.lock();
        let mut result = String::new();
        
        if packet_logs.is_empty() {
            return "No packet logs captured".to_string();
        }
        
        result.push_str("=== Packet Log Summary ===\n");
        result.push_str("Timestamp | Source | Destination | Protocol | Size | Response Time\n");
        result.push_str("--------------------------------------------------------------------------\n");
        
        for log in packet_logs.iter() {
            let src = match log.src_port {
                Some(p) => format!("{}:{}", log.src_ip, p),
                None => log.src_ip.clone(),
            };
            
            let dst = match log.dst_port {
                Some(p) => format!("{}:{}", log.dst_ip, p),
                None => log.dst_ip.clone(),
            };
            
            let response_time = match log.response_time {
                Some(t) => format!("{:.2}ms", t * 1000.0),
                None => "N/A".to_string(),
            };
            
            result.push_str(&format!(
                "{} | {} | {} | {} | {}B | {}\n",
                log.timestamp.format("%H:%M:%S%.3f"),
                src,
                dst,
                log.protocol,
                log.payload_size,
                response_time
            ));
        }
        
        result
    }
    
    /// Save packet logs to encrypted file
    pub fn save_packet_logs(&self, path: &Path, password: Option<&str>) -> Result<(), anyhow::Error> {
        if !self.enable_packet_capture {
            return Ok(());
        }
        
        let packet_logs = self.packet_log.lock();
        if packet_logs.is_empty() {
            return Ok(());
        }
        
        // Serialize packet logs to JSON
        let json = serde_json::to_string(&*packet_logs)?;
        
        if let Some(pass) = password {
            // Encrypt the logs with the provided password
            use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
            use rand::{thread_rng, Rng};
            
            // Create a key from password
            let mut key = [0u8; 32];
            let mut salt = [0u8; 16];
            thread_rng().fill(&mut salt);
            
            // Derive key from password using PBKDF2 (simplified - in production use a proper KDF)
            let pass_bytes = pass.as_bytes();
            for i in 0..key.len() {
                key[i] = pass_bytes[i % pass_bytes.len()] ^ salt[i % salt.len()];
            }
            
            // Create cipher
            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;
                
            // Create nonce
            let mut nonce = [0u8; 12];
            thread_rng().fill(&mut nonce);
            
            // Encrypt data
            let encrypted = cipher.encrypt(&nonce.into(), json.as_bytes())
                .map_err(|e| anyhow::anyhow!("Encryption error: {}", e))?;
                
            // Write salt + nonce + encrypted data
            let mut file = File::create(path)?;
            file.write_all(&salt)?;
            file.write_all(&nonce)?;
            file.write_all(&encrypted)?;
        } else {
            // Write unencrypted JSON
            let mut file = File::create(path)?;
            file.write_all(json.as_bytes())?;
        }
        
        Ok(())
    }
    
    /// Get number of packet logs
    pub fn packet_log_count(&self) -> usize {
        self.packet_log.lock().len()
    }
    
    /// Clear all packet logs
    pub fn clear_packet_logs(&self) {
        self.packet_log.lock().clear();
    }
    
    /// Access to underlying memory buffer
    pub fn buffer(&self) -> &MemoryLogBuffer {
        &self.buffer
    }
}

/// Determine if the content might be a service banner
pub fn is_likely_service_banner(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }
    
    // Check for common service banner patterns
    if let Ok(str_data) = std::str::from_utf8(data) {
        // Common banner prefixes
        let common_patterns = [
            "SSH-", "220 ", "HTTP/", "* OK ", "SMTP", "+OK ", 
            "FTP", "POP3", "IMAP", "NNTP", "PROXY", "MySQL",
            "220-", "250-", "RFB ", "AUTH", "LMTP", "ESMTP",
            "VNC ", "EHLO", "HELO", "200 ", "100 ", "101 ", 
            "302 ", "404 ", "500 ", "Connection: "
        ];
        
        for pattern in &common_patterns {
            if str_data.starts_with(pattern) {
                return true;
            }
        }
        
        // Look for version numbers with common formats
        if str_data.contains("version") || 
           str_data.contains("Version") || 
           str_data.contains(" v") ||
           (str_data.contains("Server: ")) {
            return true;
        }
    }
    
    false
}

/// Extract likely version information from a service banner
pub fn extract_version_info(data: &[u8]) -> Option<String> {
    if let Ok(str_data) = std::str::from_utf8(data) {
        // Try to extract version patterns like "version X.Y.Z" or "vX.Y.Z"
        let re = regex::Regex::new(r"(?i)(?:version|v)[.\s]+([0-9]+(?:\.[0-9]+)+(?:-\w+)?)")
            .ok()?;
            
        if let Some(captures) = re.captures(str_data) {
            if let Some(version) = captures.get(1) {
                return Some(version.as_str().to_string());
            }
        }
        
        // Try to extract "Server: xxxx" from HTTP headers
        let re = regex::Regex::new(r"Server: ([^\r\n]+)")
            .ok()?;
            
        if let Some(captures) = re.captures(str_data) {
            if let Some(server) = captures.get(1) {
                return Some(server.as_str().to_string());
            }
        }
    }
    
    None
} 