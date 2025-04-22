pub struct QuantumScanner {
    // ... existing fields ...
    memory_log: Option<Arc<utils::MemoryLogBuffer>>,
    enhanced_logger: Option<Arc<utils::EnhancedLogger>>,
    // ... existing fields ...
}

impl QuantumScanner {
    // ... existing code ...
    
    /// Set enhanced logger for packet capture and detailed analysis
    pub fn set_enhanced_logger(&mut self, logger: Arc<utils::EnhancedLogger>) {
        self.enhanced_logger = Some(logger);
    }
    
    // ... existing code ...
    
    /// Process a packet response and log it with the enhanced logger if available
    fn log_packet_response(&self, 
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
        if let Some(logger) = &self.enhanced_logger {
            logger.log_packet(
                src_ip, 
                dst_ip, 
                protocol,
                src_port,
                dst_port,
                flags,
                payload,
                ttl,
                response_time
            );
            
            // Check if this might be a service banner and extract version if possible
            if utils::is_likely_service_banner(payload) {
                if let Some(port) = dst_port {
                    // This appears to be a service banner response
                    let banner_str = String::from_utf8_lossy(payload);
                    logger.log("INFO", &format!(
                        "Possible service banner on port {}: {}", 
                        port,
                        banner_str.chars().take(100).collect::<String>() // Limit to first 100 chars for log
                    ));
                    
                    // Try to extract version information
                    if let Some(version) = utils::extract_version_info(payload) {
                        logger.log("INFO", &format!(
                            "Detected version on port {}: {}", 
                            port,
                            version
                        ));
                    }
                }
            }
        }
    }
    
    // ... existing code ...
    
    /// Analyze SSL/TLS on an open port
    async fn analyze_ssl(&mut self, target: &str, port: u16) -> Option<SslInfo> {
        let start_time = std::time::Instant::now();
        
        // Create TLS configuration
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(webpki_roots::TLS_SERVER_ROOTS.clone())
            .with_no_client_auth();
            
        let rc_config = Arc::new(config);
        
        // Create TLS connector
        let connector = tokio_rustls::TlsConnector::from(rc_config);
        
        // Connect to target
        let addr = format!("{}:{}", target, port);
        let stream = match tokio::net::TcpStream::connect(&addr).await {
            Ok(s) => s,
            Err(e) => {
                if let Some(logger) = &self.enhanced_logger {
                    logger.log("DEBUG", &format!(
                        "Failed to connect to {}:{} for SSL analysis: {}", 
                        target, port, e
                    ));
                }
                return None;
            }
        };
        
        // Perform TLS handshake
        let domain = rustls::ServerName::try_from(target)
            .map_err(|_| format!("Invalid DNS name: {}", target))
            .ok()?;
            
        let tls_stream = match connector.connect(domain, stream).await {
            Ok(s) => s,
            Err(e) => {
                if let Some(logger) = &self.enhanced_logger {
                    logger.log("DEBUG", &format!(
                        "TLS handshake failed on {}:{}: {}", 
                        target, port, e
                    ));
                }
                return None;
            }
        };
        
        // Extract TLS certificate information if available
        let (_, rustls_connection) = tls_stream.get_ref();
        let certs = rustls_connection.peer_certificates().map(|certs| certs.to_vec());
        
        // Extract certificate info
        let mut ssl_info = SslInfo {
            handshake_ms: start_time.elapsed().as_secs_f64() * 1000.0,
            protocol_version: None,
            cipher_suite: None,
            cert_cn: None,
            cert_san: Vec::new(),
            cert_issuer: None,
            cert_valid_from: None,
            cert_valid_to: None,
            cert_serial: None,
            // ... other fields ...
        };
        
        // Get connection info
        ssl_info.protocol_version = rustls_connection.protocol_version().map(|v| format!("{:?}", v));
        ssl_info.cipher_suite = rustls_connection.negotiated_cipher_suite().map(|cs| format!("{:?}", cs.suite()));
        
        // Process certificate if available
        if let Some(certs) = certs {
            if !certs.is_empty() {
                use x509_parser::prelude::*;
                // Parse first certificate (leaf cert)
                if let Ok((_, cert)) = X509Certificate::from_der(&certs[0].0) {
                    // Extract subject common name
                    if let Some(cn) = cert.subject().iter_common_name().next() {
                        if let Ok(cn_str) = cn.as_str() {
                            ssl_info.cert_cn = Some(cn_str.to_string());
                        }
                    }
                    
                    // Extract subject alternative names
                    if let Some(sans) = cert.subject_alternative_name() {
                        if let Ok((_, san)) = sans.value.general_names() {
                            for gn in san {
                                match gn {
                                    GeneralName::DNSName(name) => {
                                        ssl_info.cert_san.push(name.to_string());
                                    },
                                    GeneralName::IPAddress(ip) => {
                                        ssl_info.cert_san.push(format!("IP:{:?}", ip));
                                    },
                                    _ => {}
                                }
                            }
                        }
                    }
                    
                    // Extract issuer
                    if let Some(issuer) = cert.issuer().iter_common_name().next() {
                        if let Ok(issuer_str) = issuer.as_str() {
                            ssl_info.cert_issuer = Some(issuer_str.to_string());
                        }
                    }
                    
                    // Extract validity
                    ssl_info.cert_valid_from = Some(cert.validity().not_before.to_string());
                    ssl_info.cert_valid_to = Some(cert.validity().not_after.to_string());
                    
                    // Extract serial number
                    ssl_info.cert_serial = Some(format!("{:X}", cert.serial));
                    
                    // Log certificate information
                    if let Some(logger) = &self.enhanced_logger {
                        logger.log("INFO", &format!(
                            "TLS certificate for {}:{} - Subject: {}, Issuer: {}, Valid until: {}",
                            target, 
                            port,
                            ssl_info.cert_cn.as_deref().unwrap_or("Unknown"),
                            ssl_info.cert_issuer.as_deref().unwrap_or("Unknown"),
                            ssl_info.cert_valid_to.as_deref().unwrap_or("Unknown")
                        ));
                    }
                }
            }
        }
        
        Some(ssl_info)
    }

    // ... existing code ...
    
    /// Update an enhanced scan status in results
    async fn update_port_result_enhanced(&mut self, port: u16, scan_type: ScanType, status: PortStatus) {
        // ... existing code ...
        
        // If the port is open, attempt additional analysis
        if status == PortStatus::Open {
            // Check if port is HTTP/HTTPS and grab server banner
            if port == 80 || port == 443 || port == 8080 || port == 8443 {
                self.grab_http_banner(&self.target_ip, port).await;
            }
            
            // Analyze SSL/TLS if appropriate
            if port == 443 || port == 465 || port == 636 || port == 993 || port == 995 || port == 8443 {
                if let Some(ssl_info) = self.analyze_ssl(&self.target_ip, port).await {
                    if let Some(result) = self.results.get_mut(&port) {
                        result.cert_info = Some(ssl_info);
                    }
                }
            }
            
            // Try simple banner grabbing for known service ports
            let known_service_ports = [
                21, 22, 23, 25, 110, 119, 143, 389, 587
            ];
            
            if known_service_ports.contains(&port) {
                self.grab_banner(&self.target_ip, port).await;
            }
        }
    }
    
    /// Grab HTTP server banner and log it
    async fn grab_http_banner(&mut self, target: &str, port: u16) {
        let protocol = if port == 443 || port == 8443 { "https" } else { "http" };
        let url = format!("{}://{}:{}/", protocol, target, port);
        
        // Simulate a very simple HTTP client
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            target
        );
        
        let stream_result = if protocol == "https" {
            // For HTTPS, we need TLS
            let config = rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(webpki_roots::TLS_SERVER_ROOTS.clone())
                .with_no_client_auth();
                
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let addr = format!("{}:{}", target, port);
            
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(stream) => {
                    let domain = match rustls::ServerName::try_from(target) {
                        Ok(d) => d,
                        Err(_) => return,
                    };
                    
                    match connector.connect(domain, stream).await {
                        Ok(tls_stream) => {
                            let (mut reader, mut writer) = tokio::io::split(tls_stream);
                            
                            // Write request
                            if writer.write_all(request.as_bytes()).await.is_err() {
                                return;
                            }
                            
                            // Read response
                            let mut buffer = [0; 4096];
                            match reader.read(&mut buffer).await {
                                Ok(n) if n > 0 => Some(buffer[..n].to_vec()),
                                _ => None,
                            }
                        },
                        Err(_) => None,
                    }
                },
                Err(_) => None,
            }
        } else {
            // Regular HTTP
            let addr = format!("{}:{}", target, port);
            
            match tokio::net::TcpStream::connect(&addr).await {
                Ok(mut stream) => {
                    // Write request
                    if stream.write_all(request.as_bytes()).await.is_err() {
                        return;
                    }
                    
                    // Read response
                    let mut buffer = [0; 4096];
                    match stream.read(&mut buffer).await {
                        Ok(n) if n > 0 => Some(buffer[..n].to_vec()),
                        _ => None,
                    }
                },
                Err(_) => None,
            }
        };
        
        // Process the response
        if let Some(response) = stream_result {
            // Log the HTTP response with the enhanced logger
            self.log_packet_response(
                target,
                &utils::get_local_ipv4().unwrap_or_else(|| "127.0.0.1".to_string()),
                "HTTP",
                Some(port),
                None,
                None,
                &response,
                None,
                None
            );
            
            // Update result
            if let Some(result) = self.results.get_mut(&port) {
                // Save banner
                result.banner = Some(String::from_utf8_lossy(&response[..std::cmp::min(response.len(), 1024)]).to_string());
                
                // Extract server header
                if let Some(version) = utils::extract_version_info(&response) {
                    result.version = Some(version);
                }
                
                // Update service
                if protocol == "https" {
                    result.service = Some("https".to_string());
                } else {
                    result.service = Some("http".to_string());
                }
            }
        }
    }
    
    /// Grab generic service banner and log it
    async fn grab_banner(&mut self, target: &str, port: u16) {
        let addr = format!("{}:{}", target, port);
        
        match tokio::time::timeout(
            Duration::from_secs_f64(self.timeout_banner),
            tokio::net::TcpStream::connect(&addr)
        ).await {
            Ok(Ok(mut stream)) => {
                // Some services send a banner immediately upon connection
                let mut buffer = [0; 2048];
                
                // Wait a short time for the banner
                match tokio::time::timeout(
                    Duration::from_millis(500),
                    stream.read(&mut buffer)
                ).await {
                    Ok(Ok(n)) if n > 0 => {
                        let response = &buffer[..n];
                        
                        // Log the service response
                        self.log_packet_response(
                            target,
                            &utils::get_local_ipv4().unwrap_or_else(|| "127.0.0.1".to_string()),
                            "TCP",
                            Some(port),
                            None,
                            None,
                            response,
                            None,
                            None
                        );
                        
                        // Update result with banner
                        if let Some(result) = self.results.get_mut(&port) {
                            result.banner = Some(String::from_utf8_lossy(response).to_string());
                            
                            // Try to infer service and version
                            match port {
                                21 => result.service = Some("ftp".to_string()),
                                22 => result.service = Some("ssh".to_string()),
                                23 => result.service = Some("telnet".to_string()),
                                25 | 587 => result.service = Some("smtp".to_string()),
                                110 => result.service = Some("pop3".to_string()),
                                119 => result.service = Some("nntp".to_string()),
                                143 => result.service = Some("imap".to_string()),
                                389 => result.service = Some("ldap".to_string()),
                                _ => {}
                            }
                            
                            // Extract version if possible
                            if let Some(version) = utils::extract_version_info(response) {
                                result.version = Some(version);
                            }
                        }
                    },
                    _ => {}
                }
            },
            _ => {}
        }
    }

    // ... existing code ...
} 