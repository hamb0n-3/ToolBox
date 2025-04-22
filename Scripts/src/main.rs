#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Enable packet capture for detailed network analysis
    #[clap(long, default_value_t = true)]
    packet_capture: bool,
    
    /// Maximum number of packet logs to keep
    #[clap(long, default_value_t = 1000)]
    max_packet_logs: usize,
    
    /// Save packet logs to file
    #[clap(long)]
    packet_log_file: Option<PathBuf>,
    
    /// Password for packet log encryption
    #[clap(long)]
    packet_log_password: Option<String>,
    
    /// Output detailed certificate information for SSL/TLS ports
    #[clap(long, default_value_t = true)]
    ssl_details: bool,
    
    /// Skip version detection
    #[clap(long)]
    no_version_detection: bool,
    
    /// Try to grab service banners
    #[clap(long, default_value_t = true)]
    grab_banners: bool,
    
    /// Analyze HTTP headers
    #[clap(long, default_value_t = true)]
    analyze_http: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // Setup memory logger with memory-only option
    let memory_logger = match setup_logging(
        &args.log_file, 
        args.verbose, 
        args.memory_only,
        args.encrypt_logs,
        args._log_password.as_deref()
    ) {
        Ok(logger) => logger,
        Err(e) => {
            eprintln!("Warning: Failed to set up logging: {}", e);
            None
        }
    };
    
    // Setup enhanced logger for packet capture if enabled
    let enhanced_logger = if args.packet_capture {
        println!("[{}+{}] Packet capture enabled - collecting detailed network data", 
            colors.green, colors.reset);
        Some(Arc::new(utils::EnhancedLogger::new(
            args.max_packet_logs,
            args.encrypt_logs,
            true // enable packet capture
        )))
    } else {
        None
    };
    
    // Create scanner instance with enhanced evasion options
    let mut scanner = QuantumScanner::new(
        &args.target,
        ports_to_scan.clone(),
        scan_types,
        args.concurrency,
        args.rate,
        // Use enhanced evasion if specified
        args.evasion || args.enhanced_evasion,
        args.verbose,
        args.ipv6,
        args.json,
        args.timeout,
        args.timeout_connect,
        args.timeout_banner,
        &args.mimic_protocol,
        args.frag_min_size,
        args.frag_max_size,
        args.frag_min_delay,
        args.frag_max_delay,
        args.frag_timeout,
        args.frag_first_min_size,
        args.frag_two_frags,
        &args.log_file,
    ).await?;
    
    // Set enhanced evasion options
    if args.enhanced_evasion {
        scanner.set_enhanced_evasion(true, args.mimic_os.as_deref().unwrap_or("random"), args.ttl_jitter);
        scanner.set_protocol_variant(args.protocol_variant.as_deref());
    }
    
    // Set memory logger if available
    if let Some(logger) = memory_logger.clone() {
        scanner.set_memory_log(Arc::new(logger));
    }
    
    // Set enhanced logger if available
    if let Some(logger) = enhanced_logger.clone() {
        scanner.set_enhanced_logger(logger.clone());
    }
    
    // Run the scan
    println!("[{}+{}] Starting scan of {} with {} ports", 
        colors.green, colors.reset, args.target, ports_to_scan.len());
    println!("{}════════════════════════════════════════════{}", colors.blue, colors.reset);
    
    let results = scanner.run_scan().await?;
    
    // Output results based on mode
    println!("{}════════════════════════════════════════════{}", colors.blue, colors.reset);
    println!("[{}+{}] Scan completed. Found {} open ports", 
        colors.green, colors.reset, results.open_ports.len());
    
    // Display results
    for port in results.open_ports.iter().cloned().collect::<Vec<_>>() {
        if let Some(result) = results.results.get(&port) {
            let _status = result.tcp_states.values().next().unwrap_or(&PortStatus::Filtered);
            println!("Port {}:{} {}", port, colors.green, colors.reset);
            
            if let Some(service) = &result.service {
                println!("  Service: {}", service);
            }
            
            if let Some(version) = &result.version {
                println!("  Version: {}", version);
            }
            
            // Display SSL/TLS details if available and ssl_details enabled
            if args.ssl_details {
                if let Some(ssl_info) = &result.cert_info {
                    println!("  SSL/TLS:");
                    if let Some(protocol) = &ssl_info.protocol_version {
                        println!("    Protocol: {}", protocol);
                    }
                    if let Some(cipher) = &ssl_info.cipher_suite {
                        println!("    Cipher: {}", cipher);
                    }
                    if let Some(cn) = &ssl_info.cert_cn {
                        println!("    Subject: {}", cn);
                    }
                    if let Some(issuer) = &ssl_info.cert_issuer {
                        println!("    Issuer: {}", issuer);
                    }
                    if let Some(valid_to) = &ssl_info.cert_valid_to {
                        println!("    Valid Until: {}", valid_to);
                    }
                }
            }
            
            // Display banner if available and verbose enabled
            if args.verbose {
                if let Some(banner) = &result.banner {
                    // Limit banner display to first line or 80 chars
                    let first_line = banner.lines().next().unwrap_or(banner).chars().take(80).collect::<String>();
                    println!("  Banner: {}", first_line);
                }
            }
        }
    }
    
    // Output to file if requested
    if let Some(output_path) = args.output {
        if args.json {
            output::save_json_results(&results, &output_path)?;
            println!("[{}+{}] Results saved to {} in JSON format", 
                colors.green, colors.reset, output_path.display());
        } else {
            output::save_text_results(&results, &output_path)?;
            println!("[{}+{}] Results saved to {}", 
                colors.green, colors.reset, output_path.display());
        }
    }
    
    // Save packet logs if requested
    if let Some(packet_log_path) = args.packet_log_file {
        if let Some(logger) = enhanced_logger {
            match logger.save_packet_logs(&packet_log_path, args.packet_log_password.as_deref()) {
                Ok(_) => {
                    println!("[{}+{}] Packet logs saved to {}", 
                        colors.green, colors.reset, packet_log_path.display());
                    println!("[{}+{}] Captured {} network packets", 
                        colors.green, colors.reset, logger.packet_log_count());
                },
                Err(e) => {
                    println!("[{}!{}] Failed to save packet logs: {}", 
                        colors.yellow, colors.reset, e);
                }
            }
        }
    } else if args.packet_capture {
        // Display packet log summary if enabled but not saved to file
        if let Some(logger) = enhanced_logger {
            println!("\n[{}+{}] Captured {} network packets", 
                colors.green, colors.reset, logger.packet_log_count());
            
            if args.verbose {
                println!("\nPacket Log Summary:");
                println!("{}", logger.format_packet_logs());
            }
        }
    }
    
    // Print memory log summary if available
    if let Some(logger) = memory_logger {
        if args.verbose {
            println!("\nLog entries: {}", logger.len());
            println!("Log contents:");
            println!("{}", logger.format_logs(true));
        }
    }
    
    // ... existing cleanup code ...
    
    println!("{}Quantum Scanner operation complete{}", colors.green, colors.reset);
    
    Ok(())
} 