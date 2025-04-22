/// SSL/TLS certificate and connection information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SslInfo {
    /// Handshake time in milliseconds
    pub handshake_ms: f64,
    /// Protocol version (TLS 1.0, 1.1, 1.2, 1.3)
    pub protocol_version: Option<String>,
    /// Negotiated cipher suite
    pub cipher_suite: Option<String>,
    /// Certificate common name
    pub cert_cn: Option<String>,
    /// Certificate subject alternative names
    pub cert_san: Vec<String>,
    /// Certificate issuer
    pub cert_issuer: Option<String>,
    /// Certificate validity start date
    pub cert_valid_from: Option<String>,
    /// Certificate validity end date
    pub cert_valid_to: Option<String>,
    /// Certificate serial number
    pub cert_serial: Option<String>,
    /// Certificate public key algorithm
    pub public_key_algorithm: Option<String>,
    /// Certificate signature algorithm
    pub signature_algorithm: Option<String>,
    /// Certificate key length (bits)
    pub key_length: Option<u32>,
    /// Certificate is self-signed
    pub is_self_signed: Option<bool>,
    /// Certificate has weak signature (MD5, SHA1)
    pub has_weak_signature: Option<bool>,
    /// Server supports TLS 1.3
    pub supports_tls13: Option<bool>,
    /// Server supports TLS 1.2
    pub supports_tls12: Option<bool>,
    /// Server supports TLS 1.1
    pub supports_tls11: Option<bool>,
    /// Server supports TLS 1.0
    pub supports_tls10: Option<bool>,
    /// Server supports SSL 3.0
    pub supports_ssl3: Option<bool>,
    /// Certificate has expired
    pub is_expired: Option<bool>,
    /// Certificate will expire soon (< 30 days)
    pub expires_soon: Option<bool>,
    /// Certificate chain is trusted
    pub chain_is_trusted: Option<bool>,
    /// Certificate subject organization
    pub organization: Option<String>,
    /// Certificate fingerprint (SHA-256)
    pub fingerprint: Option<String>,
}

/// Enum for HTTP security headers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HttpSecurityHeader {
    /// Content-Security-Policy
    ContentSecurityPolicy(String),
    /// X-Content-Type-Options
    XContentTypeOptions(String),
    /// X-Frame-Options
    XFrameOptions(String),
    /// X-XSS-Protection
    XXssProtection(String),
    /// Strict-Transport-Security
    StrictTransportSecurity(String),
    /// Referrer-Policy
    ReferrerPolicy(String),
    /// Feature-Policy/Permissions-Policy
    FeaturePolicy(String),
    /// Other custom security headers
    Other(String, String),
}

/// HTTP response details
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HttpInfo {
    /// HTTP response status code
    pub status_code: Option<u16>,
    /// HTTP response status text
    pub status_text: Option<String>,
    /// HTTP version
    pub http_version: Option<String>,
    /// Server header
    pub server: Option<String>,
    /// Content type
    pub content_type: Option<String>,
    /// Security headers
    pub security_headers: Vec<HttpSecurityHeader>,
    /// Response size in bytes
    pub response_size: Option<usize>,
    /// Response time in milliseconds
    pub response_time: Option<f64>,
    /// Title (from HTML)
    pub title: Option<String>,
    /// Technologies detected
    pub technologies: Vec<String>,
    /// Response headers (full)
    pub headers: HashMap<String, String>,
    /// Cookies
    pub cookies: Vec<String>,
    /// Redirects
    pub redirects: Vec<String>,
}

/// Result information for a single port
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    /// TCP status for different scan techniques
    pub tcp_states: HashMap<ScanType, PortStatus>,
    /// UDP status
    pub udp_state: Option<PortStatus>,
    /// Firewall/filtering information
    pub filtering: Option<String>,
    /// Service name
    pub service: Option<String>,
    /// Service version
    pub version: Option<String>,
    /// Known vulnerabilities
    pub vulns: Vec<String>,
    /// SSL/TLS certificate info
    pub cert_info: Option<SslInfo>,
    /// Service banner
    pub banner: Option<String>,
    /// Operating system guess
    pub os_guess: Option<String>,
    /// Time of scan
    pub scan_time: chrono::DateTime<chrono::Utc>,
    /// HTTP response info
    pub http_info: Option<HttpInfo>,
} 