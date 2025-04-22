#!/usr/bin/env python3
# Detection patterns for file analysis

from typing import Dict, Tuple

def get_patterns() -> Dict[str, str]:
    """
    Get regular expressions for different types of data.
    
    Returns:
        Dictionary mapping pattern names to regex patterns
    """
    return {
        'ipv4': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'ipv6': r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'domain_keywords': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'url': r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)',
        'hash': r'\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128}|\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53})\b',
        'api_key': r'(?i)(?:api[_-]?key|secret)[=:]\s*[\'"]([^\'"]+)[\'"]',
        'jwt': r'eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
        # New patterns for sensitive information
        'username': r'(?i)(?:username|user|login)[=:]\s*[\'"]([^\'"]+)[\'"]',
        'password': r'(?i)(?:password|pass|pwd)[=:]\s*[\'"]([^\'"]+)[\'"]',
        'private_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
        'public_key': r'-----BEGIN (?:RSA|DSA|EC|OPENSSH) PUBLIC KEY-----',
        'aws_key': r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        'base64_encoded': r'[A-Za-z0-9+/=]{40,}',
        'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        'social_security': r'\b\d{3}-\d{2}-\d{4}\b',
        'database_connection': r'(?i)(?:mysql|postgresql|mongodb|sqlserver)://[^:\s]+:[^@\s]+@[^:\s]+:\d+',
        'access_token': r'(?i)(?:access[_-]?token|bearer[_-]?token)[=:]\s*[\'"]([^\'"]+)[\'"]',
        'refresh_token': r'(?i)(?:refresh[_-]?token)[=:]\s*[\'"]([^\'"]+)[\'"]',
        'oauth_token': r'(?i)(?:oauth[_-]?token)[=:]\s*[\'"]([^\'"]+)[\'"]',
        'session_id': r'(?i)(?:session[_-]?id|sid)[=:]\s*[\'"]([^\'"]+)[\'"]',
        'cookie': r'(?i)(?:cookie|session)[=:]\s*[\'"]([^\'"]+)[\'"]',
        # New API-related patterns
        'api_endpoint': r'(?i)(?:https?://[^/\s]+)?/(?:api|rest|graphql|v\d+)/[^\s"\']+',
        'api_method': r'(?i)(?:\'|"|\b)(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)(?:\'|"|\b)',
        'content_type': r'(?i)(?:Content-Type|content-type)[=:]\s*[\'"]([^\'"]+)[\'"]',
        'api_version': r'(?i)(?:v\d+(?:\.\d+)*|\bversion[=:]\s*[\'"]([^\'"]+)[\'"])',
        'api_parameter': r'(?i)(?:[?&][^=\s]+=[^&\s]+)',
        'authorization_header': r'(?i)(?:Authorization|auth)[=:]\s*[\'"]([^\'"]+)[\'"]',
        'rate_limit': r'(?i)(?:rate[_-]?limit|x-rate-limit)[=:]\s*[\'"]?(\d+)[\'"]?',
        'api_key_param': r'(?i)(?:api_key|apikey|key)=([^&\s]+)',
        'curl_command': r'(?i)curl\s+(?:-X\s+(?:GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\s+)?[\'"]?https?://[^\s\'">]+',
        'webhook_url': r'(?i)(?:webhook|callback)[=:]\s*[\'"]?https?://[^\s\'"]+[\'"]?',
        'http_status_code': r'(?i)(?:status|code)[=:]\s*[\'"]?(\d{3})[\'"]?',
        # OpenAPI/Swagger detection
        'openapi_schema': r'(?i)(?:\"openapi\"\s*:\s*\"[^\"]*)|(swagger\s*:\s*\"[^\"]*)',
        
        # GraphQL patterns
        'graphql_query': r'(?i)(?:query\s+\w+\s*\{[^}]*\}|mutation\s+\w+\s*\{[^}]*\})',
        'graphql_schema': r'(?i)(?:type\s+\w+\s*\{[^}]*\}|input\s+\w+\s*\{[^}]*\}|interface\s+\w+\s*\{[^}]*\})',
        
        # REST resource patterns
        'rest_resource': r'(?i)(?:\/[a-zA-Z0-9_-]+(?:\/\{[a-zA-Z0-9_-]+\})?(?:\/[a-zA-Z0-9_-]+)*)',
        
        # API response patterns
        'xml_response': r'(?i)(?:<\?xml[^>]+>|<[a-zA-Z0-9_:]+\s+xmlns)',
        
        # Error handling patterns
        'error_pattern': r'(?i)(?:\"error\"\s*:\s*\{|\"errors\"\s*:\s*\[|\<error>|\<errors>)',
        'http_error': r'(?i)(?:[45]\d{2}\s+[A-Za-z\s]+)',
        
        # API authentication schemes
        'oauth_flow': r'(?i)(?:oauth2|authorization_code|client_credentials|password|implicit)',
        'api_auth_scheme': r'(?i)(?:bearer|basic|digest|apikey|oauth|jwt)\s+auth',
        
        # API request headers
        'request_header': r'(?i)(?:[A-Za-z0-9-]+:\s*[^\n]+)',
        
        # Request body identification
        'request_body_json': r'(?i)(?:body\s*:\s*\{[^}]*\}|data\s*:\s*\{[^}]*\})',
        'form_data': r'(?i)(?:FormData|multipart\/form-data|application\/x-www-form-urlencoded)',
        
        # API parameter types
        'path_parameter': r'(?i)(?:\{[a-zA-Z0-9_-]+\})',
        'query_parameter': r'(?i)(?:\?(?:[a-zA-Z0-9_-]+=[^&\s]+)(?:&[a-zA-Z0-9_-]+=[^&\s]+)*)',
        
        # API documentation patterns
        'api_doc_comment': r'(?i)(?:\/\*\*[\s\S]*?\*\/|\/\/\/.*$|#\s+@api)',
        
        # Webhook patterns
        'webhook_event': r'(?i)(?:\"event\"\s*:\s*\"[^\"]+\"|event=[^&\s]+)',
        
        # Rate limiting and pagination
        'pagination': r'(?i)(?:page=\d+|limit=\d+|offset=\d+|per_page=\d+)',
        'rate_limit_header': r'(?i)(?:X-RateLimit-Limit|X-RateLimit-Remaining|X-RateLimit-Reset)',
        
        # New pattern for successful JSON requests
        'successful_json_request': r'(?i)(?:\{\s*\"(?:success|status|ok|result)\"\s*:\s*(?:true|\"success\"|\"ok\"|1)|\{\s*\"data\"\s*:|\{\s*\"[^\"]+\"\s*:\s*\{[^}]+\}\s*,\s*\"status\"\s*:\s*(?:200|201|\"success\"|\"ok\"))',
        
        # New pattern for failed JSON requests
        'failed_json_request': r'(?i)(?:\{\s*\"(?:error|errors|status)\"\s*:\s*(?:false|\"failed\"|\"error\"|0|\{)|\{\s*\"message\"\s*:\s*\"[^\"]*error[^\"]*\")',
    }

def get_hash_patterns() -> Dict[str, Tuple[str, int]]:
    """
    Get patterns for hash identification.
    
    Returns:
        Dictionary mapping hash types to (regex_pattern, expected_length)
    """
    return {
        'MD5': (r'^[a-fA-F0-9]{32}$', 32),
        'SHA-1': (r'^[a-fA-F0-9]{40}$', 40),
        'SHA-256': (r'^[a-fA-F0-9]{64}$', 64),
        'SHA-512': (r'^[a-fA-F0-9]{128}$', 128),
        'NTLM': (r'^[a-fA-F0-9]{32}$', 32),
        'MySQL4': (r'^[a-fA-F0-9]{16}$', 16),
        'MySQL5': (r'^[a-fA-F0-9]{40}$', 40),
        'BCrypt': (r'^\$2[ayb]\$[0-9]{2}\$[A-Za-z0-9./]{53}$', None),
        'RIPEMD-160': (r'^[a-fA-F0-9]{40}$', 40)
    }

def get_language_security_patterns() -> Dict[str, Dict[str, str]]:
    """
    Get language-specific security pattern detection.
    
    Returns:
        Dictionary of language-specific security patterns
    """
    return {
        'python': {
            'Hardcoded Secret': r'(?:password|secret|key|token)\s*=\s*[\'"][^\'"]+[\'"]',
            'Shell Injection': r'(?:os\.system|subprocess\.call|subprocess\.Popen|eval|exec)\s*\(',
            'SQL Injection': r'(?:execute|executemany)\s*\(\s*[f\'"]',
            'Pickle Usage': r'pickle\.(?:load|loads)',
            'Temp File': r'(?:tempfile\.mk(?:stemp|temp)|open\s*\(\s*[\'"]\/tmp\/)',
            'Assert Usage': r'\bassert\b',
            'HTTP Without TLS': r'http:\/\/(?!localhost|127\.0\.0\.1)',
        },
        'javascript': {
            'Eval Usage': r'\beval\s*\(',
            'Document Write': r'document\.write\s*\(',
            'innerHtml Assignment': r'\.innerHTML\s*=',
            'DOM-based XSS': r'(?:document\.(?:URL|documentURI|URLUnencoded|baseURI|cookie|referrer))',
            'DOM Storage Usage': r'(?:localStorage|sessionStorage)\.',
            'Hardcoded JWT': r'[\'"]eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*[\'"]',
            'Protocol-relative URL': r'[\'"]\/\/\w+',
            'HTTP Without TLS': r'http:\/\/(?!localhost|127\.0\.0\.1)',
            # Adding more comprehensive JavaScript security patterns
            'Dangerous Function Creation': r'(?:new\s+Function|setTimeout\s*\(\s*[\'"`][^\'"`]*[\'"`]\s*\)|setInterval\s*\(\s*[\'"`][^\'"`]*[\'"`]\s*\))',
            'Prototype Pollution': r'(?:Object\.assign|Object\.prototype\.|__proto__|constructor\.prototype)',
            'XSS Sinks': r'(?:\.outerHTML\s*=|\.insertAdjacentHTML|\.write\s*\(|\.writeln\s*\(|\.createContextualFragment\s*\()',
            'Insecure Randomness': r'(?:Math\.random\s*\(\))',
            'JWT Verification Issues': r'(?:\.verify\s*\(\s*token\s*,\s*[\'"`][^\'"]+[\'"`]\s*[,\)]|{algorithms:\s*\[\s*[\'"`]none[\'"`]\s*\]})',
            'Client Storage of Sensitive Data': r'(?:localStorage\.setItem\s*\(\s*[\'"`][^\'"]+[\'"`]\s*,\s*(?:password|token|key|secret|credentials))',
            'Insecure Client-Side Validation': r'(?:\.validate\s*\(\s*\)|\.isValid\s*\(\s*\))',
            'Weak Cryptography': r'(?:\bMD5\b|\bSHA1\b|\.createHash\s*\(\s*[\'"`]md5[\'"`]\s*\))',
            'Postmessage Vulnerabilities': r'(?:window\.addEventListener\s*\(\s*[\'"`]message[\'"`]|\.postMessage\s*\(\s*[^,]+,\s*[\'"]\*[\'"])',
            'CSRF Issues': r'(?:withCredentials\s*:\s*true|xhrFields\s*:\s*{\s*withCredentials\s*:\s*true\s*})',
            'Content Security Issues': r'(?:unsafe-eval|unsafe-inline)',
            'Hardcoded Credentials': r'(?:username\s*[:=]\s*[\'"`][^\'"]+[\'"`]|password\s*[:=]\s*[\'"`][^\'"]+[\'"`]|apiKey\s*[:=]\s*[\'"`][^\'"]+[\'"`]|token\s*[:=]\s*[\'"`][^\'"]+[\'"`])',
            'Insecure Communication': r'(?:ws:\/\/(?!localhost|127\.0\.0\.1))',
            'NoSQL Injection': r'(?:\.find\s*\(\s*{\s*\$where\s*:\s*|\.find\s*\(\s*{\s*[\'"`][^\'"]+[\'"`]\s*:\s*\$\w+)',
            'Regular Expression DOS': r'(?:[^\\][.+*]\{\d+,\}|\(\.\*\)\+)',
            'Insecure Cross-Origin Resource Sharing': r'(?:Access-Control-Allow-Origin\s*:\s*\*|cors\(\s*\{origin\s*:\s*[\'"`]\*[\'"`])',
            'Insecure Third-Party Scripts': r'(?:<script\s+src\s*=\s*[\'"`]http:\/\/|\.src\s*=\s*[\'"`]http:\/\/)',
            'Server-Side Request Forgery': r'(?:\.open\s*\(\s*[\'"`]GET[\'"`]\s*,\s*(?:url|req|request))',
            'Insecure File Upload': r'(?:\.upload\s*\(\s*|\.uploadFile\s*\(\s*|createReadStream\s*\(\s*)',
            'Insecure Iframe': r'(?:<iframe\s+src\s*=\s*[\'"`]http:\/\/|\.src\s*=\s*[\'"`]http:\/\/)',
            'JSON Injection': r'(?:JSON\.parse\s*\(\s*.*(?:req|request|input|data)\s*)',
            'Path Traversal': r'(?:fs\.readFileSync\s*\(\s*.*\.\.\/|fs\.readFile\s*\(\s*.*\.\.\/)',
            'Command Injection': r'(?:(?:child_process|exec|spawn|execSync)\s*\(\s*.*(?:\+|\$\{))',
        },
        'java': {
            'Hardcoded Password': r'(?:password|pwd|passwd)\s*=\s*[\'"][^\'"]+[\'"]',
            'SQL Injection': r'(?:executeQuery|executeUpdate|prepareStatement)\s*\(\s*[\'"].*\+',
            'Command Injection': r'(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)',
            'XXE Vulnerability': r'(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)',
            'Crypto Issues': r'(?:MD5|DES|AES/ECB)',
            'Random Predictable': r'new\s+Random\s*\(\s*\)',
            'Trust All Certificates': r'TrustAllCerts|X509TrustManager',
        }
    }

def get_network_patterns() -> Dict[str, Dict[str, str]]:
    """
    Get network protocol and security patterns.
    
    Returns:
        Dictionary of network-related patterns
    """
    return {
        'protocols': {
            'HTTP': r'(?i)(?:http\.(?:get|post|put|delete)|fetch\(|XMLHttpRequest|axios)',
            'HTTPS': r'(?i)https:\/\/',
            'FTP': r'(?i)(?:ftp:\/\/|ftps:\/\/|\bftp\s+(?:open|get|put))',
            'SSH': r'(?i)(?:ssh\s+|ssh2_connect|new\s+SSH|JSch)',
            'SMTP': r'(?i)(?:smtp\s+|mail\s+send|createTransport|sendmail|new\s+SmtpClient)',
            'DNS': r'(?i)(?:dns\s+lookup|resolv|nslookup|dig\s+)',
            'MQTT': r'(?i)(?:mqtt\s+|MQTTClient|mqtt\.connect)',
            'WebSocket': r'(?i)(?:new\s+WebSocket|createWebSocketClient|websocket\.connect)',
            'gRPC': r'(?i)(?:grpc\.(?:Server|Client)|new\s+ServerBuilder)',
            'GraphQL': r'(?i)(?:graphql\s+|ApolloClient|gql`)',
            'TCP/IP': r'(?i)(?:socket\.|Socket\(|createServer|listen\(\d+|bind\(\d+|connect\(\d+)',
            'UDP': r'(?i)(?:dgram\.|DatagramSocket|UdpClient)',
            'ICMP': r'(?i)(?:ping\s+|ICMP|IcmpClient)',
            'SNMP': r'(?i)(?:snmp\s+|SnmpClient|createSnmpSession)',
            'LDAP': r'(?i)(?:ldap\s+|LdapClient|createLdapConnection)',
            # JavaScript-specific network protocols
            'Fetch API': r'(?i)(?:fetch\s*\(|\.then\s*\(|\.json\s*\(\s*\)|\.blob\s*\(\s*\))',
            'Axios': r'(?i)(?:axios\.(?:get|post|put|delete|patch)|axios\s*\(\s*\{)',
            'jQuery AJAX': r'(?i)(?:\$\.(?:ajax|get|post|getJSON)|jQuery\.(?:ajax|get|post))',
            'XMLHttpRequest': r'(?i)(?:new\s+XMLHttpRequest\(|\.open\s*\(|\.send\s*\(|\.onreadystatechange)',
            'NodeJS HTTP': r'(?i)(?:require\s*\(\s*[\'"]http[\'"]|http\.createServer|http\.request|http\.get)',
            'NodeJS HTTPS': r'(?i)(?:require\s*\(\s*[\'"]https[\'"]|https\.createServer|https\.request|https\.get)',
            'WebRTC': r'(?i)(?:RTCPeerConnection|getUserMedia|createDataChannel|onicecandidate)',
            'Server-Sent Events': r'(?i)(?:new\s+EventSource\s*\(|\.addEventListener\s*\(\s*[\'"]message[\'"])',
            'Service Workers': r'(?i)(?:navigator\.serviceWorker|ServiceWorkerRegistration|new\s+Cache\()',
            'Firebase': r'(?i)(?:firebase\.database\(\)|ref\(\)|child\(\)|set\(\)|push\(\)|update\(\)|remove\(\))',
            'Socket.IO': r'(?i)(?:io\s*\(\s*|\.on\s*\(\s*[\'"]connect[\'"]\s*|socket\.emit\s*\()',
            'Cross-Domain': r'(?i)(?:\.postMessage\s*\(|JSONP|document\.domain\s*=)',
        },
        'security_issues': {
            'Clear Text Credentials': r'(?i)(?:auth=|user:pass@|username=\w+&password=)',
            'Insecure Protocol': r'(?i)(?:ftp:\/\/|telnet:\/\/|http:\/\/(?!localhost|127\.0\.0\.1))',
            'Hardcoded IP': r'\b(?:PUBLIC_IP|SERVER_ADDR|API_HOST)\s*=\s*[\'"](?:\d{1,3}\.){3}\d{1,3}[\'"]',
            'Open Port': r'(?i)(?:listen\(\s*\d+|port\s*=\s*\d+|\.connect\(\s*(?:["\']\w+["\']\s*,\s*)?\d+\))',
            'Weak TLS': r'(?i)(?:SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|\bRC4\b|\bDES\b|MD5WithRSA|allowAllHostnames)',
            'Certificate Validation Disabled': r'(?i)(?:verify=False|CERT_NONE|InsecureRequestWarning|rejectUnauthorized:\s*false|trustAllCerts)',
            'Proxy Settings': r'(?i)(?:proxy\s*=|http_proxy|https_proxy|\.setProxy|\.proxy\()',
            'CORS Misconfiguration': r'(?i)(?:Access-Control-Allow-Origin:\s*\*|cors\({.*?origin:\s*[\'"]?\*[\'"]?)',
            'Unencrypted Socket': r'(?i)(?:new\s+Socket|socket\.|createServer)(?![^\n]*SSL|[^\n]*TLS)',
            'Server-Side Request Forgery': r'(?i)(?:\.open\([\'"]GET[\'"],\s*(?:url|req|request))',
            'DNS Rebinding': r'(?i)(?:allowLocal\s*:|allowAny\s*:|\*\.localhost)',
            'WebSockets Insecure': r'(?i)(?:ws:\/\/|new\s+WebSocket\([\'"]ws:\/\/)',
        },
        'configuration': {
            'port': r'(?:^|\s)(?:PORT|port)\s*(?:=|:)\s*(\d+)',
            'host': r'(?:^|\s)(?:HOST|host|SERVER|server)\s*(?:=|:)\s*[\'"]([\w\.\-]+)[\'"]',
        }
    }

def get_software_version_patterns() -> Dict[str, str]:
    """
    Get patterns to detect software versions.
    
    Returns:
        Dictionary mapping software names to version detection patterns
    """
    return {
        'jquery': r'(?:jquery[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'bootstrap': r'(?:bootstrap[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'react': r'(?:react[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'vue': r'(?:vue[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'angular': r'(?:angular[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'lodash': r'(?:lodash[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'express': r'(?:express[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'django': r'(?:django[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'flask': r'(?:flask[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'spring': r'(?:spring[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'tensorflow': r'(?:tensorflow[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'pytorch': r'(?:pytorch[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'openssl': r'(?:openssl[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?[a-z]?)',
        'nginx': r'(?:nginx[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'apache': r'(?:apache[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'php': r'(?:php[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'node.js': r'(?:node[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'python': r'(?:python[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'java': r'(?:java[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'dotnet': r'(?:\.net[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'wordpress': r'(?:wordpress[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'drupal': r'(?:drupal[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'joomla': r'(?:joomla[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        # Additional software patterns
        'laravel': r'(?:laravel[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'symfony': r'(?:symfony[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'spring-boot': r'(?:spring-boot[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'rails': r'(?:rails[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'jquery-ui': r'(?:jquery-ui[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'moment': r'(?:moment[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'axios': r'(?:axios[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'webpack': r'(?:webpack[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'babel': r'(?:babel[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'eslint': r'(?:eslint[.-]?)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
    }

def get_package_file_patterns() -> Dict[str, str]:
    """
    Get patterns to detect versions in dependency files.
    
    Returns:
        Dictionary mapping package file types to dependency patterns
    """
    return {
        'package.json': r'"([\w\-@/]+)":\s*"([~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9\.]+)?)"',
        'requirements.txt': r'([\w\-]+)(?:={1,2}|>=|<=|>|<|~=)([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'composer.json': r'"([\w\-/]+)":\s*"([~^]?[0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9\.]+)?)"',
        'build.gradle': r'([\w\-]+):([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        'pom.xml': r'<([\w\-\.]+)>[0-9]+\.[0-9]+(?:\.[0-9]+)?</\1>',
    } 