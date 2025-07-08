import random
import datetime
import ipaddress
import hashlib
import json

# --- MITRE ATT&CK Definitions ---
MITRE_ATTACK_TECHNIQUES = {
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1078": "Valid Accounts",
    "T1053.005": "Scheduled Task/Job",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1071.001": "Application Layer Protocol: Web Protocols (HTTP/S)",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1036.005": "Masquerading: Match Legitimate Name or Location",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1486": "Data Encrypted for Impact (Ransomware)",
    "T1567.002": "Exfiltration Over C2 Channel",
    "T1087.001": "Account Discovery: Local Account",
    "T1046": "Network Service Discovery",
    "T1070.004": "Indicator Removal on Host: File Deletion",
    "T1136.001": "Create Account: Local Account",
    "T1098": "Account Manipulation",
    "T1068": "Exploitation for Privilege Escalation",
    "T1055": "Process Injection",
    "T1027": "Obfuscated Files or Information",
    "T1573.001": "Encrypted Channel: Symmetric Cryptography",
    "T1090.002": "Proxy: SOCKS Proxy",
    "T1018": "Remote System Discovery",
    "T1083": "File and Directory Discovery",
    "T1074.001": "Data Staged: Local Data Staging",
    "T1537": "Transfer Data to Cloud Account",
    "T1560.001": "Archive Collected Data: Archive via Utility",
    "T1072": "Software Deployment Tools"
}

MITRE_ATTACK_GROUPS = {
    "G0006": "APT28 (Fancy Bear)",
    "G0032": "Lazarus Group",
    "G0034": "FIN7",
    "G0096": "DarkSide",
    "G0102": "BlackMatter",
    "G0091": "UNC2452 (SolarWinds)",
    "G0005": "APT29 (Cozy Bear)",
    "G0045": "Dragonfly",
    "G0059": "Equation Group",
    "G0084": "Sandworm Team"
}

def generate_ip_address(is_malicious=False):
    """Generates a random IP address, optionally making it a 'known' malicious one."""
    if is_malicious:
        malicious_ips = [
            "192.168.1.100", # Internal IP often used in labs, can be 'malicious' in context
            "10.0.0.5",     # Another internal IP
            "172.16.0.1",   # Another internal IP
            "1.2.3.4",      # Placeholder for external malicious IP
            "5.6.7.8",      # Placeholder for external malicious IP
            "185.239.237.10", # Example botnet C2
            "45.79.179.176",  # Example phishing server
            "203.0.113.12",   # Example for documentation
            "198.51.100.25"   # Example for documentation
        ]
        return random.choice(malicious_ips)
    else:
        return str(ipaddress.IPv4Address(random.getrandbits(32)))

def generate_random_hash(hash_type='sha256'):
    """Generates a random SHA256 or MD5 hash."""
    if hash_type == 'sha256':
        return hashlib.sha256(str(random.getrandbits(256)).encode()).hexdigest()
    elif hash_type == 'md5':
        return hashlib.md5(str(random.getrandbits(128)).encode()).hexdigest()
    return ""

def generate_timestamp(start_date, end_date):
    """Generates a random timestamp within a given date range."""
    time_between_dates = end_date - start_date
    random_seconds = random.randrange(int(time_between_dates.total_seconds()))
    return (start_date + datetime.timedelta(seconds=random_seconds)).isoformat()

def generate_network_log(start_date, end_date, is_suspicious=False):
    """Generates a single synthetic network log entry."""
    timestamp = generate_timestamp(start_date, end_date)
    source_ip = generate_ip_address(is_malicious=is_suspicious and random.random() < 0.7)
    dest_ip = generate_ip_address(is_malicious=is_suspicious and random.random() < 0.3)
    source_port = random.randint(1024, 65535)
    dest_port = random.choice([80, 443, 22, 21, 23, 3389, 8080, 53, random.randint(1, 65535)])
    protocol = random.choice(['TCP', 'UDP', 'ICMP'])
    action = random.choice(['ALLOW', 'DENY'])
    bytes_sent = random.randint(50, 50000)
    bytes_received = random.randint(50, 50000)
    event_type = "connection"
    alert_level = "INFO"

    if is_suspicious:
        suspicion_type = random.random()
        if suspicion_type < 0.3: # Port scan attempt
            dest_port = random.randint(1, 1024)
            action = "DENY"
            event_type = "port_scan_attempt"
            alert_level = "WARNING"
        elif suspicion_type < 0.6: # Unusual high traffic
            bytes_sent = random.randint(500000, 5000000)
            bytes_received = random.randint(500000, 5000000)
            event_type = "unusual_traffic"
            alert_level = "WARNING"
        elif suspicion_type < 0.8: # Known malicious IP communication
            event_type = "malicious_ip_communication"
            alert_level = "CRITICAL"
            action = "DENY" if random.random() < 0.8 else "ALLOW"
        else: # Attempted unauthorized access
            dest_port = random.choice([22, 3389, 23])
            action = "DENY"
            event_type = "unauthorized_access_attempt"
            alert_level = "HIGH"

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "source_port": source_port,
        "dest_port": dest_port,
        "protocol": protocol,
        "action": action,
        "bytes_sent": bytes_sent,
        "bytes_received": bytes_received,
        "event_type": event_type,
        "alert_level": alert_level
    }

def generate_threat_intelligence_ioc():
    """Generates a single synthetic IOC entry with MITRE ATT&CK context."""
    ioc_type = random.choice(['IP_ADDRESS', 'DOMAIN', 'FILE_HASH_SHA256', 'FILE_HASH_MD5', 'URL'])
    value = ""
    if ioc_type == 'IP_ADDRESS':
        value = generate_ip_address(is_malicious=True)
    elif ioc_type == 'DOMAIN':
        value = random.choice([
            "malicious-domain.com", "phishing-site.net", "badware.org",
            "c2-server.ru", "exploit-kit.xyz", "update-service.biz",
            "free-downloads.info", "secure-login.co"
        ])
    elif ioc_type == 'FILE_HASH_SHA256':
        value = generate_random_hash('sha256')
    elif ioc_type == 'FILE_HASH_MD5':
        value = generate_random_hash('md5')
    elif ioc_type == 'URL':
        value = random.choice([
            "http://phishing-site.net/login.php",
            "https://badware.org/malware.exe",
            "http://c2-server.ru/beacon",
            "http://free-downloads.info/crack.zip"
        ])

    threat_group_id = random.choice(list(MITRE_ATTACK_GROUPS.keys()))
    threat_group_name = MITRE_ATTACK_GROUPS[threat_group_id]

    # Select 1-3 relevant ATT&CK techniques
    num_techniques = random.randint(1, 3)
    techniques_ids = random.sample(list(MITRE_ATTACK_TECHNIQUES.keys()), num_techniques)
    techniques_details = [{"id": tid, "name": MITRE_ATTACK_TECHNIQUES[tid]} for tid in techniques_ids]

    description_templates = [
        f"Associated with {threat_group_name} ({threat_group_id}) campaigns. Observed using techniques like {', '.join([t['name'] for t in techniques_details])}.",
        f"This {ioc_type.replace('_', ' ').lower()} is a known indicator for {threat_group_name} ({threat_group_id}), often involved in {random.choice(['initial access', 'persistence', 'exfiltration'])} operations.",
        f"IOC linked to {threat_group_name} ({threat_group_id}), specifically seen in attacks employing {random.choice([techniques_details[0]['name'], 'multiple ATT&CK techniques'])}."
    ]
    description = random.choice(description_templates)

    confidence_score = round(random.uniform(0.6, 0.95), 2)
    last_seen = generate_timestamp(datetime.datetime(2023, 1, 1), datetime.datetime.now())

    return {
        "ioc_type": ioc_type,
        "value": value,
        "threat_group_id": threat_group_id,
        "threat_group_name": threat_group_name,
        "mitre_attack_techniques": techniques_details,
        "description": description,
        "confidence_score": confidence_score,
        "last_seen": last_seen
    }

def generate_incident_report(start_date, end_date):
    """Generates a single synthetic incident report entry with MITRE ATT&CK context."""
    incident_id = f"INC-{random.randint(10000, 99999)}"
    timestamp_detected = generate_timestamp(start_date, end_date)

    incident_types_and_techniques = {
        "Malware Infection": ["T1059.001", "T1547.001", "T1486", "T1055"],
        "Phishing Attempt": ["T1566.001", "T1078"],
        "Unauthorized Access": ["T1078", "T1021.001", "T1087.001", "T1068"],
        "DDoS Attack": ["T1071.001"], # More generic, less direct ATT&CK mapping
        "Data Exfiltration": ["T1567.002", "T1074.001", "T1537"],
        "Insider Threat": ["T1078", "T1087.001", "T1070.004"],
        "Web Application Attack": ["T1071.001", "T1059.003"],
        "Brute Force Attack": ["T1078"]
    }

    incident_type = random.choice(list(incident_types_and_techniques.keys()))
    possible_techniques_ids = incident_types_and_techniques[incident_type]
    
    # Select 1-3 techniques relevant to the incident type
    num_techniques = random.randint(1, min(len(possible_techniques_ids), 3))
    techniques_ids = random.sample(possible_techniques_ids, num_techniques)
    techniques_observed = [{"id": tid, "name": MITRE_ATTACK_TECHNIQUES[tid]} for tid in techniques_ids]

    severity = random.choice(['Low', 'Medium', 'High', 'Critical'])
    status = random.choice(['Open', 'In Progress', 'Closed', 'Resolved'])
    
    num_affected_assets = random.randint(1, 5)
    affected_assets = [f"host-{random.randint(1, 500)}" for _ in range(num_affected_assets)]
    
    detection_method = random.choice([
        "IDS Alert", "SIEM Correlation", "Endpoint Detection",
        "User Report", "Threat Intelligence Match", "Manual Review",
        "Network Anomaly Detection"
    ])

    suspected_threat_group_id = random.choice(list(MITRE_ATTACK_GROUPS.keys()))
    suspected_threat_group_name = MITRE_ATTACK_GROUPS[suspected_threat_group_id]
    
    remediation_steps_templates = [
        f"Isolate affected hosts, remove malware, patch system. Block associated IOCs.",
        f"Block malicious IP, notify users, reset passwords. Review logs for {random.choice([t['name'] for t in techniques_observed])}.",
        f"Contain incident, restore from backup, conduct forensic analysis. Investigate for {suspected_threat_group_name} TTPs.",
        f"Filter traffic, mitigate DDoS, review logs for signs of {random.choice(['T1071.001', 'T1046'])}."
    ]
    remediation_steps = random.choice(remediation_steps_templates)
    
    analyst_notes_templates = [
        f"Initial assessment indicates {incident_type}. Observed techniques: {', '.join([t['name'] for t in techniques_observed])}. Suspected involvement of {suspected_threat_group_name}.",
        f"Incident classified as {incident_type}. Evidence suggests {suspected_threat_group_name} utilizing {random.choice([t['name'] for t in techniques_observed])}. Severity set to {severity}.",
        f"Detected via {detection_method}. Correlated with {random.choice(['T1078', 'T1059.001'])} activity. Further investigation required to confirm {suspected_threat_group_name} attribution."
    ]
    analyst_notes = random.choice(analyst_notes_templates)

    return {
        "incident_id": incident_id,
        "timestamp_detected": timestamp_detected,
        "incident_type": incident_type,
        "severity": severity,
        "status": status,
        "affected_assets": affected_assets,
        "detection_method": detection_method,
        "mitre_attack_techniques_observed": techniques_observed,
        "suspected_threat_group_id": suspected_threat_group_id,
        "suspected_threat_group_name": suspected_threat_group_name,
        "remediation_steps": remediation_steps,
        "analyst_notes": analyst_notes
    }

def generate_synthetic_data(num_network_logs=1000, num_iocs=100, num_incidents=50):
    """Generates a complete set of synthetic cybersecurity data."""
    start_date = datetime.datetime(2024, 1, 1, 0, 0, 0)
    end_date = datetime.datetime.now()

    network_logs = []
    for i in range(num_network_logs):
        is_suspicious = random.random() < 0.1 # 10% of logs are suspicious
        network_logs.append(generate_network_log(start_date, end_date, is_suspicious))

    iocs = [generate_threat_intelligence_ioc() for _ in range(num_iocs)]
    incidents = [generate_incident_report(start_date, end_date) for _ in range(num_incidents)]

    return {
        "network_logs": network_logs,
        "threat_intelligence_iocs": iocs,
        "incident_reports": incidents,
        "mitre_attack_definitions": {
            "techniques": MITRE_ATTACK_TECHNIQUES,
            "groups": MITRE_ATTACK_GROUPS
        }
    }

if __name__ == "__main__":
    # Generate a dataset with 5000 network logs, 200 IOCs, and 100 incidents
    synthetic_data = generate_synthetic_data(
        num_network_logs=5000,
        num_iocs=200,
        num_incidents=100
    )

    # Save the data to a JSON file
    output_filename = "cybersecurity_synthetic_data_with_mitre.json"
    with open(output_filename, 'w') as f:
        json.dump(synthetic_data, f, indent=4)

    print(f"Synthetic cybersecurity data generated and saved to {output_filename}")
    print(f"  - Network Logs: {len(synthetic_data['network_logs'])} entries")
    print(f"  - Threat Intelligence IOCs: {len(synthetic_data['threat_intelligence_iocs'])} entries")
    print(f"  - Incident Reports: {len(synthetic_data['incident_reports'])} entries")
    print(f"  - MITRE ATT&CK Definitions included.")
