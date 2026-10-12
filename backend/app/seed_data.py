from sqlalchemy.orm import Session
from app.models import FirewallRule, SystemSetting
from app.database import Base, engine, SessionLocal

DEFAULT_RULES = [
    {
        "name": "Allow Localhost Traffic",
        "priority": 10,
        "action": "ALLOW",
        "protocol": "ANY",
        "src_ip": "127.0.0.1",
        "dst_ip": "127.0.0.1",
        "src_port": "ANY",
        "dst_port": "ANY",
        "enabled": True,
        "description": "Permit internal loopback traffic"
    },
    {
        "name": "Block Hostile Threat Subnet",
        "priority": 20,
        "action": "BLOCK",
        "protocol": "ANY",
        "src_ip": "198.51.100.0/24",
        "dst_ip": "ANY",
        "src_port": "ANY",
        "dst_port": "ANY",
        "enabled": True,
        "description": "Block documented hostile scanner network"
    },
    {
        "name": "Block Legacy Telnet (Port 23)",
        "priority": 30,
        "action": "BLOCK",
        "protocol": "TCP",
        "src_ip": "ANY",
        "dst_ip": "ANY",
        "src_port": "ANY",
        "dst_port": "23",
        "enabled": True,
        "description": "Block insecure unencrypted remote login"
    },
    {
        "name": "Block Microsoft SMB (Port 445)",
        "priority": 40,
        "action": "BLOCK",
        "protocol": "TCP",
        "src_ip": "ANY",
        "dst_ip": "ANY",
        "src_port": "ANY",
        "dst_port": "445",
        "enabled": True,
        "description": "Defend against SMB worms and EternalBlue"
    },
    {
        "name": "Allow Outbound DNS Queries",
        "priority": 50,
        "action": "ALLOW",
        "protocol": "UDP",
        "src_ip": "ANY",
        "dst_ip": "ANY",
        "src_port": "ANY",
        "dst_port": "53",
        "enabled": True,
        "description": "Permit standard domain name lookups"
    },
    {
        "name": "Allow Web Browsing (HTTP/HTTPS)",
        "priority": 60,
        "action": "ALLOW",
        "protocol": "TCP",
        "src_ip": "ANY",
        "dst_ip": "ANY",
        "src_port": "ANY",
        "dst_port": "80,443",
        "enabled": True,
        "description": "Permit outbound HTTP (80) and HTTPS (443) traffic"
    },
    {
        "name": "Allow Internal Subnet SSH",
        "priority": 70,
        "action": "ALLOW",
        "protocol": "TCP",
        "src_ip": "192.168.1.0/24",
        "dst_ip": "ANY",
        "src_port": "ANY",
        "dst_port": "22",
        "enabled": True,
        "description": "Allow SSH administration from local subnet only"
    },
    {
        "name": "Block External SSH Attempts",
        "priority": 80,
        "action": "BLOCK",
        "protocol": "TCP",
        "src_ip": "ANY",
        "dst_ip": "ANY",
        "src_port": "ANY",
        "dst_port": "22",
        "enabled": True,
        "description": "Prevent brute force attacks from the public internet"
    },
    {
        "name": "Allow Internal LAN ICMP Ping",
        "priority": 90,
        "action": "ALLOW",
        "protocol": "ICMP",
        "src_ip": "192.168.1.0/24",
        "dst_ip": "ANY",
        "src_port": "ANY",
        "dst_port": "ANY",
        "enabled": True,
        "description": "Permit ping diagnostics within the local network"
    }
]

DEFAULT_SETTINGS = [
    {"key": "DEFAULT_POLICY", "value": "BLOCK", "description": "Default firewall policy when no rule matches (BLOCK or ALLOW)"},
    {"key": "PORT_SCAN_THRESHOLD", "value": "5", "description": "Number of distinct ports accessed within window to trigger alert"},
    {"key": "PORT_SCAN_WINDOW_SECONDS", "value": "30", "description": "Sliding time window in seconds for port scan tracking"},
    {"key": "SYN_FLOOD_THRESHOLD", "value": "15", "description": "Number of SYN packets in window to trigger flood alert"},
    {"key": "SIMULATOR_RATE_MS", "value": "1000", "description": "Interval between synthetic packet bursts in milliseconds"},
    {"key": "SIMULATOR_BATCH_SIZE", "value": "2", "description": "Packets generated per simulation cycle"}
]

def seed_database(db: Session, reset_all: bool = False):
    Base.metadata.create_all(bind=engine)

    if reset_all:
        db.query(FirewallRule).delete()

    existing_rules_count = db.query(FirewallRule).count()
    if existing_rules_count == 0:
        for r_data in DEFAULT_RULES:
            rule = FirewallRule(**r_data)
            db.add(rule)

    for s_data in DEFAULT_SETTINGS:
        existing_s = db.query(SystemSetting).filter(SystemSetting.key == s_data["key"]).first()
        if not existing_s:
            s = SystemSetting(**s_data)
            db.add(s)

    db.commit()

if __name__ == "__main__":
    db = SessionLocal()
    seed_database(db)
    print("Database seeded successfully with default firewall rules and baseline configuration.")
    db.close()
