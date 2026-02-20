"""
nids_dashboard_enhanced.py 
Advanced Network Intrusion Detection System (NIDS) 

Change the Home_IP to your machines IP address before running.
Also Remember to to import these libraries if you don't have them already:
pip install scapy tkinter matplotlib sklearn geoip2
"""

import os
import socket
import sys
import time
import json
import sqlite3
import threading
from datetime import datetime, timedelta
from collections import defaultdict, deque
import hashlib
import re

# Networking & sniffing
from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, DNSQR, sniff, wrpcap

# GUI + plotting
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from threading import Thread, Lock
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

CAPTURE_IFACE = "Wi-Fi"

# ML (optional)
try:
    from sklearn.ensemble import IsolationForest
    import numpy as np
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

# GeoIP (optional)
GEOIP_ENABLED = False
try:
    import geoip2.database
    GEOIP_ENABLED = True
except Exception:
    pass

# -------------------------
# ENHANCED CONFIG
# -------------------------
HOME_IP = "10.68.157.177"  # CHANGE THIS TO YOUR MACHINE'S IP
DB_FILE = "nids_alerts_enhanced.db"
PCAP_DIR = "pcaps"
REPORTS_DIR = "reports"
RULES_FILE = "custom_rules.json"
PCAP_SAVE_ENABLED = True
AUTO_BLOCK_ENABLED = False
GEOIP_DB_PATH = "GeoLite2-City.mmdb"
SAMPLING_WINDOW = 10

# Enhanced thresholds with severity levels
THRESHOLDS = {
    "port_scan_ports": 12,
    "syn_rate": 20,
    "icmp_rate": 30,
    "udp_rate": 50,
    "ml_score_thresh": -0.2,
    "dns_rate": 40,
    "connection_rate": 100,
    "payload_size": 1500,
    "ddos_rate": 50,
    "ddos_window": 1.0,
    "beaconing_interval": 30.0,
    "beaconing_tolerance": 2.0,
    "exfil_icmp_size": 1000,
    "exfil_dns_size": 512
}

SEVERITY_LEVELS = {
    "CRITICAL": {"color": "#FF0000", "priority": 5},
    "HIGH": {"color": "#FF6B35", "priority": 4},
    "MEDIUM": {"color": "#FFA500", "priority": 3},
    "LOW": {"color": "#FFD700", "priority": 2},
    "INFO": {"color": "#3280DA", "priority": 1}
}

# Create directories
os.makedirs(PCAP_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

# -------------------------
# ENHANCED DATABASE
# -------------------------
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
db_lock = Lock()
cur = conn.cursor()

cur.execute("""CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    src TEXT,
    dst TEXT,
    proto TEXT,
    sport INTEGER,
    dport INTEGER,
    attack_type TEXT,
    severity TEXT,
    details TEXT,
    payload_hash TEXT,
    geo_info TEXT,
    blocked INTEGER DEFAULT 0
)""")

cur.execute("""CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id TEXT UNIQUE,
    src TEXT,
    dst TEXT,
    sport INTEGER,
    dport INTEGER,
    proto TEXT,
    start_ts TEXT,
    end_ts TEXT,
    packet_count INTEGER,
    byte_count INTEGER,
    flags TEXT
)""")

cur.execute("""CREATE TABLE IF NOT EXISTS dns_queries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    src TEXT,
    query TEXT,
    qtype TEXT,
    suspicious INTEGER DEFAULT 0
)""")

cur.execute("""CREATE TABLE IF NOT EXISTS performance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    packets_processed INTEGER,
    alerts_generated INTEGER,
    cpu_usage REAL,
    memory_usage REAL
)""")

conn.commit()

# -------------------------
# ENHANCED TRACKERS
# -------------------------
events = {
    "tcp_ports": defaultdict(lambda: deque(maxlen=1000)),
    "syn": defaultdict(lambda: deque(maxlen=1000)),
    "icmp": defaultdict(lambda: deque(maxlen=1000)),
    "udp": defaultdict(lambda: deque(maxlen=1000)),
    "dns": defaultdict(lambda: deque(maxlen=1000)),
    "connections": defaultdict(lambda: deque(maxlen=1000)),
    "ddos": defaultdict(lambda: deque(maxlen=1000)),
    "beaconing": defaultdict(list)
}

arp_watch = {}
arp_lock = Lock()

attack_summary = defaultdict(lambda: {
    "port_scan": {"count": 0, "severity": "LOW"},
    "syn": {"count": 0, "severity": "MEDIUM"},
    "icmp": {"count": 0, "severity": "LOW"},
    "udp": {"count": 0, "severity": "MEDIUM"},
    "ml": {"count": 0, "severity": "HIGH"},
    "dns": {"count": 0, "severity": "MEDIUM"},
    "ddos": {"count": 0, "severity": "CRITICAL"},
    "mitm": {"count": 0, "severity": "CRITICAL"},
    "beaconing": {"count": 0, "severity": "CRITICAL"},
    "exfiltration": {"count": 0, "severity": "CRITICAL"}
})

flows = {}
flow_lock = Lock()

proto_stats = defaultdict(int)
proto_lock = Lock()

packet_stats = {
    "total": 0,
    "tcp": 0,
    "udp": 0,
    "icmp": 0,
    "arp": 0,
    "other": 0,
    "malformed": 0
}
stats_lock = Lock()

ML_BUFFER_SIZE = 1000
ml_feature_buffer = deque(maxlen=ML_BUFFER_SIZE)
ml_model = None
ml_initialized = False

custom_rules = []

SUSPICIOUS_PATTERNS = {
    "sql_injection": [r"(\bUNION\b.*\bSELECT\b)", r"(\bOR\b.*=.*)", r"(;\s*DROP\s+TABLE)"],
    "xss": [r"(<script.*?>)", r"(javascript:)", r"(onerror\s*=)"],
    "command_injection": [r"(;\s*cat\s+)", r"(\|\s*nc\s+)", r"(&&\s*rm\s+)"],
    "path_traversal": [r"(\.\.\/)", r"(\.\.\\)"]
}

sniffer_thread = None
sniffer_stop_flag = threading.Event()

# -------------------------
# UTILITY FUNCTIONS
# -------------------------
def timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

def calculate_severity(attack_type, metrics):
    base_severity = {
        "PORT_SCAN": "LOW",
        "SYN_FLOOD": "HIGH",
        "ICMP_FLOOD": "MEDIUM",
        "UDP_FLOOD": "MEDIUM",
        "DNS_FLOOD": "MEDIUM",
        "ML_ANOMALY": "HIGH",
        "BLACKLIST": "CRITICAL",
        "PAYLOAD_SUSPICIOUS": "HIGH",
        "CONN_FLOOD": "MEDIUM",
        "DDOS": "CRITICAL",
        "MITM": "CRITICAL",
        "ARP_SPOOF": "CRITICAL",
        "TCP_ANOMALY": "MEDIUM",
        "BEACONING": "CRITICAL",
        "DATA_EXFILTRATION": "CRITICAL"
    }
    return base_severity.get(attack_type, "LOW")

def write_pcap(packet, label):
    if not PCAP_SAVE_ENABLED:
        return
    fname = os.path.join(PCAP_DIR, f"{label}_{datetime.now().strftime('%Y%m%d')}.pcap")
    try:
        wrpcap(fname, packet, append=True)
    except Exception as e:
        print(f"PCAP write error: {e}")

def save_alert_db(ts, src, dst, proto, sport, dport, attack_type, severity, details="", payload_hash="", geo_info=""):
    with db_lock:
        try:
            cur.execute("""INSERT INTO alerts 
                (ts, src, dst, proto, sport, dport, attack_type, severity, details, payload_hash, geo_info) 
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (ts, src, dst, proto, sport, dport, attack_type, severity, details, payload_hash, geo_info))
            conn.commit()
        except Exception as e:
            print(f"DB insert error: {e}")

def get_flow_id(src, dst, sport, dport, proto):
    return hashlib.md5(f"{src}:{sport}-{dst}:{dport}-{proto}".encode()).hexdigest()

def update_flow(src, dst, sport, dport, proto, packet_len, flags=""):
    flow_id = get_flow_id(src, dst, sport, dport, proto)
    ts = timestamp()
    
    with flow_lock:
        if flow_id not in flows:
            flows[flow_id] = {
                "src": src, "dst": dst, "sport": sport, "dport": dport,
                "proto": proto, "start_ts": ts, "end_ts": ts,
                "packet_count": 1, "byte_count": packet_len, "flags": flags
            }
        else:
            flows[flow_id]["end_ts"] = ts
            flows[flow_id]["packet_count"] += 1
            flows[flow_id]["byte_count"] += packet_len
            if flags:
                flows[flow_id]["flags"] += "," + flags

def check_payload_patterns(payload):
    if not payload:
        return None, None
    
    payload_str = str(payload)
    for pattern_type, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, payload_str, re.IGNORECASE):
                return pattern_type, pattern
    return None, None

def load_custom_rules():
    global custom_rules
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, 'r') as f:
                custom_rules = json.load(f)
        except Exception as e:
            print(f"Error loading rules: {e}")

def cleanup_events():
    """FIXED cleanup using time.time()"""
    now = time.time()
    cleanup_threshold = now - SAMPLING_WINDOW
    
    for event_type in events:
        for ip in list(events[event_type].keys()):
            if event_type == "beaconing":
                events[event_type][ip] = [ts for ts in events[event_type][ip] 
                                         if ts > cleanup_threshold]
            else:
                new_deque = deque(maxlen=1000)
                for item in events[event_type][ip]:
                    timestamp_val = item[1] if isinstance(item, tuple) else item
                    if timestamp_val > cleanup_threshold:
                        new_deque.append(item)
                events[event_type][ip] = new_deque
            
            if not events[event_type][ip]:
                del events[event_type][ip]

def calculate_packet_rate(key, event_type):
    packets = events[event_type].get(key, deque())
    
    if len(packets) < 2:
        return 0.0
    
    # For deques with timestamps directly
    if isinstance(packets[0], (int, float)):
        time_span = packets[-1] - packets[0]
    # For deques with tuples (port, timestamp)
    elif isinstance(packets[0], tuple):
        time_span = packets[-1][1] - packets[0][1]
    else:
        return 0.0
    
    if time_span <= 0:
        return 0.0
    
    return len(packets) / time_span

def check_beaconing(src, dst, now):
    """FIXED: Detect C2 beaconing using time.time()"""
    key = f"{src}->{dst}"
    
    if key not in events["beaconing"]:
        events["beaconing"][key] = []
    
    events["beaconing"][key].append(now)
    
    # Keep only last 5 minutes
    events["beaconing"][key] = [t for t in events["beaconing"][key] 
                                if now - t <= 300.0]
    
    timestamps = events["beaconing"][key]
    if len(timestamps) < 3:
        return False
    
    recent = timestamps[-5:] if len(timestamps) >= 5 else timestamps
    if len(recent) < 3:
        return False
    
    intervals = [recent[i+1] - recent[i] for i in range(len(recent)-1)]
    avg_interval = sum(intervals) / len(intervals)
    
    if abs(avg_interval - THRESHOLDS["beaconing_interval"]) < THRESHOLDS["beaconing_tolerance"]:
        variance = sum((x - avg_interval)**2 for x in intervals) / len(intervals)
        if variance < 5.0:
            return True
    
    return False

def check_data_exfiltration(pkt, proto, src, dst):
    packet_len = len(pkt)
    
    if proto == "ICMP" and packet_len > THRESHOLDS["exfil_icmp_size"]:
        return True, f"Large ICMP packet: {packet_len} bytes"
    
    if proto == "DNS" and packet_len > THRESHOLDS["exfil_dns_size"]:
        return True, f"Large DNS packet: {packet_len} bytes"
    
    return False, ""

# -------------------------
# ML FUNCTIONS
# -------------------------
def ml_train_if_needed():
    global ml_model, ml_initialized
    if ml_initialized or not SKLEARN_AVAILABLE:
        return
    
    if len(ml_feature_buffer) >= 100:
        try:
            X = np.array(list(ml_feature_buffer))
            model = IsolationForest(contamination=0.02, random_state=42, n_estimators=100)
            model.fit(X)
            ml_model = model
            ml_initialized = True
            print("ML model trained successfully")
        except Exception as e:
            print(f"ML training error: {e}")

def ml_predict(feature_vector):
    ml_feature_buffer.append(feature_vector)
    ml_train_if_needed()
    
    if SKLEARN_AVAILABLE and ml_model:
        try:
            score = ml_model.decision_function([feature_vector])[0]
            return score
        except Exception:
            return 0.0
    return 0.0

# -------------------------
# ENHANCED PACKET PROCESSING
# -------------------------
def process_packet(pkt, app):
    """FIXED: Proper NIDS filtering"""
    try:
        with stats_lock:
            packet_stats["total"] += 1
        
        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            
            # FIXED: Only skip localhost and self-to-self traffic
            if src.startswith('127.') or dst.startswith('127.'):
                return
            
            if src == HOME_IP and dst == HOME_IP:
                return
            
            # Now process ALL other traffic
            if TCP in pkt:
                handle_tcp(pkt, src, dst, app)
            elif UDP in pkt:
                handle_udp(pkt, src, dst, app)
            elif ICMP in pkt:
                handle_icmp(pkt, src, dst, app)
            
            if SKLEARN_AVAILABLE:
                check_ml_anomaly(pkt, src, dst, app)
        
        if ARP in pkt:
            handle_arp(pkt, app)
        
        if packet_stats["total"] % 100 == 0:
            cleanup_events()
        
    except Exception as e:
        with stats_lock:
            packet_stats["malformed"] += 1
        print(f"Packet processing error: {e}")

def handle_tcp(pkt, src, dst, app):
    """FIXED TCP handling"""
    with stats_lock:
        packet_stats["tcp"] += 1
    with proto_lock:
        proto_stats["TCP"] += 1
    
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport
    flags = pkt[TCP].flags
    now = time.time()
    
    update_flow(src, dst, sport, dport, "TCP", len(pkt), str(flags))
    
    # TCP FLAGS DETECTION
    if flags & 0x29 == 0x29:
        app.generate_alert(src, dst, "TCP", sport, dport, "TCP_ANOMALY", "MEDIUM",
                          "Christmas Tree packet detected")
        write_pcap(pkt, "tcp_anomaly_christmas")
    elif flags == 0:
        app.generate_alert(src, dst, "TCP", sport, dport, "TCP_ANOMALY", "MEDIUM",
                          "Null packet detected")
        write_pcap(pkt, "tcp_anomaly_null")
    
    # DDOS DETECTION
    key = f"{src}->{dst}"
    events["ddos"][key].append(now)
    rate = calculate_packet_rate(key, "ddos")
    if rate > THRESHOLDS["ddos_rate"]:
        app.generate_alert(src, dst, "TCP", sport, dport, "DDOS", "CRITICAL",
                          f"DDoS detected: {rate:.1f} pps")
        write_pcap(pkt, "ddos")
    
    # SYN FLOOD
    if flags & 0x02:
        events["syn"][src].append(now)
        # Clean old entries
        events["syn"][src] = deque([t for t in events["syn"][src] if now - t <= 1.0],
                                   maxlen=1000)
        
        if len(events["syn"][src]) > app.syn_var.get():
            app.generate_alert(src, dst, "TCP", sport, dport, "SYN_FLOOD", "HIGH",
                              f"SYN flood: {len(events['syn'][src])} packets/sec")
            write_pcap(pkt, "syn_flood")
    
    # PORT SCAN
    events["tcp_ports"][src].append((dport, now))
    events["tcp_ports"][src] = deque([(p, t) for p, t in events["tcp_ports"][src] 
                                      if now - t <= 60.0],
                                     maxlen=1000)
    
    unique_ports = len(set(p[0] for p in events["tcp_ports"][src]))
    if unique_ports > app.port_scan_var.get():
        app.generate_alert(src, dst, "TCP", sport, dport, "PORT_SCAN", "LOW",
                          f"Port scan: {unique_ports} unique ports")
        write_pcap(pkt, "port_scan")
    
    # BEACONING
    if check_beaconing(src, dst, now):
        app.generate_alert(src, dst, "TCP", sport, dport, "BEACONING", "CRITICAL",
                          "C2 beaconing detected")
        write_pcap(pkt, "beaconing")
    
    # PAYLOAD CHECK
    if pkt.haslayer('Raw'):
        payload = bytes(pkt['Raw'])
        pattern_type, pattern = check_payload_patterns(payload)
        if pattern_type:
            app.generate_alert(src, dst, "TCP", sport, dport, "PAYLOAD_SUSPICIOUS", "HIGH",
                              f"Suspicious payload: {pattern_type}")
            write_pcap(pkt, "payload_suspicious")

def handle_udp(pkt, src, dst, app):
    """FIXED UDP handling"""
    with stats_lock:
        packet_stats["udp"] += 1
    with proto_lock:
        proto_stats["UDP"] += 1
    
    sport = pkt[UDP].sport
    dport = pkt[UDP].dport
    now = time.time()
    
    update_flow(src, dst, sport, dport, "UDP", len(pkt))
    
    # DDOS
    key = f"{src}->{dst}"
    events["ddos"][key].append(now)
    rate = calculate_packet_rate(key, "ddos")
    if rate > THRESHOLDS["ddos_rate"]:
        app.generate_alert(src, dst, "UDP", sport, dport, "DDOS", "CRITICAL",
                          f"UDP DDoS: {rate:.1f} pps")
        write_pcap(pkt, "ddos_udp")
    
    # UDP FLOOD
    events["udp"][src].append((dport, now))
    events["udp"][src] = deque([(p, t) for p, t in events["udp"][src] 
                                if now - t <= 60.0],
                               maxlen=1000)
    
    if len(events["udp"][src]) > app.udp_var.get():
        app.generate_alert(src, dst, "UDP", sport, dport, "UDP_FLOOD", "MEDIUM",
                          f"UDP flood: {len(events['udp'][src])} packets")
        write_pcap(pkt, "udp_flood")
    
    # DNS
    if DNS in pkt and pkt.haslayer(DNSQR):
        query = pkt[DNSQR].qname.decode('utf-8', errors='ignore')
        events["dns"][src].append((query, now))
        
        # Exfiltration check
        is_exfil, exfil_details = check_data_exfiltration(pkt, "DNS", src, dst)
        if is_exfil:
            app.generate_alert(src, dst, "UDP", sport, dport, "DATA_EXFILTRATION", "CRITICAL",
                              f"DNS exfiltration: {exfil_details}")
            write_pcap(pkt, "exfiltration_dns")
        
        # DNS flood
        events["dns"][src] = deque([(q, t) for q, t in events["dns"][src] 
                                    if now - t <= 60.0],
                                   maxlen=1000)
        
        if len(events["dns"][src]) > app.dns_var.get():
            app.generate_alert(src, dst, "UDP", sport, dport, "DNS_FLOOD", "MEDIUM",
                              f"DNS flood: {len(events['dns'][src])} queries")
            write_pcap(pkt, "dns_flood")
        
        # Log to DB
        with db_lock:
            cur.execute("INSERT INTO dns_queries (ts, src, query, qtype) VALUES (?,?,?,?)",
                      (timestamp(), src, query, "A"))
            conn.commit()

def handle_icmp(pkt, src, dst, app):
    """FIXED ICMP handling"""
    with stats_lock:
        packet_stats["icmp"] += 1
    with proto_lock:
        proto_stats["ICMP"] += 1
    
    now = time.time()
    
    # DDOS
    key = f"{src}->{dst}"
    events["ddos"][key].append(now)
    rate = calculate_packet_rate(key, "ddos")
    if rate > THRESHOLDS["ddos_rate"]:
        app.generate_alert(src, dst, "ICMP", 0, 0, "DDOS", "CRITICAL",
                          f"ICMP DDoS: {rate:.1f} pps")
        write_pcap(pkt, "ddos_icmp")
    
    # Exfiltration
    is_exfil, exfil_details = check_data_exfiltration(pkt, "ICMP", src, dst)
    if is_exfil:
        app.generate_alert(src, dst, "ICMP", 0, 0, "DATA_EXFILTRATION", "CRITICAL",
                          f"ICMP exfiltration: {exfil_details}")
        write_pcap(pkt, "exfiltration_icmp")
    
    # ICMP FLOOD
    events["icmp"][src].append((dst, now))
    events["icmp"][src] = deque([(d, t) for d, t in events["icmp"][src] 
                                 if now - t <= 60.0],
                                maxlen=1000)
    
    if len(events["icmp"][src]) > app.icmp_var.get():
        app.generate_alert(src, dst, "ICMP", 0, 0, "ICMP_FLOOD", "MEDIUM",
                          f"ICMP flood: {len(events['icmp'][src])} packets")
        write_pcap(pkt, "icmp_flood")

def handle_arp(pkt, app):
    """MITM Detection"""
    with stats_lock:
        packet_stats["arp"] += 1
    with proto_lock:
        proto_stats["ARP"] += 1
    
    if ARP in pkt:
        arp_src_ip = pkt[ARP].psrc
        arp_src_mac = pkt[ARP].hwsrc
        arp_op = pkt[ARP].op
        
        if arp_op == 2:
            with arp_lock:
                if arp_src_ip in arp_watch:
                    old_mac = arp_watch[arp_src_ip]
                    if old_mac != arp_src_mac:
                        app.generate_alert(arp_src_ip, "BROADCAST", "ARP", 0, 0, "MITM", "CRITICAL",
                                          f"ARP spoofing! IP {arp_src_ip} changed MAC {old_mac} to {arp_src_mac}")
                        write_pcap(pkt, "mitm_arp_spoof")
                        arp_watch[arp_src_ip] = arp_src_mac
                else:
                    arp_watch[arp_src_ip] = arp_src_mac

def check_ml_anomaly(pkt, src, dst, app):
    """ML-based anomaly detection"""
    if not SKLEARN_AVAILABLE:
        return
    
    try:
        features = [
            len(pkt),
            pkt[IP].ttl if IP in pkt else 0,
            pkt[TCP].sport if TCP in pkt else 0,
            pkt[TCP].dport if TCP in pkt else 0,
            len(events["tcp_ports"].get(src, [])),
            len(events["syn"].get(src, []))
        ]
        
        score = ml_predict(features)
        if score < THRESHOLDS["ml_score_thresh"]:
            proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "ICMP"
            sport = pkt[TCP].sport if TCP in pkt else 0
            dport = pkt[TCP].dport if TCP in pkt else 0
            app.generate_alert(src, dst, proto, sport, dport, "ML_ANOMALY", "HIGH",
                              f"ML anomaly: score={score:.3f}")
    except Exception as e:
        pass

# ========== END OF PART 1 ==========
# PART 2 (GUI) will continue from here in the next response

"""
PART 2 - GUI CODE ONLY
ADD THIS AFTER PART 1 (after the check_ml_anomaly function)

This is the EnhancedNIDSApp class and main() function
"""

# -------------------------
# ENHANCED GUI APPLICATION
# -------------------------
class EnhancedNIDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced NIDS - Production-Ready Dashboard")
        self.root.geometry("1400x800")
        self.root.configure(bg='#1e1e1e')
        
        # Variables
        self.is_running = False
        self.monitoring_active = False
        self.total_alerts = 0
        self.alert_queue = deque(maxlen=1000)
        
        # Threshold variables
        self.port_scan_var = tk.IntVar(value=THRESHOLDS["port_scan_ports"])
        self.syn_var = tk.IntVar(value=THRESHOLDS["syn_rate"])
        self.icmp_var = tk.IntVar(value=THRESHOLDS["icmp_rate"])
        self.udp_var = tk.IntVar(value=THRESHOLDS["udp_rate"])
        self.dns_var = tk.IntVar(value=THRESHOLDS["dns_rate"])
        
        # Plotting data
        self.plot_data = {
            "time": deque(maxlen=60),
            "alerts": deque(maxlen=60),
            "packets": deque(maxlen=60),
            "protocols": {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}
        }
        
        self.setup_ui()
        self.is_running = True
        self.start_ui_updates()
        
    def setup_ui(self):
        """Setup the enhanced UI with multiple tabs"""
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background='#2d2d2d', borderwidth=0)
        style.configure('TNotebook.Tab', background='#3d3d3d', foreground='white', padding=[10, 5])
        style.map('TNotebook.Tab', background=[('selected', '#4a4a4a')])
        
        # Top toolbar
        self.create_toolbar()
        
        # Main notebook with tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_alerts_tab()
        self.create_network_tab()
        self.create_analysis_tab()
        self.create_config_tab()
        
        # Status bar
        self.create_statusbar()
        
    def create_toolbar(self):
        """Create top toolbar with controls"""
        toolbar = tk.Frame(self.root, bg='#2d2d2d', height=50)
        toolbar.pack(side=tk.TOP, fill=tk.X)
        
        # Title
        title = tk.Label(toolbar, text="🛡️ Advanced NIDS - Production Ready", 
                        font=('Arial', 16, 'bold'), bg='#2d2d2d', fg='#4a9eff')
        title.pack(side=tk.LEFT, padx=20, pady=10)
        
        # START/STOP button (main feature)
        btn_frame = tk.Frame(toolbar, bg='#2d2d2d')
        btn_frame.pack(side=tk.RIGHT, padx=10)
        
        self.start_stop_btn = tk.Button(btn_frame, text="▶️ START MONITORING", 
                                        command=self.toggle_monitoring,
                                        bg='#4CAF50', fg='white', relief=tk.FLAT, 
                                        padx=20, pady=8, font=('Arial', 10, 'bold'))
        self.start_stop_btn.pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="📊 Export", command=self.export_report,
                 bg='#4a4a4a', fg='white', relief=tk.FLAT, padx=10).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="🔄 Refresh", command=self.refresh_all,
                 bg='#4a4a4a', fg='white', relief=tk.FLAT, padx=10).pack(side=tk.LEFT, padx=5)
    
    def toggle_monitoring(self):
        """Start/Stop packet monitoring"""
        if not self.monitoring_active:
            # START monitoring
            self.monitoring_active = True
            self.start_stop_btn.config(text="⏸️ STOP MONITORING", bg='#f44336')
            self.status_label.config(text="Status: Monitoring Active ✓", fg='#4CAF50')
            
            # Start capture thread
            global sniffer_thread, sniffer_stop_flag
            sniffer_stop_flag.clear()
            sniffer_thread = Thread(target=self.capture_packets, daemon=True)
            sniffer_thread.start()
        else:
            # STOP monitoring
            self.monitoring_active = False
            self.start_stop_btn.config(text="▶️ START MONITORING", bg='#4CAF50')
            self.status_label.config(text="Status: Monitoring Stopped", fg='#FFA500')
            
            # Signal stop
            sniffer_stop_flag.set()

    def capture_packets(self):
        """Packet capture with debugging"""
        print("=" * 60)
        print("🔍 STARTING PACKET CAPTURE")
        print(f"📡 Interface: {CAPTURE_IFACE}")
        print(f"🏠 Home IP: {HOME_IP}")
        print(f"✅ Monitoring ALL traffic (attacks TO/FROM/BETWEEN devices)")
        print("=" * 60)
        
        packet_count = 0
        
        def packet_callback(pkt):
            nonlocal packet_count
            packet_count += 1
            
            # Debug every 50 packets
            if packet_count % 50 == 0:
                print(f"📦 Processed {packet_count} packets | Alerts: {self.total_alerts}")
            
            process_packet(pkt, self)
        
        try:
            sniff(
                iface=CAPTURE_IFACE,
                prn=packet_callback,
                store=False,
                stop_filter=lambda x: sniffer_stop_flag.is_set()
            )
        except Exception as e:
            print(f"❌ Capture error: {e}")
            self.monitoring_active = False
            self.root.after(0, lambda: self.start_stop_btn.config(
                text="▶️ START MONITORING", bg='#4CAF50'))
    
    def create_dashboard_tab(self):
        """Main dashboard with live statistics"""
        tab = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(tab, text="📊 Dashboard")
        
        # Top stats cards
        stats_frame = tk.Frame(tab, bg='#1e1e1e')
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.stats_cards = {}
        cards = [
            ("Total Alerts", "total_alerts", "#FF6B35"),
            ("Critical", "critical", "#FF0000"),
            ("Packets Processed", "packets", "#4A90E2"),
            ("Active Flows", "flows", "#50C878")
        ]
        
        for i, (title, key, color) in enumerate(cards):
            card = self.create_stat_card(stats_frame, title, "0", color)
            card.grid(row=0, column=i, padx=10, pady=5, sticky='ew')
            self.stats_cards[key] = card
            stats_frame.columnconfigure(i, weight=1)
        
        # Charts frame
        chart_frame = tk.Frame(tab, bg='#1e1e1e')
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left: Alert timeline
        left_chart = tk.Frame(chart_frame, bg='#2d2d2d')
        left_chart.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        tk.Label(left_chart, text="Alert Timeline (Last 60s)", 
                font=('Arial', 12, 'bold'), bg='#2d2d2d', fg='white').pack(pady=5)
        
        self.fig_timeline = Figure(figsize=(6, 4), facecolor='#2d2d2d')
        self.ax_timeline = self.fig_timeline.add_subplot(111)
        self.ax_timeline.set_facecolor('#1e1e1e')
        self.canvas_timeline = FigureCanvasTkAgg(self.fig_timeline, left_chart)
        self.canvas_timeline.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        
        # Right: Protocol distribution
        right_chart = tk.Frame(chart_frame, bg='#2d2d2d')
        right_chart.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        tk.Label(right_chart, text="Protocol Distribution", 
                font=('Arial', 12, 'bold'), bg='#2d2d2d', fg='white').pack(pady=5)
        
        self.fig_proto = Figure(figsize=(6, 4), facecolor='#2d2d2d')
        self.ax_proto = self.fig_proto.add_subplot(111)
        self.canvas_proto = FigureCanvasTkAgg(self.fig_proto, right_chart)
        self.canvas_proto.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_stat_card(self, parent, title, value, color):
        """Create a statistic card"""
        card = tk.Frame(parent, bg='#2d2d2d', relief=tk.RAISED, borderwidth=2)
        
        tk.Label(card, text=title, font=('Arial', 10), 
                bg='#2d2d2d', fg='#888').pack(pady=(10, 5))
        
        value_label = tk.Label(card, text=value, font=('Arial', 24, 'bold'), 
                              bg='#2d2d2d', fg=color)
        value_label.pack(pady=(0, 10))
        
        card.value_label = value_label
        return card
    
    def create_alerts_tab(self):
        """Alerts monitoring tab"""
        tab = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(tab, text="🚨 Alerts")
        
        # Filters
        filter_frame = tk.Frame(tab, bg='#2d2d2d')
        filter_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(filter_frame, text="Filter by Severity:", 
                bg='#2d2d2d', fg='white').pack(side=tk.LEFT, padx=5)
        
        self.severity_filter = ttk.Combobox(filter_frame, 
                                           values=["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
                                           state='readonly', width=15)
        self.severity_filter.set("ALL")
        self.severity_filter.pack(side=tk.LEFT, padx=5)
        self.severity_filter.bind('<<ComboboxSelected>>', lambda e: self.refresh_alerts())
        
        tk.Button(filter_frame, text="Clear Alerts", command=self.clear_alerts,
                 bg='#f44336', fg='white', relief=tk.FLAT, padx=10).pack(side=tk.RIGHT, padx=5)
        
        # Alert list
        list_frame = tk.Frame(tab, bg='#1e1e1e')
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview
        columns = ('Time', 'Source', 'Dest', 'Protocol', 'Type', 'Severity', 'Details')
        self.alert_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            self.alert_tree.heading(col, text=col)
            width = 150 if col == 'Details' else 120 if col == 'Time' else 100
            self.alert_tree.column(col, width=width)
        
        # Scrollbars
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.alert_tree.yview)
        hsb = ttk.Scrollbar(list_frame, orient="horizontal", command=self.alert_tree.xview)
        self.alert_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        self.alert_tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        
        list_frame.grid_rowconfigure(0, weight=1)
        list_frame.grid_columnconfigure(0, weight=1)
        
        # Color tags
        self.alert_tree.tag_configure('CRITICAL', background='#4a0000')
        self.alert_tree.tag_configure('HIGH', background='#4a2000')
        self.alert_tree.tag_configure('MEDIUM', background='#4a4a00')
        self.alert_tree.tag_configure('LOW', background='#2d2d2d')
    
    def create_network_tab(self):
        """Network flows and connections tab"""
        tab = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(tab, text="🌐 Network")
        
        # Top stats
        stats_frame = tk.Frame(tab, bg='#2d2d2d')
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(stats_frame, text="Active Network Flows", 
                font=('Arial', 14, 'bold'), bg='#2d2d2d', fg='white').pack(pady=10)
        
        # Flow list
        list_frame = tk.Frame(tab, bg='#1e1e1e')
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        columns = ('Flow ID', 'Source', 'Dest', 'Protocol', 'Packets', 'Bytes', 'Duration')
        self.flow_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.flow_tree.heading(col, text=col)
            self.flow_tree.column(col, width=120)
        
        vsb = ttk.Scrollbar(list_frame, orient="vertical", command=self.flow_tree.yview)
        self.flow_tree.configure(yscrollcommand=vsb.set)
        
        self.flow_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Refresh button
        tk.Button(tab, text="Refresh Flows", command=self.refresh_flows,
                 bg='#4a90e2', fg='white', relief=tk.FLAT, padx=20, pady=5).pack(pady=10)
    
    def create_analysis_tab(self):
        """Advanced analysis tab"""
        tab = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(tab, text="📈 Analysis")
        
        # Attack summary
        summary_frame = tk.Frame(tab, bg='#2d2d2d')
        summary_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(summary_frame, text="Attack Type Distribution", 
                font=('Arial', 14, 'bold'), bg='#2d2d2d', fg='white').pack(pady=10)
        
        self.analysis_text = scrolledtext.ScrolledText(summary_frame, height=20, width=80,
                                                       bg='#1e1e1e', fg='white', 
                                                       font=('Courier', 10))
        self.analysis_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Button(tab, text="Generate Analysis Report", command=self.generate_analysis,
                 bg='#4a90e2', fg='white', relief=tk.FLAT, padx=20, pady=5).pack(pady=10)
    
    def create_config_tab(self):
        """Configuration tab"""
        tab = tk.Frame(self.notebook, bg='#1e1e1e')
        self.notebook.add(tab, text="⚙️ Config")
        
        # Threshold settings
        config_frame = tk.Frame(tab, bg='#2d2d2d')
        config_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        tk.Label(config_frame, text="Detection Thresholds", 
                font=('Arial', 14, 'bold'), bg='#2d2d2d', fg='white').pack(pady=10)
        
        # Threshold controls
        thresholds = [
            ("Port Scan Threshold:", self.port_scan_var, 1, 50),
            ("SYN Flood Threshold:", self.syn_var, 10, 100),
            ("ICMP Flood Threshold:", self.icmp_var, 10, 100),
            ("UDP Flood Threshold:", self.udp_var, 10, 150),
            ("DNS Flood Threshold:", self.dns_var, 10, 100)
        ]
        
        for i, (label, var, min_val, max_val) in enumerate(thresholds):
            frame = tk.Frame(config_frame, bg='#2d2d2d')
            frame.pack(fill=tk.X, padx=20, pady=5)
            
            tk.Label(frame, text=label, bg='#2d2d2d', fg='white', 
                    width=25, anchor='w').pack(side=tk.LEFT)
            
            scale = tk.Scale(frame, from_=min_val, to=max_val, orient=tk.HORIZONTAL,
                           variable=var, bg='#2d2d2d', fg='white', 
                           highlightthickness=0, length=300)
            scale.pack(side=tk.LEFT, padx=10)
            
            tk.Label(frame, textvariable=var, bg='#2d2d2d', fg='white', 
                    width=5).pack(side=tk.LEFT)
        
        # System info
        info_frame = tk.Frame(config_frame, bg='#1e1e1e')
        info_frame.pack(fill=tk.X, padx=20, pady=20)
        
        info_text = f"""
System Configuration:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Home IP: {HOME_IP}
Database: {DB_FILE}
PCAP Directory: {PCAP_DIR}
ML Enabled: {SKLEARN_AVAILABLE}
GeoIP Enabled: {GEOIP_ENABLED}
Auto-Block: {AUTO_BLOCK_ENABLED}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
        
        tk.Label(info_frame, text=info_text, bg='#1e1e1e', fg='#4a90e2',
                font=('Courier', 10), justify=tk.LEFT).pack(pady=10)
    
    def create_statusbar(self):
        """Create bottom status bar"""
        statusbar = tk.Frame(self.root, bg='#2d2d2d', height=30)
        statusbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_label = tk.Label(statusbar, text="Status: Ready", 
                                     bg='#2d2d2d', fg='#4CAF50',
                                     font=('Arial', 9))
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        self.packet_label = tk.Label(statusbar, text="Packets: 0", 
                                     bg='#2d2d2d', fg='white',
                                     font=('Arial', 9))
        self.packet_label.pack(side=tk.RIGHT, padx=10)
    
    def generate_alert(self, src, dst, proto, sport, dport, attack_type, severity, details=""):
        """Generate and log an alert - WITH DEBUG OUTPUT"""
        ts = timestamp()
        
        # DEBUG OUTPUT - CRITICAL FOR SEEING ALERTS
        print(f"🚨 ALERT: {severity} | {attack_type} | {src} → {dst} | {details[:50]}")
        
        # Save to database
        save_alert_db(ts, src, dst, proto, sport, dport, attack_type, severity, details)
        
        # Update summary
        attack_summary[src][attack_type.lower()]["count"] += 1
        attack_summary[src][attack_type.lower()]["severity"] = severity
        
        # Add to queue
        alert = {
            "time": ts,
            "src": src,
            "dst": dst,
            "proto": proto,
            "sport": sport,
            "dport": dport,
            "type": attack_type,
            "severity": severity,
            "details": details
        }
        self.alert_queue.append(alert)
        self.total_alerts += 1
        
        # Update UI (thread-safe)
        self.root.after(0, lambda: self.add_alert_to_tree(alert))
    
    def add_alert_to_tree(self, alert):
        """Add alert to treeview"""
        try:
            values = (
                alert["time"],
                alert["src"],
                alert["dst"],
                alert["proto"],
                alert["type"],
                alert["severity"],
                alert["details"][:50]
            )
            self.alert_tree.insert('', 0, values=values, tags=(alert["severity"],))
        except Exception as e:
            print(f"UI update error: {e}")
    
    def refresh_alerts(self):
        """Refresh alert list with filter"""
        self.alert_tree.delete(*self.alert_tree.get_children())
        
        filter_severity = self.severity_filter.get()
        
        for alert in reversed(list(self.alert_queue)):
            if filter_severity == "ALL" or alert["severity"] == filter_severity:
                self.add_alert_to_tree(alert)
    
    def clear_alerts(self):
        """Clear all alerts"""
        if messagebox.askyesno("Confirm", "Clear all alerts?"):
            self.alert_queue.clear()
            self.alert_tree.delete(*self.alert_tree.get_children())
            self.total_alerts = 0
    
    def refresh_flows(self):
        """Refresh network flows display"""
        self.flow_tree.delete(*self.flow_tree.get_children())
        
        with flow_lock:
            for flow_id, flow_data in list(flows.items())[:100]:
                try:
                    start = datetime.strptime(flow_data["start_ts"], "%Y-%m-%d %H:%M:%S.%f")
                    end = datetime.strptime(flow_data["end_ts"], "%Y-%m-%d %H:%M:%S.%f")
                    duration = (end - start).total_seconds()
                    
                    values = (
                        flow_id[:12],
                        f"{flow_data['src']}:{flow_data['sport']}",
                        f"{flow_data['dst']}:{flow_data['dport']}",
                        flow_data['proto'],
                        flow_data['packet_count'],
                        flow_data['byte_count'],
                        f"{duration:.2f}s"
                    )
                    self.flow_tree.insert('', 'end', values=values)
                except Exception:
                    pass
    
    def generate_analysis(self):
        """Generate attack analysis report"""
        self.analysis_text.delete(1.0, tk.END)
        
        report = f"""
╔══════════════════════════════════════════════════════════════╗
║           NETWORK INTRUSION DETECTION ANALYSIS               ║
║                  Generated: {timestamp()}              ║
╚══════════════════════════════════════════════════════════════╝

SUMMARY STATISTICS:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Alerts: {self.total_alerts}
Total Packets: {packet_stats['total']}
Active Flows: {len(flows)}

PACKET BREAKDOWN:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TCP:      {packet_stats['tcp']:>8}
UDP:      {packet_stats['udp']:>8}
ICMP:     {packet_stats['icmp']:>8}
ARP:      {packet_stats['arp']:>8}
Other:    {packet_stats['other']:>8}
Malformed:{packet_stats['malformed']:>8}

TOP ATTACKERS (by alert count):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        
        # Sort attackers by total alerts
        sorted_attackers = sorted(
            attack_summary.items(),
            key=lambda x: sum(v["count"] for v in x[1].values()),
            reverse=True
        )[:10]
        
        for ip, attacks in sorted_attackers:
            total = sum(v["count"] for v in attacks.values())
            report += f"\n{ip:>15} - {total:>5} alerts\n"
            
            for attack_type, data in attacks.items():
                if data["count"] > 0:
                    report += f"  ↳ {attack_type.upper():20} {data['count']:>5} ({data['severity']})\n"
        
        report += "\n" + "━" * 64 + "\n"
        
        self.analysis_text.insert(1.0, report)
    
    def export_report(self):
        """Export analysis report to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialdir=REPORTS_DIR,
            initialfile=f"nids_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if filename:
            try:
                self.generate_analysis()
                with open(filename, 'w') as f:
                    f.write(self.analysis_text.get(1.0, tk.END))
                messagebox.showinfo("Success", f"Report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {e}")
    
    def refresh_all(self):
        """Refresh all displays"""
        self.refresh_alerts()
        self.refresh_flows()
        self.generate_analysis()
    
    def update_plots(self):
        """Update dashboard charts"""
        try:
            # Update timeline
            self.plot_data["time"].append(datetime.now())
            self.plot_data["alerts"].append(len(self.alert_queue))
            self.plot_data["packets"].append(packet_stats["total"])
            
            # Clear and redraw timeline
            self.ax_timeline.clear()
            if len(self.plot_data["time"]) > 1:
                times = [(t - self.plot_data["time"][0]).total_seconds() 
                        for t in self.plot_data["time"]]
                self.ax_timeline.plot(times, list(self.plot_data["alerts"]), 
                                     color='#FF6B35', linewidth=2, label='Alerts')
                self.ax_timeline.set_xlabel('Time (s)', color='white')
                self.ax_timeline.set_ylabel('Alert Count', color='white')
                self.ax_timeline.tick_params(colors='white')
                self.ax_timeline.legend(facecolor='#2d2d2d', edgecolor='white', 
                                       labelcolor='white')
                self.ax_timeline.grid(True, alpha=0.3, color='white')
            
            self.canvas_timeline.draw()
            
            # Update protocol pie chart
            self.ax_proto.clear()
            with proto_lock:
                labels = list(proto_stats.keys())
                sizes = list(proto_stats.values())
            
            if sum(sizes) > 0:
                colors = ['#FF6B35', '#4A90E2', '#50C878', '#FFD700', '#FF1493']
                self.ax_proto.pie(sizes, labels=labels, autopct='%1.1f%%', 
                                 colors=colors, startangle=90)
                self.ax_proto.set_facecolor('#2d2d2d')
            
            self.canvas_proto.draw()
            
        except Exception as e:
            print(f"Plot update error: {e}")
    
    def update_stats_cards(self):
        """Update statistics cards"""
        try:
            self.stats_cards["total_alerts"].value_label.config(text=str(self.total_alerts))
            
            critical_count = sum(1 for a in self.alert_queue if a["severity"] == "CRITICAL")
            self.stats_cards["critical"].value_label.config(text=str(critical_count))
            
            self.stats_cards["packets"].value_label.config(text=str(packet_stats["total"]))
            
            self.stats_cards["flows"].value_label.config(text=str(len(flows)))
            
            # Update status bar
            self.packet_label.config(text=f"Packets: {packet_stats['total']}")
            
        except Exception as e:
            print(f"Stats update error: {e}")
    
    def start_ui_updates(self):
        """Start periodic UI updates"""
        def update_loop():
            if self.is_running:
                try:
                    self.update_stats_cards()
                    self.update_plots()
                except Exception as e:
                    print(f"Update loop error: {e}")
                
                # Schedule next update
                self.root.after(1000, update_loop)
        
        # Start the update loop
        update_loop()
    
    def on_closing(self):
        """Handle window closing"""
        if messagebox.askokcancel("Quit", "Stop monitoring and exit?"):
            self.is_running = False
            sniffer_stop_flag.set()
            
            # Close database
            try:
                conn.close()
            except Exception:
                pass
            
            self.root.destroy()


# -------------------------
# MAIN FUNCTION
# -------------------------
def main():
    """Main entry point"""
    print("=" * 70)
    print("🛡️  ADVANCED NETWORK INTRUSION DETECTION SYSTEM (NIDS)")
    print("=" * 70)
    print(f"📅 Started: {timestamp()}")
    print(f"🏠 Home IP: {HOME_IP}")
    print(f"📡 Capture Interface: {CAPTURE_IFACE}")
    print(f"💾 Database: {DB_FILE}")
    print(f"📁 PCAP Directory: {PCAP_DIR}")
    print(f"🤖 ML Enabled: {SKLEARN_AVAILABLE}")
    print(f"🌍 GeoIP Enabled: {GEOIP_ENABLED}")
    print("=" * 70)
    print("\n⚠️  IMPORTANT CONFIGURATION:")
    print(f"   - Ensure HOME_IP is set correctly: {HOME_IP}")
    print(f"   - Ensure CAPTURE_IFACE matches your network adapter: {CAPTURE_IFACE}")
    print("\n✅ Starting GUI Dashboard...")
    print("=" * 70)
    
    # Load custom rules
    load_custom_rules()
    
    # Create GUI
    root = tk.Tk()
    app = EnhancedNIDSApp(root)
    
    # Handle window close
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    
    # Start GUI
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user. Shutting down...")
        sniffer_stop_flag.set()
        try:
            conn.close()
        except Exception:
            pass
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)