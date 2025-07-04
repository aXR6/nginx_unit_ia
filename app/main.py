import time
from scapy.all import sniff
from . import config, db
from .detection import Detector

def packet_callback(packet):
    if packet.haslayer('Raw'):
        payload = bytes(packet['Raw'].load).decode('latin-1', errors='ignore')
        anomaly, severity, nids = detector.analyze(payload)
        db.save_log(config.NETWORK_INTERFACE, payload, severity, anomaly)
        print(f"Anomaly: {anomaly} Severity: {severity} NIDS: {nids}")

def run():
    db.init_db()
    print(f"Monitorando interface {config.NETWORK_INTERFACE}...")
    sniff(iface=config.NETWORK_INTERFACE, prn=packet_callback, store=False)

if __name__ == '__main__':
    detector = Detector()
    run()
