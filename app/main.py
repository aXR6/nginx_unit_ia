import time
from scapy.all import sniff
from . import config, db
from .detection import Detector

def packet_callback(packet):
    if packet.haslayer('Raw'):
        payload = bytes(packet['Raw'].load).decode('latin-1', errors='ignore')
        result = detector.analyze(payload)
        db.save_log(
            config.NETWORK_INTERFACE,
            payload,
            result['severity'],
            result['anomaly'],
            result['nids'],
        )
        print(
            f"Anomaly: {result['anomaly']['label']} Severity: {result['severity']['label']} NIDS: {result['nids']['label']}"
        )

def run():
    db.init_db()
    print(f"Monitorando interface {config.NETWORK_INTERFACE}...")
    sniff(iface=config.NETWORK_INTERFACE, prn=packet_callback, store=False)

if __name__ == '__main__':
    detector = Detector()
    run()
