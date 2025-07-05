import logging
from scapy.all import AsyncSniffer
from scapy.layers.inet import IP
from . import config, db
from . import firewall
from .detection import Detector

# Global detector instance, lazily initialized in `run()`
logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

detector = None
sniffer = None


def packet_callback(packet):
    if packet.haslayer("Raw"):
        payload = bytes(packet["Raw"].load).decode("latin-1", errors="ignore")
        result = detector.analyze(payload)
        db.save_log(
            config.NETWORK_INTERFACE,
            payload,
            result["severity"],
            result["anomaly"],
            result["nids"],
        )
        logging.info(
            "Anomaly: %s Severity: %s NIDS: %s",
            result["anomaly"]["label"],
            result["severity"]["label"],
            result["nids"]["label"],
        )

        src_ip = None
        if packet.haslayer(IP):
            src_ip = packet[IP].src

        if src_ip:
            # simple heuristic: block if severity is high or anomaly not normal
            sev_label = str(result["severity"]["label"]).lower()
            anomaly_label = str(result["anomaly"]["label"]).lower()
            if sev_label == "high" or anomaly_label not in ("normal", "none"):
                if firewall.block_ip(src_ip):
                    reason = (
                        f"{result['anomaly']['label']} / {result['severity']['label']}"
                    )
                    db.save_blocked_ip(src_ip, reason)


def run():
    global detector, sniffer
    if detector is None:
        detector = Detector()
    db.init_db()
    # Defensive sanitization in case the interface contains unexpected NULs
    iface = config.NETWORK_INTERFACE.replace("\x00", "")
    logging.info("Monitorando interface %s...", iface)
    sniffer = AsyncSniffer(
        iface=iface,
        prn=packet_callback,
        store=False,
    )
    sniffer.start()
    sniffer.join()


def stop():
    global sniffer
    if sniffer and sniffer.running:
        sniffer.stop()
        sniffer = None


if __name__ == "__main__":
    run()
