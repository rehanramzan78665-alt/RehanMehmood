from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, Raw, get_if_list
from datetime import datetime
import string

# ---------- Settings (edit these) ----------
PACKET_COUNT = 20     # number of packets to capture (0 = run until Ctrl+C)
INTERFACE = None      # None = default interface, or e.g. "Wi-Fi" / "eth0"
BPF_FILTER = None     # e.g. "tcp port 80", "udp port 53", "icmp"
# -------------------------------------------

PRINTABLE = set(string.printable) - set("\r\n\t\x0b\x0c")


def printable_preview(data: bytes) -> str:
    return "".join(chr(b) if chr(b) in PRINTABLE else "." for b in data)


def analyze_packet(packet):
    print("\n" + "=" * 60)
    ts = datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S.%f")[:-3]
    print("Time           :", ts)
    print("Packet Length  :", len(packet))

    if IP in packet:
        ip_layer = packet[IP]
    elif IPv6 in packet:
        ip_layer = packet[IPv6]
    else:
        print("Non-IP packet (e.g., ARP)")
        print("Summary        :", packet.summary())
        print("=" * 60)
        return

    print("IP Version     :", ip_layer.version)
    print("Source IP      :", ip_layer.src)
    print("Destination IP :", ip_layer.dst)

    if TCP in packet:
        print("Protocol       : TCP")
        print("Source Port    :", packet[TCP].sport)
        print("Dest Port      :", packet[TCP].dport)
        print("TCP Flags      :", packet[TCP].flags)
    elif UDP in packet:
        print("Protocol       : UDP")
        print("Source Port    :", packet[UDP].sport)
        print("Dest Port      :", packet[UDP].dport)
    elif ICMP in packet:
        print("Protocol       : ICMP")
        print("ICMP Type      :", packet[ICMP].type)
    else:
        print("Protocol       : Other IP protocol")

    if DNS in packet and packet.haslayer(DNSQR):
        print("DNS Query      :", packet[DNSQR].qname.decode(errors="replace"))

    if Raw in packet:
        payload = bytes(packet[Raw].load)[:80]
        print("Payload (hex)  :", payload.hex())
        print("Payload (text) :", printable_preview(payload))

    print("=" * 60)


def start_sniffer():
    print("Python Network Packet Sniffer")
    print("Available interfaces:", get_if_list())
    print("Press Ctrl+C to stop.\n")
    

    try:
        sniff(
            iface=INTERFACE,
            filter=BPF_FILTER,
            prn=analyze_packet,
            count=PACKET_COUNT,
            store=False,
        )
    except PermissionError:
        print("Permission denied. Run VS Code as Administrator (or use sudo).")
    except OSError as error:
        print("Capture error (on Windows, make sure Npcap is installed):", error)
    except Exception as error:
        print("Error:", error)
    finally:
        print("\nPacket capturing stopped.")


if __name__ == "__main__":
    start_sniffer()