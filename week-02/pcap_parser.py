import struct
import ipaddress

def parse_ethernet(packet):
    if len(packet) < 14:
        raise ValueError("Incomplete Ethernet header")

    destination = packet[0:6]
    source = packet[6:12]
    ether_type = struct.unpack("!H", packet[12:14])[0]

    def format_mac(mac):
        return ":".join(f"{byte:02x}" for byte in mac)

    return {
        "destination_mac": format_mac(destination),
        "source_mac": format_mac(source),
        "ether_type": ether_type,
    }

def parse_ipv4(packet):
    if len(packet) < 20:
        raise ValueError("Incomplete IPv4 header")

    version_ihl = packet[0]

    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) *4

    if version != 4 or ihl < 20 or len(packet) < ihl:
        raise ValueError("Invalid IPv4 header")

    ttl = packet[8]
    protocol = packet[9]

    source_ip = str(ipaddress.IPv4Address(packet[12:16]))
    destination_ip = str(ipaddress.IPv4Address(packet[16:20]))

    return {
        "version": version,
        "header_length": ihl,
        "ttl": ttl,
        "protocol": protocol,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
    }

def parse_icmp(icmp_data):
    if len(icmp_data) < 8:
        raise ValueError("Incorrect ICMP data")

    return {
        "type": icmp_data[0],
        "code": icmp_data[1],
        "checksum": int.from_bytes(icmp_data[2:4], byteorder="big"),
        "identifier": int.from_bytes(icmp_data[4:6], byteorder="big"),
        "sequence": int.from_bytes(icmp_data[6:8], byteorder="big"),
    }

PCAP_FILE ="sample.pcap"

def main():
    
    with open(PCAP_FILE, "rb") as file:
        # read the 24-byte global header
        global_header = file.read(24)

        if len(global_header) != 24:
            raise ValueError("Invalid PCAP global header")

        # Identify byte order and timestamp format
        magic = global_header[:4]

        formats = {
            b"\xd4\xc3\xb2\xa1": ("<", "microseconds"),
            b"\xa1\xb2\xc3\xd4": (">", "microseconds"),
            b"\x4d\xc3\xb2\xa1": ("<", "nanoseconds"),
            b"\xa1\xb2\x3c\x4d": (">", "nanoseconds"),
        }

        if magic not in formats:
            raise ValueError("Unsupported PCAP format")

        endian, precision = formats[magic]

        # Read link-layer type
        link_type = struct.unpack(
            endian + "I", global_header[20:24]
        )[0]

        print("=== PCAP ANalysis ===")
        print(f"Timestamp precision {precision}")
        print(f"Link-layer type: {link_type}")

        packet_count = 0
        successful = 0
        malformed = 0

        while True:
            record_header = file.read(16)

            if not record_header:
                break

            if len(record_header) != 16:
                raise ValueError("Truncated packet header")

            ts_sec, ts_fraction, captured_len, original_len = (
                struct.unpack(endian + "IIII", record_header)
            )

            packet = file.read(captured_len)

            if len(packet) != captured_len:
                raise ValueError("Truncated packet data")

            packet_count += 1

            try:
                if link_type == 1:
                    ethernet = parse_ethernet(packet)

                if ethernet["ether_type"] == 0x0800:
                    ipv4 = parse_ipv4(packet[14:])

                    print(
                        f"Packet {packet_count}: "
                        f"{ipv4['source_ip']} -> "
                        f"{ipv4['destination_ip']} "
                        f"Protocol={ipv4['protocol']} "
                        f"TTL={ipv4['ttl']}"
                    )

                    if ipv4["protocol"] == 1:
                        icmp_offset = 14 + ipv4["header_length"]
                        icmp_data = packet[icmp_offset:]

                        if len(icmp_data) >= 8 and icmp_data[0] in (0,8):
                            icmp = parse_icmp(icmp_data)

                            icmp_types = {
                                0: "Echo Reply",
                                8: "Echo Request"
                            }

                            icmp_description = icmp_types.get(icmp["type"], "Unknown ICMP Type")

                            print(
                                f"ICMP Type: {icmp_description} "
                                f"ICMP Code: {icmp['code']} "
                                f"ICMP Checksum: {icmp['checksum']} "
                                f"ICMP Identifier: {icmp['identifier']} "
                                f"ICMP Sequence: {icmp['sequence']} "
                            )

                        successful += 1

            except ValueError as error:
                malformed += 1
                print(f"Packet {packet_count}: {error}")
                continue


                print(
                    f"Packet {packet_count}: "
                    f"{captured_len} captured bytes, "
                    f"{original_len} original bytes"
                )

            print(f"\nTotal packets: {packet_count}")
            print(f"\nSuccesful packets: {successful}")
            print(f"\nMalformed packets: {malformed}")

            if packet_count > 0:
                print(f"\nMalformed rate: {malformed / packet_count:.2f}%")

    def test_short_ethernet_frame():
        packet = b"\x00\x01\x02\x03\x04"

        try:
            parse_ethernet(packet)
            print("FAIL: Invalid packet was accepted")

        except ValueError as error:
            print("PASS: Invalid packet was rejected")
            print(f"Reason: {error}")

    test_short_ethernet_frame()

if __name__ == "__main__":
    main()