import struct

with open("sample.pcap", "rb") as file:
    header = file.read(24)

endian = "<"

major = struct.unpack(endian + "H", header[4:6])[0]
minor = struct.unpack(endian + "H", header[6:8])[0]
snaplen = struct.unpack(endian + "I", header[16:20])[0]
link_type = struct.unpack(endian + "I", header[20:24])[0]

print(f"PCAP version: {major}.{minor}")
print(f"Snapshot length: {snaplen}")
print(f"Link type: {link_type}")