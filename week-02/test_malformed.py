import unittest
from pcap_parser import parse_ethernet, parse_ipv4, parse_icmp

class TestEthernetParser(unittest.TestCase):

    def test_short_ethernet_frame(self):
        packet = b"\x00\x01\x02\x03\x04"

        with self.assertRaises(ValueError):
            parse_ethernet(packet)

        # try:
        #     parse_ethernet(packet)
        #     print("FAIL: Invalid packet was accepted")

        # except ValueError as error:
        #     print("PASS: Invalid packet was accepted")
        #     print(f"Readson: {error}")

class TestIPv4Parser(unittest.TestCase):

    def test_short_ipv4_header(self):
        packet =b"\x45\x00\x14"

        with self.assertRaises(ValueError):
            parse_ipv4(packet)

    def test_valid_ethernet_header(self):
        
        packet = bytes.fromhex(
            "001122334455"
            "aabbccddeeff"
            "0800"
        )

        result = parse_ethernet(packet)

        self.assertEqual(result["destination_mac"], "00:11:22:33:44:55")
        self.assertEqual(result["source_mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result["ether_type"], 2048)

class TestICMPParser(unittest.TestCase):
    
    def test_short_icmp_header(self):
        packet = b"\x08\x00\x00"

        with self.assertRaises(ValueError):
            parse_icmp(packet)

    def test_valid_echo_request(self):
        packet = b"\x08\x00\x12\x34\x00\x01\x00\x02"

        result = parse_icmp(packet)

        self.assertEqual(result["type"], 8)
        self.assertEqual(result["code"], 0)
        self.assertEqual(result["checksum"], 0x1234)
        self.assertEqual(result["identifier"], 1)
        self.assertEqual(result["sequence"], 2)


if __name__ == "__main__":
    unittest.main()