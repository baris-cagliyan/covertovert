Covert Storage Channel that exploits Protocol Field Manipulation using Type field in ICMP [Code: CSC-PSV-ICMP-TYPE]

Overview
    This project implements a Covert Storage Channel that exploits Protocol Field Manipulation using the Type field in ICMP (Internet Control Message Protocol) packets. The channel encodes data by altering the ICMP type field based on a 2-bit encoding scheme, enabling covert communication between a sender and receiver without raising immediate suspicion.

    Covert Channel Capacity in bits per second:  46.23733223094943

How It Works

    Sending Side:

    Message Generation: A random message is generated and logged.
    Binary Conversion: The message is converted into a binary string.
    2-Bit Chunk Processing: The binary message is divided into 2-bit chunks.
    ICMP Type Encoding:
        Each 2-bit chunk determines the range of ICMP type values:
            00 → Random integer in [0, threshold_1)
            01 → Random integer in [threshold_1, threshold_2)
            10 → Random integer in [threshold_2, threshold_3)
            11 → Random integer in [threshold_3, 255]
    Packet Sending: An ICMP packet is crafted with the selected type value and sent to the receiver's IP address.
    Timing Control: A short delay (time.sleep(0.025)) is introduced between packets to prevent packet loss and manage transmission rate.

    Receiving Side:

    Packet Sniffing: Continuously listens for ICMP packets originating from the sender's IP.
    ICMP Type Decoding: For each captured packet, the ICMP type value is decoded into a 2-bit chunk based on the defined thresholds:
        < threshold_1 → 00
        < threshold_2 → 01
        < threshold_3 → 10
        Otherwise → 11
    Bit Accumulation: The 2-bit chunks are accumulated into a bit buffer.
    Message Reconstruction: Every 8 bits in the buffer are converted back to ASCII characters.
    Termination: The process stops upon decoding a '.' character, indicating the end of the message.
    Logging: The received message is logged for verification.

Usage

    Configuration Parameters

    log_file_name: Path to the log file where messages are stored.
    threshold_1, threshold_2, threshold_3: Integer values defining the ICMP type ranges for encoding.
        Ensure threshold_1 < threshold_2 < threshold_3 < 256.
        Example:
            threshold_1 = 50
            threshold_2 = 100
            threshold_3 = 150
    receiver_ip / sender_ip: IP address of the receiver/sender.

Limitations

    Threshold Constraints:
        threshold_1 must be less than threshold_2, and threshold_2 must be less than threshold_3.
        All thresholds must be within the range [0, 255].
    ICMP Type Range:
        ICMP types are limited to 0-255. Selecting thresholds must ensure sufficient range for each 2-bit encoding to minimize collisions with standard ICMP types.
    Transmission Rate:
        The time.sleep(0.025) delay sets the transmission rate. Reducing this may increase covert channel capacity but risks packet loss.

Covert Channel Capacity

    The implemented covert storage channel achieves a capacity of approximately 46.24 bits per second. This is calculated based on the number of bits transmitted over the time taken to send the message.