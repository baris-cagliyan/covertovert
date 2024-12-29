from CovertChannelBase import CovertChannelBase
from scapy.all import IP, ICMP, sniff
import time
import random

class MyCovertChannel(CovertChannelBase):
    """
    Example: 2-bit encoding in ICMP.type field using threshold_1, threshold_2, threshold_3
    """

    def __init__(self):
        super().__init__()

    def send(self, log_file_name, threshold_1, threshold_2, threshold_3, receiver_ip, sleep_duration):
        """
        Steps:
        1. Generate a random message and log it.
        2. Convert the message to binary.
        3. Process the binary message 2 bits at a time.
        4. Depending on the 2-bit chunk, choose a random integer in a range:
           - 00 -> random integer in [0, threshold_1)
           - 01 -> random integer in [threshold_1, threshold_2)
           - 10 -> random integer in [threshold_2, threshold_3)
           - 11 -> random integer in [threshold_3, 255] 
        5. Send packet with ICMP(type=random_integer).
        6. Sleep for sleep_duration seconds between sending packets.
        """
        # Generate and log the random message
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        two_bit_chunks = [binary_message[i:i+2] for i in range(0, len(binary_message), 2)]

        start = time.time()

        for chunk in two_bit_chunks:
        # Zero-pad if last chunk is only 1 bit (unlikely in a well-formed 8-bit block scenario, but just in case)
            if len(chunk) < 2:
                chunk = chunk.ljust(2, '0')

            if chunk == "00":
                icmp_type_value = random.randint(0, threshold_1 - 1)
            elif chunk == "01":
                icmp_type_value = random.randint(threshold_1, threshold_2 - 1)
            elif chunk == "10":
                icmp_type_value = random.randint(threshold_2, threshold_3 - 1)
            else:  # "11"
                icmp_type_value = random.randint(threshold_3, 255)

            pkt = IP(dst=receiver_ip)/ICMP(type=icmp_type_value)
            super().send(pkt)  
            time.sleep(sleep_duration)    # Tested minimum sleep time is 0.025 to avoid packet loss

        end=time.time()
        length = end-start
        print("Time taken to send the message: ", length)
        print("Covert Channel Capacity in bits per second: ", len(binary_message)/length)


    def receive(self, threshold_1, threshold_2, threshold_3, sender_ip, log_file_name):
        """
        Steps:
        1. Sniff ICMP packets from the sender.
        2. For each packet's ICMP.type, convert to 2-bit chunk:
           - type < threshold_1 => "00"
           - type < threshold_2 => "01"
           - type < threshold_3 => "10"
           - otherwise         => "11"
        3. Append the 2 bits to a bit_buffer.
        4. Every 8 bits => one character.
        5. Stop when '.' character is decoded.
        6. Log the received message.
        """

        received_message = ""
        bit_buffer = ""

        while True:
            packets = sniff(filter=f"icmp and host {sender_ip}", count=1, timeout=10)
            if not packets or len(packets) == 0:
                # No more packets received in 10 seconds
                break

            pkt = packets[0]
            if ICMP in pkt and pkt[IP].src == sender_ip:
                icmp_type_value = pkt[ICMP].type

                # Decode 2 bits
                if icmp_type_value < threshold_1:
                    two_bits = "00"
                elif icmp_type_value < threshold_2:
                    two_bits = "01"
                elif icmp_type_value < threshold_3:
                    two_bits = "10"
                else:
                    two_bits = "11"

                # Accumulate the 2 bits
                bit_buffer += two_bits

                # Check if we formed at least one 8-bit chunk
                while len(bit_buffer) >= 8:
                    eight_bits = bit_buffer[:8]
                    bit_buffer = bit_buffer[8:]

                    char = self.convert_eight_bits_to_character(eight_bits)
                    received_message += char

                    if char == '.':
                        # We stop upon detecting '.'
                        self.log_message(received_message, log_file_name)
                        return

        # If we exit the while loop normally (no '.' found), log whatever was received so far
        self.log_message(received_message, log_file_name)

