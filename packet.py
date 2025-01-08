import time
import socket
import struct
from multiprocessing import Process


def print_packet(packet):
    ip_header = packet[0:20]
    ip_fields = struct.unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = ip_fields[0]
    ihl = version_ihl & 0xF
    total_length = ip_fields[2]
    
    src_ip = socket.inet_ntoa(ip_fields[8])
    udp_header = packet[20:28]
    udp_fields = struct.unpack('!HHHH', udp_header)

    src_port = udp_fields[0]
    dest_port = udp_fields[1]
    
    print(f"IP Version: {ip_fields[0] >> 4}, Header Length: {ihl * 4} bytes, Total Length: {total_length} bytes")
    print(f"Source IP: {src_ip}, Source Port: {src_port}, Destination Port: {dest_port}\n")

    return src_ip, src_port


def packet_capture(lag_delay):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    local_ip = "127.0.0.1"  # Replace with your machine's actual IP
    sock.bind((local_ip, 0))

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print("Listening for incoming packets...")

    try:
        while True:
            packet, addr = sock.recvfrom(65565)
            src_ip, src_port = print_packet(packet)

            if src_port == 52015:
                print(f"Delaying processing for packet from port {src_port} and IP {src_ip}")
                time.sleep(lag_delay)  # Delay the processing for packets from the port

    except KeyboardInterrupt:
        print("\nExiting packet capture...")
    except Exception as e:
        print(f"An error occurred during packet capture: {e}")


def main():
    delay = float(input("Enter the lag delay in seconds: "))

    capture_process = Process(target=packet_capture, args=(delay,))
    capture_process.start()

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\nExiting...")

    finally:
        capture_process.terminate()
        capture_process.join()


if __name__ == '__main__':
    main()
