import pyshark
import pandas as pd

def pcapng_to_csv(pcapng_file, output_csv):
    try:
        # Load the .pcapng file
        capture = pyshark.FileCapture(pcapng_file)

        # Initialize a list to store data
        data = []

        # Extract relevant details
        for packet in capture:
            try:
                source_port = packet.tcp.srcport if hasattr(packet, 'tcp') else None
                dest_port = packet.tcp.dstport if hasattr(packet, 'tcp') else None
                protocol = packet.highest_layer
                length = packet.length
                timestamp = packet.sniff_time

                # Add a placeholder for the Label column
                label = 'Normal'  # Replace with actual labeling logic

                data.append([source_port, dest_port, protocol, length, timestamp, label])
            except Exception as e:
                print(f"Error processing packet: {e}")

        # Convert to DataFrame and save
        columns = ['Source Port', 'Destination Port', 'Protocol', 'Packet Length', 'Timestamp', 'Label']
        df = pd.DataFrame(data, columns=columns)
        df.to_csv(output_csv, index=False)
        print(f"File converted and saved to {output_csv}")
    except Exception as e:
        print(f"Error reading .pcapng file: {e}")

# Example usage
pcapng_to_csv('Example.pcapng', 'output.csv')
