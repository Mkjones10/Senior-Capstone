from pymodbus.client import ModbusTcpClient
import struct

# Configure your PLC IP address and port
plc_ip = "192.168.0.10"  # Replace with your PLC's IP
port = 502

# Create Modbus client
client = ModbusTcpClient(plc_ip, port=port)

# Connect to the PLC
if client.connect():
    print("Connected to the PLC successfully.")
else:
    print("Failed to connect to the PLC.")
    exit(1)

# Write 1337.0 to %MD20
value = 1337.0
float_as_int = int.from_bytes(bytearray(struct.pack("f", value)), byteorder="big")
client.write_registers(20, [float_as_int], unit=1)  # Assuming register %MD20 is at address 20

# Read the response from %MD21
response = client.read_holding_registers(21, 2, unit=1)  # Assuming %MD21 starts at address 21
if response.isError():
    print("Error reading from %MD21.")
else:
    # Combine the two 16-bit registers into a 32-bit integer
    raw_value = response.registers[0] << 16 | response.registers[1]
    
    # Drop the decimal and convert to ASCII
    ascii_value = ''.join(chr(int(digit)) for digit in str(int(raw_value)))
    print("The answer is:", ascii_value)

# Close the connection
client.close()
