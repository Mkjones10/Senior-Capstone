from pymodbus.client import ModbusTcpClient


client = ModbusTcpClient('services.cityinthe.cloud', port=5093)
client.connect()

# Example to read coils
coils = client.read_coils(1, 10)  # Change starting address and count as needed
  # Adjust as needed
if not coils.isError():
    print("Coil status:", coils.bits)
else:
    print("Error reading coils.")

# Example to read input register at address 0x7630
register = client.read_input_registers(0x7630, 1)
if not register.isError():
    print("Register 0x7630:", hex(register.registers[0]))
else:
    print("Error reading register.")

client.close()
