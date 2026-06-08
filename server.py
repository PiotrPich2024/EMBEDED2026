import asyncio
import time
import network
import ucryptolib
from machine import SPI, Pin
import sdcard, os
 
 
users = {
    "admin": "123passw123",
    "user": "1234"
}
 
 
def list_dir(path):
    result = ""
    for entry in os.ilistdir(path):
        name = entry[0]
        entry_type = entry[1]
        size = entry[3]
        display_name = name[:-4] if name.endswith(".enc") else name
        if entry_type == 0x4000:
            result += f"drwxr-xr-x 1 ftp ftp {size} Jan 01 00:00 {display_name}\r\n"
        else:
            result += f"-rw-r--r-- 1 ftp ftp {size} Jan 01 00:00 {display_name}\r\n"
    return result

 
def connect_to_network():
    SSID = 'iotcopernicus'
    PASSWORD = 'iot-2015-2017'
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    print('Łączenie z siecią Wi-Fi...')
    wlan.connect(SSID, PASSWORD)
    while not wlan.isconnected():
        print('Łączenie...')
        time.sleep(1)
    print('Połączono!')
    print('Adres IP:', wlan.ifconfig()[0])
    return wlan.ifconfig()[0]

 
async def read_command(reader):
    line = await reader.readline()
    if not line:
        return None
    return line.rstrip(b"\r\n").decode("utf-8")
 
 
async def handle_pasv(host, writer):
    PORT = 50001
    conn_event = asyncio.Event()
    conn_result = [None, None]

    async def _accept_one(r, w):
        conn_result[0] = r
        conn_result[1] = w
        conn_event.set()

    pasv_server = await asyncio.start_server(_accept_one, host, PORT)
    try:
        p1, p2 = PORT // 256, PORT % 256
        message = "227 Entering Passive Mode (" + host.replace(".", ",") + "," + str(p1) + "," + str(p2) + ")\r\n"
        writer.write(message.encode("utf-8"))
        await writer.drain()

        await conn_event.wait()
    finally:
        pasv_server.close()          # zawsze zamknij serwer PASV
        await pasv_server.wait_closed()

    return conn_result[0], conn_result[1]
 
 
def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]
 
 
async def manage_client_cc(host, reader, writer):
    """Główna pętla obsługi komend FTP po zalogowaniu."""
    data_reader = None
    data_writer = None
    # Nie chce mi sie czytac co to EBDC więc tylko bedzie ascii i binary
    # Niech 0 = ascii, zaś 1 to będzie binary (niestety nie ma enumów)
    data_type = 1
    KEY = b"1234567890abcdef"  # 16 bajtów = AES-128
    IV  = b"abcdef1234567890"  # 16 bajtów
 
    try:
        rename_from = None
        while True:
            command = await read_command(reader)
            if command is None:
                break
 
            if command.startswith("PASV"):
                data_reader, data_writer = await handle_pasv(host, writer)
 
            elif command.startswith("QUIT"):
                writer.write("221 Goodbye\r\n".encode("utf-8"))
                await writer.drain()
                break
 
            elif command.startswith("SYST"):
                writer.write("215 UNIX Type: L8\r\n".encode("utf-8"))
                await writer.drain()
 
            elif command.startswith("TYPE"):
                if "A" in command:
                    data_type = 0
                elif "I" in command:
                    data_type = 1
                writer.write("200 OK\r\n".encode("utf-8"))
                await writer.drain()
 
            elif command.startswith("FEAT"):
                writer.write("211 no-features\r\n".encode("utf-8"))
                await writer.drain()
 
            elif command.startswith("PWD"):
                writer.write('257 "/sd" is current working directory\r\n'.encode("utf-8"))
                await writer.drain()
 
            elif command.startswith("LIST"):
                if data_writer is None:
                    writer.write("425 No data connection\r\n".encode("utf-8"))
                    await writer.drain()
                    continue
                writer.write("150 Opening data connection\r\n".encode("utf-8"))
                await writer.drain()
                data_writer.write(list_dir("/sd").encode("utf-8"))
                await data_writer.drain()
                data_writer.close()
                await data_writer.wait_closed()
                data_reader = None
                data_writer = None
                writer.write(b"226 Transfer complete\r\n")
                await writer.drain()
 
            elif command.startswith("NOOP"):
                writer.write("200 OK\r\n".encode("utf-8"))
                await writer.drain()
 
            elif command.startswith("RETR"):
                requested = command.split()[1]
                
                # zdjecie.png → zdjecie.png.enc
                disk_filename = "/sd/" + requested + ".enc"

                if data_writer is None:
                    writer.write("425 No data connection\r\n".encode("utf-8"))
                    await writer.drain()
                    continue

                try:
                    os.stat(disk_filename)
                except:
                    writer.write("550 File not found\r\n".encode("utf-8"))
                    await writer.drain()
                    continue

                writer.write("150 Opening data connection\r\n".encode("utf-8"))
                await writer.drain()

                file_size = os.stat(disk_filename)[6]
                bytes_read = 0

                current_iv = IV
                with open(disk_filename, "rb") as f:
                    while True:
                        buffer = f.read(1024)
                        if not buffer:
                            break
                        bytes_read += len(buffer)
                        last_block = buffer[-16:]  # zapamiętaj ostatnie 16 bajtów PRZED paddingiem
                        if len(buffer) % 16 != 0:
                            buffer = buffer + b'\x00' * (16 - len(buffer) % 16)
                        aes = ucryptolib.aes(KEY, 2, current_iv)  # użyj aktualnego IV
                        chunk = aes.decrypt(buffer)
                        current_iv = last_block  # następny chunk używa ostatniego bloku jako IV
                        if bytes_read == file_size:
                            chunk = unpad(chunk)
                        data_writer.write(chunk)
                        await data_writer.drain()

                data_writer.close()
                await data_writer.wait_closed()
                data_reader = None
                data_writer = None
                writer.write("226 Transfer complete\r\n".encode("utf-8"))
                await writer.drain()
            
            elif command.startswith("STOR"):
                requested = command.split()[1]
                disk_filename = "/sd/" + requested + ".enc"
                if data_reader is None:
                    writer.write("425 No data connection\r\n".encode("utf-8"))
                    await writer.drain()
                    continue
                writer.write("150 Opening data connection\r\n".encode("utf-8"))
                await writer.drain()
                current_iv = IV
                with open(disk_filename, "wb") as f:
                    prev_chunk = None
                    while True:
                        chunk = await data_reader.read(1024)
                        if not chunk:
                            if prev_chunk is not None:
                                pad_len = 16 - (len(prev_chunk) % 16)
                                prev_chunk = prev_chunk + bytes([pad_len] * pad_len)
                                aes = ucryptolib.aes(KEY, 2, current_iv)
                                encrypted = aes.encrypt(prev_chunk)
                                current_iv = encrypted[-16:]
                                f.write(encrypted)
                            break
                        if prev_chunk is not None:
                            if len(prev_chunk) % 16 != 0:
                                prev_chunk = prev_chunk + b'\x00' * (16 - len(prev_chunk) % 16)
                            aes = ucryptolib.aes(KEY, 2, current_iv)
                            encrypted = aes.encrypt(prev_chunk)
                            current_iv = encrypted[-16:]  # ← ostatnie 16 bajtów zaszyfrowanego chunka
                            f.write(encrypted)
                        prev_chunk = chunk
                data_reader = None
                data_writer.close()
                await data_writer.wait_closed()
                data_writer = None
                writer.write("226 Transfer complete\r\n".encode("utf-8"))
                await writer.drain()

            elif command.startswith("CWD"):
                # Ignorujemy zmianę katalogu, zawsze jesteśmy w /sd
                writer.write("250 OK\r\n".encode("utf-8"))
                await writer.drain()

            elif command.startswith("SIZE"):
                filename = command.split()[1]
                try:
                    size = os.stat(filename)[6]
                    writer.write(("213 " + str(size) + "\r\n").encode("utf-8"))
                except:
                    writer.write("550 File not found\r\n".encode("utf-8"))
                await writer.drain()
 
            elif command.startswith("DELE"):
                requested = command.split()[1]
                disk_filename = "/sd/" + requested + ".enc"
                try:
                    os.remove(disk_filename)
                    writer.write("250 File deleted\r\n".encode("utf-8"))
                except:
                    writer.write("550 File not found\r\n".encode("utf-8"))
                await writer.drain()
            
            elif command.startswith("RNFR"):
                requested = command.split()[1]
                disk_filename = "/sd/" + requested + ".enc"
                try:
                    os.stat(disk_filename)
                    rename_from = disk_filename
                    writer.write("350 Ready for destination\r\n".encode("utf-8"))
                except:
                    writer.write("550 File not found\r\n".encode("utf-8"))
                await writer.drain()

            elif command.startswith("RNTO"):
                requested = command.split()[1]
                disk_filename = "/sd/" + requested + ".enc"
                if rename_from is None:
                    writer.write("503 RNFR required first\r\n".encode("utf-8"))
                else:
                    try:
                        os.rename(rename_from, disk_filename)
                        rename_from = None
                        writer.write("250 File renamed\r\n".encode("utf-8"))
                    except:
                        writer.write("550 Rename failed\r\n".encode("utf-8"))
                await writer.drain()

            elif command.startswith("MDTM"):
                # Zwracamy stały czas — brak RTC
                writer.write("213 20000101000000\r\n".encode("utf-8"))
                await writer.drain()
 
            elif command.startswith("SITE"):
                
                writer.write("200 AES-128-CBC, KEY=1234567890abcdef, IV=abcdef1234567890\r\n".encode("utf-8"))
                await writer.drain()

            else:
                print("unknown command: " + command)
                writer.write(b"502 Command not implemented\r\n")
                await writer.drain()
 
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        if data_writer:
            data_writer.close()
 
 
async def establish_new_client_cc(host, reader, writer):
    """Obsługa nowego połączenia: powitanie, uwierzytelnienie, przekazanie do manage_client_cc."""
    addr = writer.get_extra_info("peername")
    print("połączono nowego klienta: " + str(addr))
 
    writer.write("220 Welcome\r\n".encode("utf-8"))
    await writer.drain()
 
    data = await read_command(reader)
    if not data or len(data.split()) != 2:
        writer.close()
        return
 
    op_code, user_name = data.split()
    if op_code != "USER" or user_name not in users:
        print(1)
        writer.close()
        return
 
    writer.write("331 Password required\r\n".encode("utf-8"))
    await writer.drain()
 
    data = await read_command(reader)
    if not data or len(data.split()) != 2:
        print(2)
        writer.close()
        return
 
    op_code, password = data.split()
    if op_code != "PASS":
        print(3)
        writer.close()
        return
 
    tries, chances = 1, 3
    while True:
        if tries > chances:
            print(4)
            writer.close()
            return
        if users[user_name] != password:
            tries += 1
            writer.write("430 Invalid password\r\n".encode("utf-8"))
            await writer.drain()
            line = await read_command(reader)
            if not line:
                writer.close()
                return
            _, password = line.split()
            continue
 
        writer.write("230 login succesfull\r\n".encode("utf-8"))
        await writer.drain()
        await manage_client_cc(host, reader, writer)
        return
 
 
async def open_control_channel(host):
    PORT = 21
 
    async def client_handler(reader, writer):
        await establish_new_client_cc(host, reader, writer)
 
    server = await asyncio.start_server(client_handler, host, PORT)
    print("serwer nasłuchuje na: " + host + " " + str(PORT))
    await server.wait_closed()
 
 
# ---------------------------------------------------------------------------
# SD card initialization
# ---------------------------------------------------------------------------
 
SPI_BUS = 1   # SPI BUS 1
SCK_PIN = 10  # GP10
MOSI_PIN = 11 # GP11
MISO_PIN = 12 # GP12
CS_PIN = 13   # GP13
SD_MOUNT_PATH = '/sd'
 
try:
    # Init SPI communication
    spi = SPI(SPI_BUS, sck=Pin(SCK_PIN), mosi=Pin(MOSI_PIN), miso=Pin(MISO_PIN))
    cs  = Pin(CS_PIN)
    sd  = sdcard.SDCard(spi, cs)
    
    # Mount microSD card
    os.mount(sd, SD_MOUNT_PATH)
    
    # List files on the microSD card
    print(os.listdir(SD_MOUNT_PATH))
    
except Exception as e:
    print('An error occurred:', e)
    
# ---------------------------------------------------------------------------
# Connecting to network and server start
# ---------------------------------------------------------------------------
 
host = connect_to_network()
asyncio.run(open_control_channel(host))
