import ucryptolib
from machine import SPI, Pin
import sdcard, os

# ==========================
# AES CONFIG
# ==========================
KEY = b"1234567890abcdef"
IV  = b"abcdef1234567890"

# ==========================
# SD CONFIG
# ==========================
SPI_BUS = 1
SCK_PIN = 10
MOSI_PIN = 11
MISO_PIN = 12
CS_PIN = 13

SD_MOUNT_PATH = "/sd"

# ==========================
# FUNCTIONS
# ==========================

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def encrypt_file(filepath):
    aes = ucryptolib.aes(KEY, 2, IV)

    with open(filepath, "rb") as f:
        data = f.read()

    encrypted = aes.encrypt(pad(data))

    enc_path = filepath + ".enc"

    with open(enc_path, "wb") as f:
        f.write(encrypted)

    # usuń oryginał
    os.remove(filepath)

    print("Encrypted:", enc_path)


def clear_sd():
    """
    Usuwa wszystkie pliki z /sd
    """

    files = os.listdir(SD_MOUNT_PATH)

    for filename in files:
        path = SD_MOUNT_PATH + "/" + filename

        try:
            os.remove(path)
            print("Deleted:", path)
        except Exception as e:
            print("Cannot delete:", path, e)


# ==========================
# INIT SD CARD
# ==========================

spi = SPI(
    SPI_BUS,
    sck=Pin(SCK_PIN),
    mosi=Pin(MOSI_PIN),
    miso=Pin(MISO_PIN)
)

cs = Pin(CS_PIN)

sd = sdcard.SDCard(spi, cs)
os.mount(sd, SD_MOUNT_PATH)

# ==========================
# CLEAN CARD
# ==========================

clear_sd()

# ==========================
# CREATE TXT FILE
# ==========================

txt_path = "/sd/test.txt"

with open(txt_path, "w") as f:
    f.write("This message will be encrypted.\n")

# ==========================
# CREATE SIMPLE PNG FILE
# ==========================
#
# To jest najmniejszy poprawny plik PNG (1x1 px)
#

png_bytes = (
    b'\x89PNG\r\n\x1a\n'
    b'\x00\x00\x00\rIHDR'
    b'\x00\x00\x00\x01'
    b'\x00\x00\x00\x01'
    b'\x08\x02\x00\x00\x00'
    b'\x90wS\xde'
    b'\x00\x00\x00\x0cIDAT'
    b'\x08\xd7c\xf8\xff\xff?\x00\x05\xfe\x02\xfe'
    b'A\xdd\x9d\xb3'
    b'\x00\x00\x00\x00IEND\xaeB`\x82'
)

png_path = "/sd/obraz.png"

with open(png_path, "wb") as f:
    f.write(png_bytes)

# ==========================
# ENCRYPT FILES
# ==========================

encrypt_file(txt_path)
encrypt_file(png_path)

# ==========================
# SHOW CONTENTS
# ==========================

print("\nSD CARD CONTENTS:")

for file in os.listdir("/sd"):
    print(file)