import zipfile
import struct

#Extract the files inside
with zipfile.ZipFile("/mnt/data/eldorian_artifact.pth", "r") as zf:
    zf.printdir()  # List the contents
    # 'eldorian_artifact/data/0' is the interesting file we focus on

#Read the raw float data

with zipfile.ZipFile("/mnt/data/eldorian_artifact.pth", "r") as zf:
    data_0 = zf.read("eldorian_artifact/data/0")

#The file eldorian_artifact/data/0 turned out to contain raw, little-endian float values.
# Unpack them as 32-bit floats (little-endian, '<f')
floats = struct.unpack('<1600f', data_0)  # e.g. 1600 floats

#Convert floats to text
#Once we had the array of floats, we noticed many were “nice round numbers” that looked like ASCII codes. To decode:
message_chars = []
for f in floats:
    # Round to an integer
    val = round(f)
    # Check if it’s a printable ASCII value
    if 32 <= val <= 126:
        message_chars.append(chr(val))

message = "".join(message_chars)
print(message)
