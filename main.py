import re
import base64
import binascii
import sys
from Crypto.Cipher import DES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto import Random
from py3rijndael import RijndaelCbc, ZeroPadding


def decrypt(file):
    key = 'ay$a5%&j'
    IV = 'abc@9879'
	PBKDF2_key = '0THISISOBmodedByForlaxNIGGAs'
	file_content = file.read()
    body = re.search('"Body": "(\w+)"', file_content)
	if body is None:return -1
	else:body = body.group(1)
    des_object = DES.new(key, DES.MODE_CBC, IV)
    array = []
    for i in range(int(len(body)/2)):
        array.append(binascii.unhexlify(body[i*2:i*2+2]))
    string = base64.b64decode(b''.join(array))
    b64 = des_object.decrypt(string).replace(b'\x04', b'')
    e2b = base64.b64decode(b64)
    data = re.search(b'x0;(.*?)0;x', e2b).group(1)
    array = base64.b64decode(data)
    salt = array[:32]
    IV = array[32:64]
    array2 = array[64:]
    bytesl = PBKDF2(PBKDF2_key,salt,32, 1000)
    rijndael_cbc = RijndaelCbc(
            key=bytesl,
            iv=IV,
            padding=ZeroPadding(32),
            block_size=32
        )
    return rijndael_cbc.decrypt(array2).decode()
    
    
    


if __name__ == '__main__':
    file = open(sys.argv[1], 'r')
    text = decrypt(file).replace('\x12', '').replace('\r', '').replace('\t', '')
	if text == -1:
		print('Failed to decrypt')
    with open(sys.argv[1]+'_Decrypted.loli', 'w') as f:
        f.write(text)
    print('Decrypted')
    input()
