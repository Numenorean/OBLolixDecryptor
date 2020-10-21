import re
import base64
import binascii
import sys
from Crypto.Cipher import DES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto import Random
from py3rijndael import RijndaelCbc, ZeroPadding


static_key = b'ay$a5%&j'
static_IV = b'abc@9879'
OLD_PBKDF2_key = b'0THISISOBmodedByForlaxNIGGAs'
NEW_PBKDF2_key = b'THISISOBmodedByForlax'

def getKeys(array):
    salt = array[:32]
    IV = array[32:64]
    array2 = array[64:]
    return salt, IV, array2


def decrypt(file):
    file_content = file.read()
    body = re.search('"Body": "(\w+)"', file_content)
    if body is None:
        try:
            e2b = base64.b64decode(file_content)
            data = re.search(b'0x;(.*?)x;0', e2b).group(1)
            array = base64.b64decode(data)
            salt, IV, array2 = getKeys(array)
            bytesl = PBKDF2(NEW_PBKDF2_key, salt, 32, 1000)
            rijndael_cbc = RijndaelCbc(
                key=bytesl,
                iv=IV,
                padding=ZeroPadding(32),
                block_size=32
            )
            return rijndael_cbc.decrypt(array2).decode()
        except binascii.Error:
            return -1
    else:
        body = body.group(1)
        des_object = DES.new(static_key, DES.MODE_CBC, static_IV)
        array = []
        for i in range(int(len(body)/2)):
            array.append(binascii.unhexlify(body[i*2:i*2+2]))
        string = base64.b64decode(b''.join(array))
        b64 = des_object.decrypt(string).replace(b'\x04', b'')
        e2b = base64.b64decode(b64)
        data = re.search(b'x0;(.*?)0;x', e2b).group(1)
        array = base64.b64decode(data)
        salt, IV, array2 = getKeys(array)
        bytesl = PBKDF2(OLD_PBKDF2_key, salt, 32, 1000)
        rijndael_cbc = RijndaelCbc(
            key=bytesl,
            iv=IV,
            padding=ZeroPadding(32),
            block_size=32
        )
        return rijndael_cbc.decrypt(array2).decode()


if __name__ == '__main__':
    file = open(sys.argv[1], 'r')
    text = decrypt(file)
    text = text.replace('\r', '').replace('\t', '')
    if text == -1:
        print('Failed to decrypt')
    with open(sys.argv[1]+'_Decrypted.loli', 'w', encoding='utf-8') as f:
        f.write(text)
    print('Decrypted')
    input()
