import getpass, imaplib

M = imaplib.IMAP4_SSL('imap.yandex.ru')
M.login('ilya.lazarev.i', 'pow3r4Me')
M.select()
typ, data = M.search(None, 'ALL')
print(len(data.decode()))
sys.exit(0)
for num in data[0].split():
    typ, data = M.fetch(num, '(RFC822)')
    print('Message %s\n%s\n' % (num, data[0][1]))
M.close()
M.logout()