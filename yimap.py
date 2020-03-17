# -*- coding: utf-8 -*-

""" List messages header from IMAP
поиск отправителей в заголовках"""

import sys
import sslkeylog

sslkeylog.set_keylog("sslkeylog.txt")

from imaplib import IMAP4, IMAP4_SSL
import argparse
from pathlib import Path
from email import parser
from email.header import decode_header
from math import floor
import json

try:
    import ssl
    IMAPT = IMAP4_SSL
except ImportError:
    IMAPT = IMAP4


def doEnvelope(env: bytes, progr=False):
    """ Processes RFC822.HEADER env - decode it to utf-8 """

    hp = parser.BytesParser()
    msg = hp.parsebytes(env, True)

    fr = None
    try:
        ff = str(msg['From']).split('@')
        lp = ff[-2].split('<')[-1]
        rp = ff[-1].split('>')[0]
        fr = lp+'@'+rp
        if rp == 'shararam.ru':
            print(ff)
        # print(fr)
    except Exception as e:
        pass
        # print(f'From error:{e} in {env}', file=sys.stderr)
    return fr

def xoauth2_cb(u, t):
    def xoauth2(sres):
        if len(sres) == 0:
            return 'user='+u+'\rauth=Bearer\r'+t+'\r\r'.decode('utf-8')
        sres = json.loads(sres)
        return '*'
    return xoauth2

def main(o):
    with IMAPT(o.host, o.port) as imap:
        adrset = dict()
        print('Connected...', file=sys.stderr)
        if o.auth == 'login':
            imap.login(o.user, o.pswd)
        else:
            token = Path(o.token).read_text().strip()
            imap.authenticate('XOAUTH2', xoauth2_cb(o.user, token))
        print('Logged in...', file=sys.stderr)
        _,cnt = imap.select(readonly=True)
        res, mlist = imap.search(None, 'ALL')
        cnt = int(cnt[0].decode('utf-8'))
        print(f"Total {cnt} messages", file=sys.stderr)
        mlist = mlist[0].decode().split()
        print('Fetching headers...', file=sys.stderr)
        if o.progress:
            i = 0
            sys.stderr.write("   %")
            sys.stderr.flush()
            for i in range(1,cnt):
                sys.stderr.write('\b\b\b\b{:3d}'.format(floor(1.0*i/cnt*100)));
                sys.stderr.flush()
                hdr = imap.fetch(f'{i:d}', '(RFC822.HEADER)')
                if hdr[0] != 'OK':
                    print('Error while fetching messages list', file=sys.stderr)
                    break
                else:
                    adr = doEnvelope(hdr[1][0][1], True)
                    if adr != None:
                        if adr not in adrset:
                            adrset[adr] = 1
                        else:
                            adrset[adr] = adrset[adr]+1
            sys.stderr.write('\n')
        else:
            hdr = imap.fetch(f'{1:d}:{cnt:d}', '(RFC822.HEADER)')
            if hdr[0] != 'OK':
                print('Error while fetching messages list', file=sys.stderr)
            else:
                for h in hdr[1][::2]:
                    adr = doEnvelope(h[1])
                    if adr != None:
                        if adr not in adrset:
                            adrset[adr] = 1
                        else:
                            adrset[adr] = adrset[adr]+1

        for i in {a: c for a, c in sorted(adrset.items(), key=lambda item: item[1], reverse = True)}:
            print("{}\t{}".format(i, adrset[i]))
        print('Done.', file=sys.stderr)
    return
    
if __name__ == "__main__":
    ap = argparse.ArgumentParser(prog='yimap', description='List IMAP headers')
    ap.add_argument('-v', action='version', version='%(prog)s 0.1')
    ap.add_argument('--progress',  '-g', help='show progress on stderr', action='store_true', default=False)
    ap.add_argument('host',  help='IMAP host name')
    ap.add_argument('--port',  '-p', help='IMAP host port number (default: %(default)s)', type=int, default=993 )
    ap.add_argument('user', help='IMAP user name', metavar='username')

    sp = ap.add_subparsers(dest='auth', title='IMAP authentication method', 
                           description='Following authentication methods are supported')

    plogin = sp.add_parser('login', help='Use user/password authentication')
    plogin.add_argument('pswd',  help='IMAP user password', metavar='password')

    poauth = sp.add_parser('oauth2', help='Use OAuth2 authentication')
    poauth.add_argument('token',  help='file name with OAuth2 token')

    o = ap.parse_args()
    if o.host == None or o.port == None or (o.auth == 'login' and (o.user == None or o.pswd == None)) or \
            (o.auth == 'oauth2' and o.token == None):
        ap.print_help()
    else:
        try:
            main(o)
        except IMAP4.error as e:
            msg = e.args[0]
            if isinstance(msg, bytes):
                msg = msg.decode('utf-8')
            print('Ошибка: {}', msg)
