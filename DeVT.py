lllllllllllllll, llllllllllllllI, lllllllllllllIl, lllllllllllllII, llllllllllllIll, llllllllllllIlI, llllllllllllIIl = print, FileNotFoundError, Exception, input, bool, open, __name__

from base64 import urlsafe_b64encode as IlIlllIIlIIIII
from requests import post as lIlllIllllllll, get as IllIIIllIllIll

def IIIIlIlIllllIIlIll():
    lllllllllllllll('\n  ___    __   _______ \n |   \\ __\\ \\ / /_   _|\n | |) / -_) V /  | |  \n |___/\\___|\\_/   |_|  \n                       \n===== DeVT - Pemindai VirusTotal =====\n    ')
IIlIlIIIlIlIIIlIIl = '26965bce2afbe77d763eb1d414e2236062a16cd2de26efba6e0b55c952efa56e'

def IIIIllIlllIIIllIII(llllIIIIIllIllIIlI):
    llIlIIlIIIIllIllIl = llllIIIIIllIllIIlI.encode('utf-8')
    IIIIllllllIIllIIlI = IlIlllIIlIIIII(llIlIIlIIIIllIllIl)
    return IIIIllllllIIllIIlI.decode('utf-8').strip('=')

def llllIIlIIlIIIlllll():
    llllIIIIIllIllIIlI = lllllllllllllII('Masukkan URL untuk dipindai: ')
    try:
        lIllIlllIIIllIllII = IIIIllIlllIIIllIII(llllIIIIIllIllIIlI)
        lllllIlIIlIlIIlllI = {'x-apikey': IIlIlIIIlIlIIIlIIl}
        lIIIlIlIIIlIlIIIll = IllIIIllIllIll(f'https://www.virustotal.com/api/v3/urls/{lIllIlllIIIllIllII}', headers=lllllIlIIlIlIIlllI)
        if lIIIlIlIIIlIlIIIll.status_code != 200:
            lllllllllllllll(f"Kesalahan: {lIIIlIlIIIlIlIIIll.status_code}, {lIIIlIlIIIlIlIIIll.json().get('error', {}).get('message', 'Tidak diketahui')}")
            return
        llIllllllIIIlIllIl = lIIIlIlIIIlIlIIIll.json()
        lllIlIIIlIIIIIIIll = llIllllllIIIlIllIl.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
        if not lllIlIIIlIIIIIIIll:
            lllllllllllllll('Tidak ada hasil analisis yang ditemukan.')
            return
        lllllllllllllll('\n===== Laporan Pemindaian =====')
        for (lllIIllIlIllIIIIII, IlIllIIlllIlIlIllI) in lllIlIIIlIIIIIIIll.items():
            llllllIlIIIIIlllIl = IlIllIIlllIlIlIllI.get('result', 'Unrated')
            lllllllllllllll(f'{lllIIllIlIllIIIIII:30}: {llllllIlIIIIIlllIl}')
    except lllllllllllllIl as IlIllIlIIlIIlIIlII:
        lllllllllllllll(f'Terjadi kesalahan: {IlIllIlIIlIIlIIlII}')

def IllIlIlIIIlIllllIl():
    lIllIllIIlIlIllIlI = lllllllllllllII('Masukkan lokasi file untuk dipindai: ')
    try:
        with llllllllllllIlI(lIllIllIIlIlIllIlI, 'rb') as IlIlllIIlIIIIIIlII:
            lIIIlIlIIllIlIIlll = {'file': IlIlllIIlIIIIIIlII}
            lllllIlIIlIlIIlllI = {'x-apikey': IIlIlIIIlIlIIIlIIl}
            lIIIlIlIIIlIlIIIll = lIlllIllllllll('https://www.virustotal.com/api/v3/files', headers=lllllIlIIlIlIIlllI, files=lIIIlIlIIllIlIIlll)
            if lIIIlIlIIIlIlIIIll.status_code != 200:
                lllllllllllllll(f"Kesalahan: {lIIIlIlIIIlIlIIIll.status_code}, {lIIIlIlIIIlIlIIIll.json().get('error', {}).get('message', 'Tidak diketahui')}")
                return
            llIllllllIIIlIllIl = lIIIlIlIIIlIlIIIll.json()
            lllIlIIIlIIIIIIIll = llIllllllIIIlIllIl.get('data', {}).get('attributes', {}).get('last_analysis_results', {})
            if not lllIlIIIlIIIIIIIll:
                lllllllllllllll('Tidak ada hasil analisis yang ditemukan.')
                return
            lllllllllllllll('\n===== Laporan Pemindaian =====')
            for (lllIIllIlIllIIIIII, IlIllIIlllIlIlIllI) in lllIlIIIlIIIIIIIll.items():
                llllllIlIIIIIlllIl = IlIllIIlllIlIlIllI.get('result', 'Unrated')
                lllllllllllllll(f'{lllIIllIlIllIIIIII:30}: {llllllIlIIIIIlllIl}')
    except llllllllllllllI:
        lllllllllllllll('File tidak ditemukan.')
    except lllllllllllllIl as IlIllIlIIlIIlIIlII:
        lllllllllllllll(f'Terjadi kesalahan: {IlIllIlIIlIIlIIlII}')

def llllIIIIlIIllIIlII():
    while llllllllllllIll(((1 & 0 ^ 0) & 0 ^ 1) & 0 ^ 1 ^ 1 ^ 0 | 1):
        IIIIlIlIllllIIlIll()
        lllllllllllllll('1. Scan URL')
        lllllllllllllll('2. Scan File')
        lllllllllllllll('3. Keluar')
        IlIIlIlllIIlIIIlIl = lllllllllllllII('Pilih opsi: ')
        if IlIIlIlllIIlIIIlIl == '1':
            llllIIlIIlIIIlllll()
        elif IlIIlIlllIIlIIIlIl == '2':
            IllIlIlIIIlIllllIl()
        elif IlIIlIlllIIlIIIlIl == '3':
            lllllllllllllll('Keluar dari DeVT. Tetap aman!')
            break
        else:
            lllllllllllllll('Pilihan tidak valid. Coba lagi.')
if llllllllllllIIl == '__main__':
    llllIIIIlIIllIIlII()