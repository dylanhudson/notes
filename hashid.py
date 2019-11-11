#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Oct 18 21:46:49 2019

@author: dylan
"""

# -*- coding: utf-8 -*-
"""
extract-hashes.py: Extracts hashes from a text file.
Version 0.3 - Nov/2014
Author: Daniel Marques (@0xc0da)
Modified by Dylan in Nov 2019 to incorporate more regexs. 
daniel _at_ codalabs _dot_ net - http://codalabs.net
The script reads a file and tries to extract hashes from it by using regex. 
Results are stored in separate files named as 'format-original_filename.txt'.
Supported formats and regex can be found in the 'regex_list' dictionary.
WARNING: Use carefully. It might return garbage or miss some hashes.
"""


import re
import sys
from os import path

def extract_hashes(source_file):
	regex_list = {
	
		'wordpress_md5': '\$P\$[\w\d./]+',
		'phpBB3_md5': '\$H\$[\w\d./]+',
		'sha1':  '(?<!\w)[a-f\d]{40}(?!\w)',
		'md5':  '(?<!\w)[a-f\d]{32}(?!\w)',
		'sha256':  '(?<!\w)[a-f\d]{64}(?!\w)',
		'sha512':  '(?<!\w)[a-f\d]{128}(?!\w)',
		'mysql':  '(?<!\w)[a-f\d]{16}(?!\w)',
		'mysql5': '\*[A-F\d]{40}',
        'CRC-16' : '^[a-f0-9]{4}$',
        'CRC-16-CCITT' : '^[a-f0-9]{4}$',
        'FCS-16' : '^[a-f0-9]{4}$',
        'Adler-32' : '^[a-f0-9]{8}$',
         'CRC-32B' : '^[a-f0-9]{8}$',
         'FCS-32' : '^[a-f0-9]{8}$',
         'GHash-32-3' : '^[a-f0-9]{8}$',
         'GHash-32-5' : '^[a-f0-9]{8}$',
         'FNV-132' : '^[a-f0-9]{8}$',
         'Fletcher-32' : '^[a-f0-9]{8}$',
         'Joaat' : '^[a-f0-9]{8}$',
         'ELF-32' : '^[a-f0-9]{8}$',
         'XOR-32' : '^[a-f0-9]{8}$',
         'CRC-24' : '^[a-f0-9]{6}$',
         'CRC-32' : '^(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}$',
         'Eggdrop IRC Bot' : '^\+[a-z0-9\/.]{12}$',
         'DES(Unix)' : '^[a-z0-9\/.]{13}$',
         'Traditional DES' : '^[a-z0-9\/.]{13}$',
         'DEScrypt' : '^[a-z0-9\/.]{13}$',
         'MySQL323' : '^[a-f0-9]{16}$',
         'DES(Oracle)' : '^[a-f0-9]{16}$',
         'Half MD5' : '^[a-f0-9]{16}$',
         'Oracle 7-10g' : '^[a-f0-9]{16}$',
         'FNV-164' : '^[a-f0-9]{16}$',
         'CRC-64' : '^[a-f0-9]{16}$',
         'Cisco-PIX(MD5)' : '^[a-z0-9\/.]{16}$',
         'Lotus Notes/Domino 6' : '^\([a-z0-9\/+]{20}\)$',
         'BSDi Crypt' : '^_[a-z0-9\/.]{19}$',
         'CRC-96(ZIP)' : '^[a-f0-9]{24}$',
         'Crypt16' : '^[a-z0-9\/.]{24}$',
         'MD2' : '^(\$md2\$)?[a-f0-9]{32}$',
         'MD5' : '^[a-f0-9]{32}(:.+)?$',
         'MD4' : '^[a-f0-9]{32}(:.+)?$',
         'Double MD5' : '^[a-f0-9]{32}(:.+)?$',
         'LM' : '^[a-f0-9]{32}(:.+)?$',
         'RIPEMD-128' : '^[a-f0-9]{32}(:.+)?$',
         'Haval-128' : '^[a-f0-9]{32}(:.+)?$',
         'Tiger-128' : '^[a-f0-9]{32}(:.+)?$',
         'Skein-256(128)' : '^[a-f0-9]{32}(:.+)?$',
         'Skein-512(128)' : '^[a-f0-9]{32}(:.+)?$',
         'Lotus Notes/Domino 5' : '^[a-f0-9]{32}(:.+)?$',
         'Skype' : '^[a-f0-9]{32}(:.+)?$',
         'ZipMonster' : '^[a-f0-9]{32}(:.+)?$',
         'PrestaShop' : '^[a-f0-9]{32}(:.+)?$',
         'md5(md5(md5($pass)))' : '^[a-f0-9]{32}(:.+)?$',
         'md5(strtoupper(md5($pass)))' : '^[a-f0-9]{32}(:.+)?$',
         'md5(sha1($pass))' : '^[a-f0-9]{32}(:.+)?$',
         'md5($pass.$salt)' : '^[a-f0-9]{32}(:.+)?$',
         'md5($salt.$pass)' : '^[a-f0-9]{32}(:.+)?$',
         'md5(unicode($pass).$salt)' : '^[a-f0-9]{32}(:.+)?$',
         'md5($salt.unicode($pass))' : '^[a-f0-9]{32}(:.+)?$',
         'HMAC-MD5 (key = $pass)' : '^[a-f0-9]{32}(:.+)?$',
         'HMAC-MD5 (key = $salt)' : '^[a-f0-9]{32}(:.+)?$',
         'md5(md5($salt).$pass)' : '^[a-f0-9]{32}(:.+)?$',
         'md5($salt.md5($pass))' : '^[a-f0-9]{32}(:.+)?$',
         'md5($pass.md5($salt))' : '^[a-f0-9]{32}(:.+)?$',
         'md5($salt.$pass.$salt)' : '^[a-f0-9]{32}(:.+)?$',
         'md5(md5($pass).md5($salt))' : '^[a-f0-9]{32}(:.+)?$',
         'md5($salt.md5($salt.$pass))' : '^[a-f0-9]{32}(:.+)?$',
         'md5($salt.md5($pass.$salt))' : '^[a-f0-9]{32}(:.+)?$',
         'md5($username.0.$pass)' : '^[a-f0-9]{32}(:.+)?$',
         'Snefru-128' : '^(\$snefru\$)?[a-f0-9]{32}$',
         'NTLM' : '^(\$NT\$)?[a-f0-9]{32}$',
         'Domain Cached Credentials' : '^([^\/:*?"<>|]{1,20}:)?[a-f0-9]{32}(:[^\/:*?"<>|]{1,20})?$',
         'Domain Cached Credentials 2' : '^([^\/:*?"<>|]{1,20}:)?(\$DCC2\$10240#[^\/:*?"<>|]{1,20}#)?[a-f0-9]{32}$',
         'SHA-1(Base64)' : '^{SHA}[a-z0-9\/+]{27}=$',
         'Netscape LDAP SHA' : '^{SHA}[a-z0-9\/+]{27}=$',
         'MD5 Crypt' : '^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$',
         'Cisco-IOS(MD5)' : '^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$',
         'FreeBSD MD5' : '^\$1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}(:.*)?$',
         'Lineage II C4' : '^0x[a-f0-9]{32}$',
         'phpBB v3.x' : '^\$H\$[a-z0-9\/.]{31}$',
         'Wordpress v2.6.0/2.6.1' : '^\$H\$[a-z0-9\/.]{31}$',
         'Wordpress ≥ v2.6.2' : '^\$P\$[a-z0-9\/.]{31}$',
         'Joomla ≥ v2.5.18' : '^\$P\$[a-z0-9\/.]{31}$',
         'osCommerce' : '^[a-f0-9]{32}:[a-z0-9]{2}$',
         'xt:Commerce' : '^[a-f0-9]{32}:[a-z0-9]{2}$',
         'MD5(APR)' : '^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$',
         'Apache MD5' : '^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$',
         'md5apr1' : '^\$apr1\$[a-z0-9\/.]{0,8}\$[a-z0-9\/.]{22}$',
         'AIX(smd5)' : '^{smd5}[a-z0-9$\/.]{31}$',
         'WebEdition CMS' : '^[a-f0-9]{32}:[a-f0-9]{32}$',
         'IP.Board ≥ v2+' : '^[a-f0-9]{32}:.{5}$',
         'MyBB ≥ v1.2+' : '^[a-f0-9]{32}:.{8}$',
         'CryptoCurrency(Adress)' : '^[a-z0-9]{34}$',
         'SHA-1' : '^[a-f0-9]{40}(:.+)?$',
         'Double SHA-1' : '^[a-f0-9]{40}(:.+)?$',
         'RIPEMD-160' : '^[a-f0-9]{40}(:.+)?$',
         'Haval-160' : '^[a-f0-9]{40}(:.+)?$',
         'Tiger-160' : '^[a-f0-9]{40}(:.+)?$',
         'HAS-160' : '^[a-f0-9]{40}(:.+)?$',
         'LinkedIn' : '^[a-f0-9]{40}(:.+)?$',
         'Skein-256(160)' : '^[a-f0-9]{40}(:.+)?$',
         'Skein-512(160)' : '^[a-f0-9]{40}(:.+)?$',
         'MangosWeb Enhanced CMS' : '^[a-f0-9]{40}(:.+)?$',
         'sha1(sha1(sha1($pass)))' : '^[a-f0-9]{40}(:.+)?$',
         'sha1(md5($pass))' : '^[a-f0-9]{40}(:.+)?$',
         'sha1($pass.$salt)' : '^[a-f0-9]{40}(:.+)?$',
         'sha1($salt.$pass)' : '^[a-f0-9]{40}(:.+)?$',
         'sha1(unicode($pass).$salt)' : '^[a-f0-9]{40}(:.+)?$',
         'sha1($salt.unicode($pass))' : '^[a-f0-9]{40}(:.+)?$',
         'HMAC-SHA1 (key = $pass)' : '^[a-f0-9]{40}(:.+)?$',
         'HMAC-SHA1 (key = $salt)' : '^[a-f0-9]{40}(:.+)?$',
         'sha1($salt.$pass.$salt)' : '^[a-f0-9]{40}(:.+)?$',
         'MySQL5.x' : '^\*[a-f0-9]{40}$',
         'MySQL4.1' : '^\*[a-f0-9]{40}$',
         'Cisco-IOS(SHA-256)' : '^[a-z0-9]{43}$',
         'SSHA-1(Base64)' : '^{SSHA}[a-z0-9\/+]{38}==$',
         'Netscape LDAP SSHA' : '^{SSHA}[a-z0-9\/+]{38}==$',
         'nsldaps' : '^{SSHA}[a-z0-9\/+]{38}==$',
         'Fortigate(FortiOS)' : '^[a-z0-9=]{47}$',
         'Haval-192' : '^[a-f0-9]{48}$',
         'Tiger-192' : '^[a-f0-9]{48}$',
         'SHA-1(Oracle)' : '^[a-f0-9]{48}$',
         'OSX v10.4' : '^[a-f0-9]{48}$',
         'OSX v10.5' : '^[a-f0-9]{48}$',
         'OSX v10.6' : '^[a-f0-9]{48}$',
         'Palshop CMS' : '^[a-f0-9]{51}$',
         'CryptoCurrency(PrivateKey)' : '^[a-z0-9]{51}$',
         'AIX(ssha1)' : '^{ssha1}[0-9]{2}\$[a-z0-9$\/.]{44}$',
         'MSSQL(2005)' : '^0x0100[a-f0-9]{48}$',
         'MSSQL(2008)' : '^0x0100[a-f0-9]{48}$',
         'Sun MD5 Crypt' : '^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9\/.]{0,16}(\$|\$\$)[a-z0-9\/.]{22}$',
         'SHA-224' : '^[a-f0-9]{56}$',
         'Haval-224' : '^[a-f0-9]{56}$',
         'SHA3-224' : '^[a-f0-9]{56}$',
         'Skein-256(224)' : '^[a-f0-9]{56}$',
         'Skein-512(224)' : '^[a-f0-9]{56}$',
         'Blowfish(OpenBSD)' : '^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$',
         'Woltlab Burning Board 4.x' : '^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$',
         'bcrypt' : '^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$',
         'Android PIN' : '^[a-f0-9]{40}:[a-f0-9]{16}$',
         'Oracle 11g/12c' : '^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$',
         'bcrypt(SHA-256)' : '^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9\/.]{22}\$[a-z0-9\/.]{31}$',
         'vBulletin < v3.8.5' : '^[a-f0-9]{32}:.{3}$',
         'vBulletin ≥ v3.8.5' : '^[a-f0-9]{32}:.{30}$',
         'Snefru-256' : '^(\$snefru\$)?[a-f0-9]{64}$',
         'SHA-256' : '^[a-f0-9]{64}(:.+)?$',
         'RIPEMD-256' : '^[a-f0-9]{64}(:.+)?$',
         'Haval-256' : '^[a-f0-9]{64}(:.+)?$',
         'GOST R 34.11-94' : '^[a-f0-9]{64}(:.+)?$',
         'GOST CryptoPro S-Box' : '^[a-f0-9]{64}(:.+)?$',
         'SHA3-256' : '^[a-f0-9]{64}(:.+)?$',
         'Skein-256' : '^[a-f0-9]{64}(:.+)?$',
         'Skein-512(256)' : '^[a-f0-9]{64}(:.+)?$',
         'Ventrilo' : '^[a-f0-9]{64}(:.+)?$',
         'sha256($pass.$salt)' : '^[a-f0-9]{64}(:.+)?$',
         'sha256($salt.$pass)' : '^[a-f0-9]{64}(:.+)?$',
         'sha256(unicode($pass).$salt)' : '^[a-f0-9]{64}(:.+)?$',
         'sha256($salt.unicode($pass))' : '^[a-f0-9]{64}(:.+)?$',
         'HMAC-SHA256 (key = $pass)' : '^[a-f0-9]{64}(:.+)?$',
         'HMAC-SHA256 (key = $salt)' : '^[a-f0-9]{64}(:.+)?$',
         'Joomla < v2.5.18' : '^[a-f0-9]{32}:[a-z0-9]{32}$',
         'SAM(LM_Hash:NT_Hash)' : '^[a-f-0-9]{32}:[a-f-0-9]{32}$',
         'MD5(Chap)' : '^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$',
         'iSCSI CHAP Authentication' : '^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$',
         'EPiServer 6.x < v4' : '^\$episerver\$\*0\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{27,28}$',
         'AIX(ssha256)' : '^{ssha256}[0-9]{2}\$[a-z0-9$\/.]{60}$',
         'RIPEMD-320' : '^[a-f0-9]{80}$',
         'EPiServer 6.x ≥ v4' : '^\$episerver\$\*1\*[a-z0-9\/=+]+\*[a-z0-9\/=+]{42,43}$',
         'MSSQL(2000)' : '^0x0100[a-f0-9]{88}$',
         'SHA-384' : '^[a-f0-9]{96}$',
         'SHA3-384' : '^[a-f0-9]{96}$',
         'Skein-512(384)' : '^[a-f0-9]{96}$',
         'Skein-1024(384)' : '^[a-f0-9]{96}$',
         'SSHA-512(Base64)' : '^{SSHA512}[a-z0-9\/+]{96}$',
         'LDAP(SSHA-512)' : '^{SSHA512}[a-z0-9\/+]{96}$',
         'AIX(ssha512)' : '^{ssha512}[0-9]{2}\$[a-z0-9\/.]{16,48}\$[a-z0-9\/.]{86}$',
         'SHA-512' : '^[a-f0-9]{128}(:.+)?$',
         'Whirlpool' : '^[a-f0-9]{128}(:.+)?$',
         'Salsa10' : '^[a-f0-9]{128}(:.+)?$',
         'Salsa20' : '^[a-f0-9]{128}(:.+)?$',
         'SHA3-512' : '^[a-f0-9]{128}(:.+)?$',
         'Skein-512' : '^[a-f0-9]{128}(:.+)?$',
         'Skein-1024(512)' : '^[a-f0-9]{128}(:.+)?$',
         'sha512($pass.$salt)' : '^[a-f0-9]{128}(:.+)?$',
         'sha512($salt.$pass)' : '^[a-f0-9]{128}(:.+)?$',
         'sha512(unicode($pass).$salt)' : '^[a-f0-9]{128}(:.+)?$',
         'sha512($salt.unicode($pass))' : '^[a-f0-9]{128}(:.+)?$',
         'HMAC-SHA512 (key = $pass)' : '^[a-f0-9]{128}(:.+)?$',
         'HMAC-SHA512 (key = $salt)' : '^[a-f0-9]{128}(:.+)?$',
         'OSX v10.7' : '^[a-f0-9]{136}$',
         'MSSQL(2012)' : '^0x0200[a-f0-9]{136}$',
         'MSSQL(2014)' : '^0x0200[a-f0-9]{136}$',
         'OSX v10.8' : '^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$',
         'OSX v10.9' : '^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$',
         'Skein-1024' : '^[a-f0-9]{256}$',
         'GRUB 2' : '^grub\.pbkdf2\.sha512\.[0-9]+\.([a-f0-9]{128,2048}\.|[0-9]+\.)?[a-f0-9]{128}$',
         'Django(SHA-1)' : '^sha1\$[a-z0-9]+\$[a-f0-9]{40}$',
         'Citrix Netscaler' : '^[a-f0-9]{49}$',
         'Drupal > v7.x' : '^\$S\$[a-z0-9\/.]{52}$',
         'SHA-256 Crypt' : '^\$5\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{43}$',
         'Sybase ASE' : '^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$',
         'SHA-512 Crypt' : '^\$6\$(rounds=[0-9]+\$)?[a-z0-9\/.]{0,16}\$[a-z0-9\/.]{86}$',
         'Minecraft(AuthMe Reloaded)' : '^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$',
         'Django(SHA-256)' : '^sha256\$[a-z0-9]+\$[a-f0-9]{64}$',
         'Django(SHA-384)' : '^sha384\$[a-z0-9]+\$[a-f0-9]{96}$',
         'Clavister Secure Gateway' : '^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$',
         'Cisco VPN Client(PCF-File)' : '^[a-f0-9]{112}$',
         'Microsoft MSTSC(RDP-File)' : '^[a-f0-9]{1329}$',
         'NetNTLMv1-VANILLA / NetNTLMv1+ESS' : '^[^\/:*?"<>|]{1,20}[:]{2,3}([^\/:*?"<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$',
         'NetNTLMv2' : '^([^\/:*?"<>|]{1,20}\)?[^\/:*?"<>|]{1,20}[:]{2,3}([^\/:*?"<>|]{1,20}:)?[^\/:*?"<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$',
         'Kerberos 5 AS-REQ Pre-Auth' : '^\$(krb5pa|mskrb5)\$([0-9]{2})?\$.+\$[a-f0-9]{1,}$',
         'SCRAM Hash' : '^\$scram\$[0-9]+\$[a-z0-9\/.]{16}\$sha-1=[a-z0-9\/.]{27},sha-256=[a-z0-9\/.]{43},sha-512=[a-z0-9\/.]{86}$',
         'Redmine Project Management Web App' : '^[a-f0-9]{40}:[a-f0-9]{0,32}$',
         'SAP CODVN B (BCODE)' : '^(.+)?\$[a-f0-9]{16}$',
         'SAP CODVN F/G (PASSCODE)' : '^(.+)?\$[a-f0-9]{40}$',
         'Juniper Netscreen/SSG(ScreenOS)' : '^(.+\$)?[a-z0-9\/.+]{30}(:.+)?$',
         'EPi' : '^0x[a-f0-9]{60}\s0x[a-f0-9]{40}$',
         'SMF ≥ v1.1' : '^[a-f0-9]{40}:[^*]{1,25}$',
         'Woltlab Burning Board 3.x' : '^(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$',
         'IPMI2 RAKP HMAC-SHA1' : '^[a-f0-9]{130}(:[a-f0-9]{40})?$',
         'Lastpass' : '^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$',
         'Cisco-ASA(MD5)' : '^[a-z0-9\/.]{16}([:$].{1,})?$',
         'VNC' : '^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$',
         'DNSSEC(NSEC3)' : '^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$',
         'RACF' : '^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$',
         'NTHash(FreeBSD Variant)' : '^\$3\$\$[a-f0-9]{32}$',
         'SHA-1 Crypt' : '^\$sha1\$[0-9]+\$[a-z0-9\/.]{0,64}\$[a-z0-9\/.]{28}$',
         'hMailServer' : '^[a-f0-9]{70}$',
         'MediaWiki' : '^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$',
         'Minecraft(xAuth)' : '^[a-f0-9]{140}$',
         'PBKDF2-SHA1(Generic)' : '^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{27}$',
         'PBKDF2-SHA256(Generic)' : '^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{43}$',
         'PBKDF2-SHA512(Generic)' : '^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{86}$',
         'PBKDF2(Cryptacular)' : '^\$p5k2\$[0-9]+\$[a-z0-9\/+=-]+\$[a-z0-9\/+-]{27}=$',
         'PBKDF2(Dwayne Litzenberger)' : '^\$p5k2\$[0-9]+\$[a-z0-9\/.]+\$[a-z0-9\/.]{32}$',
         'Fairly Secure Hashed Password' : '^{FSHP[0123]\|[0-9]+\|[0-9]+}[a-z0-9\/+=]+$',
         'PHPS' : '^\$PHPS\$.+\$[a-f0-9]{32}$',
         '1Password(Agile Keychain)' : '^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$',
         '1Password(Cloud Keychain)' : '^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$',
         'IKE-PSK MD5' : '^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$',
         'IKE-PSK SHA1' : '^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$',
         'PeopleSoft' : '^[a-z0-9\/+]{27}=$',
         'Django(DES Crypt Wrapper)' : '^crypt\$[a-f0-9]{5}\$[a-z0-9\/.]{13}$',
         'Django(PBKDF2-HMAC-SHA256)' : '^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{44}$',
         'Django(PBKDF2-HMAC-SHA1)' : '^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9\/+=]{28}$',
         'Django(bcrypt)' : '^bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9\/.]{53}$',
         'Django(MD5)' : '^md5\$[a-f0-9]+\$[a-f0-9]{32}$',
         'PBKDF2(Atlassian)' : '^\{PKCS5S2\}[a-z0-9\/+]{64}$',
         'PostgreSQL MD5' : '^md5[a-f0-9]{32}$',
         'Lotus Notes/Domino 8' : '^\([a-z0-9\/+]{49}\)$',
         'scrypt' : '^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:\/+=]{1,}$',
         'Cisco Type 8' : '^\$8\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$',
         'Cisco Type 9' : '^\$9\$[a-z0-9\/.]{14}\$[a-z0-9\/.]{43}$',
         'Microsoft Office 2007' : '^\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}$',
         'Microsoft Office 2010' : '^\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$',
         'Microsoft Office 2013' : '^\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$',
         'Android FDE ≤ 4.3' : '^\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}$',
         'Microsoft Office ≤ 2003 (MD5+RC4)' : '^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$',
         'Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #1' : '^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$',
         'Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #2' : '^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$',
         'Microsoft Office ≤ 2003 (SHA1+RC4)' : '^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$',
         'Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #1' : '^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$',
         'Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #2' : '^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$',
         'RAdmin v2.x' : '^(\$radmin2\$)?[a-f0-9]{32}$',
         'SAP CODVN H (PWDSALTEDHASH) iSSHA-1' : '^{x-issha,\s[0-9]{4}}[a-z0-9\/+=]+$',
         'CRAM-MD5' : '^\$cram_md5\$[a-z0-9\/+=-]+\$[a-z0-9\/+=-]{52}$',
         'SipHash' : '^[a-f0-9]{16}:2:4:[a-f0-9]{32}$',
         'Cisco Type 7' : '^[a-f0-9]{4,}$',
         'BigCrypt' : '^[a-z0-9\/.]{13,}$',
         'Cisco Type 4' : '^(\$cisco4\$)?[a-z0-9\/.]{43}$',
         'Django(bcrypt-SHA256)' : '^bcrypt_sha256\$\$(2[axy]|2)\$[0-9]+\$[a-z0-9\/.]{53}$',
         'PostgreSQL Challenge-Response Authentication (MD5)' : '^\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$',
         'Siemens-S7' : '^\$siemens-s7\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}$',
         'Microsoft Outlook PST' : '^(\$pst\$)?[a-f0-9]{8}$',
         'PBKDF2-HMAC-SHA256(PHP)' : '^sha256[:$][0-9]+[:$][a-z0-9\/+]+[:$][a-z0-9\/+]{32,128}$',
         'Dahua' : '^(\$dahua\$)?[a-z0-9]{8}$',
         'MySQL Challenge-Response Authentication (SHA1)' : '^\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}$',
         'PDF 1.4 - 1.6 (Acrobat 5 - 8)' : '^\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}$'
	
	}
	
	result = {}
	
	fh = open(source_file, 'r')
	source_file_contents = fh.read()
	fh.close()
	
	for format in regex_list.keys():
		hashes = []
		regex = re.compile(regex_list[format])
		hashes = regex.findall(source_file_contents)
		if hashes:
			result[format] = hashes

	return result

def hashes_to_files(hashes, original_file):
	for format in hashes.keys():
		prefix = path.splitext(path.basename(original_file))[0]
		filename = '%s-%s.txt' % (format, prefix)
		with open(filename,'w') as output_file:
			for found_hash in hashes[format]:
				line = '%s\n' % found_hash
				output_file.write(line)
                

def main():
	extracted_hashes = {}
	print(len(sys.argv))

	if len(sys.argv) != 3:
		print ("Missing input file.")
		print ('Use: %s <filename>' % sys.argv[0])
		sys.exit(1)

	if not path.exists(sys.argv[1]):
		print ('File %s does not exists.' % sys.argv[1])
		sys.exit(1)

	extracted_hashes = extract_hashes(sys.argv[1])

	if extracted_hashes:
		hashes_to_files(extracted_hashes, sys.argv[1])
	
	print ('\nExtracted hashes:')
	
	for format in extracted_hashes.keys():
		print ('\t%s: %s' % (format, len(extracted_hashes[format])))

if __name__ == '__main__':
	main()
