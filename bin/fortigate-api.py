#!/usr/bin/python3
"""Root-only setup and read-only connection check for the local FortiGate API.

The TLS hostname is deliberately separate from the private destination address.
Never disables certificate verification, follows redirects, or logs API bodies.
"""
import argparse
import datetime as dt
import getpass
import http.client
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import sys
import tempfile
import time
import warnings

CONFIG = Path('/etc/fls/fortigate-api.json')
HOST = 'fortigate.example.invalid'
ADDRESS = '192.0.2.1'
SOURCE = '192.0.2.2'
PORT = 29501
SERIAL = 'FGT0000000000000'
STATUS_PATH = '/api/v2/monitor/system/status?vdom=root'
MAX_BODY = 1024 * 1024


class ApiError(Exception):
    """Only constant, operator-safe messages may be used here."""


class LocalHTTPS(http.client.HTTPSConnection):
    def __init__(self):
        super().__init__(HOST, PORT, timeout=8, context=ssl.create_default_context())

    def connect(self):
        # Bind to the exact address allowed by the API user's trusted-host entry.
        raw = socket.create_connection((ADDRESS, PORT), self.timeout, (SOURCE, 0))
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=HOST)
        except BaseException:
            raw.close()
            raise


def validate_token(token):
    if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9._~+/=-]{16,512}', token):
        raise ApiError('API anahtarı geçersiz biçimde. Yalnız anahtar değerini girin.')
    return token


def status_request(token=None):
    """The only callable endpoint is a fixed GET; the token is never in a URL."""
    if token is not None:
        validate_token(token)
    connection = LocalHTTPS()
    started = time.monotonic()
    headers = {'Accept': 'application/json', 'User-Agent': 'FLS-local-api-check/1'}
    if token is not None:
        headers['Authorization'] = 'Bearer ' + token
    try:
        connection.request('GET', STATUS_PATH, headers=headers)
        response = connection.getresponse()
        code = response.status
        if token is None:
            if code not in (401, 403):
                raise ApiError('TLS doğrulandı; API kimlik doğrulama yanıtı beklenen 401/403 değil.')
            return {'tls_verified': True, 'unauthenticated_http_status': code,
                    'destination': ADDRESS, 'hostname': HOST, 'port': PORT, 'source': SOURCE}
        if code == 401:
            raise ApiError('HTTP 401: API anahtarı kabul edilmedi; hesap ve anahtar durumunu kontrol edin.')
        if code == 403:
            raise ApiError('HTTP 403: trusted-host, root VDOM veya sysgrp okuma yetkisini kontrol edin.')
        if code != 200:
            raise ApiError('API beklenen HTTP 200 yanıtını vermedi. Yönlendirmeler izlenmez.')
        if response.headers.get_content_type() != 'application/json':
            raise ApiError('API yanıtı JSON değil; yönetim/API adresini kontrol edin.')
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ApiError('API yanıtı güvenli boyut sınırını aşıyor.')
        try:
            data = json.loads(body)
        except (ValueError, UnicodeError):
            raise ApiError('API geçerli bir JSON yanıtı vermedi.') from None
        if not isinstance(data, dict) or data.get('status') != 'success':
            raise ApiError('API isteği başarılı olarak doğrulanamadı.')
        if data.get('serial') != SERIAL:
            raise ApiError('API yanıtındaki cihaz seri numarası beklenen FortiGate ile eşleşmiyor.')
        if data.get('vdom') != 'root':
            raise ApiError('API yanıtının VDOM kapsamı root değil.')
        # Do not print a raw response, reflected input, configuration, or token.
        version = data.get('version', '')
        if not isinstance(version, str) or not re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+', version):
            version = None
        build = data.get('build')
        if not isinstance(build, int) or isinstance(build, bool) or not 0 <= build <= 999999:
            build = None
        return {'connected': True, 'serial': SERIAL, 'vdom': 'root', 'version': version,
                'build': build, 'tls_verified': True, 'destination': ADDRESS, 'source': SOURCE,
                'hostname': HOST, 'port': PORT, 'latency_ms': round((time.monotonic() - started) * 1000, 1)}
    except ssl.SSLCertVerificationError:
        raise ApiError('TLS sertifikası/alan adı doğrulanamadı. Sertifika ve sunucu saatini kontrol edin.') from None
    except (TimeoutError, OSError, http.client.HTTPException):
        raise ApiError('Yerel HTTPS bağlantısı tamamlanamadı. Port, rota ve yönetim erişimini kontrol edin.') from None
    finally:
        connection.close()


def save_config(token, path=CONFIG):
    validate_token(token)
    data = {'schema': 1, 'hostname': HOST, 'connect_ip': ADDRESS, 'source_ip': SOURCE,
            'port': PORT, 'vdom': 'root', 'expected_serial': SERIAL,
            'saved_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'api_token': token}
    # mkstemp creates mode 0600 without inheriting any readable default ACL.
    fd, name = tempfile.mkstemp(prefix='.fortigate-api-', dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=True, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def load_token(path=CONFIG):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise ApiError('Gizli API yapılandırması okunamadı. Önce configure komutunu çalıştırın.') from None
    with os.fdopen(fd, 'r', encoding='utf-8') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077 or info.st_size > 16384:
            raise ApiError('API yapılandırması root sahibi ve yalnız root erişimli normal dosya olmalı (0600).')
        try:
            data = json.loads(stream.read(16385))
        except (ValueError, UnicodeError):
            raise ApiError('API yapılandırması geçersiz.') from None
    expected = {'schema': 1, 'hostname': HOST, 'connect_ip': ADDRESS, 'source_ip': SOURCE,
                'port': PORT, 'vdom': 'root', 'expected_serial': SERIAL}
    if not isinstance(data, dict) or any(data.get(k) != v for k, v in expected.items()):
        raise ApiError('API yapılandırmasındaki cihaz veya bağlantı kapsamı beklenen değerlerle eşleşmiyor.')
    return validate_token(data.get('api_token'))


def main():
    parser = argparse.ArgumentParser(description='FortiGate API anahtarını gizli kaydetme ve salt okuma bağlantı kontrolü.')
    parser.add_argument('command', choices=['probe', 'configure', 'check'])
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.exit(1, 'Bu araç root olarak çalıştırılmalı.\n')
    try:
        if args.command == 'probe':
            result = status_request()
        elif args.command == 'configure':
            if not sys.stdin.isatty():
                raise ApiError('Anahtar yalnız etkileşimli terminalde, gizli girişle alınır. Pipe veya komut argümanı kullanmayın.')
            # Test TLS before asking for a secret; TLS is checked again on the authenticated request.
            status_request()
            with warnings.catch_warnings():
                # Abort instead of allowing getpass's echoing fallback on an unsuitable TTY.
                warnings.simplefilter('error', getpass.GetPassWarning)
                token = validate_token(getpass.getpass('FortiGate API anahtarı (ekranda görünmez): ').strip())
            result = status_request(token)
            save_config(token)
            print('Anahtar /etc/fls/fortigate-api.json dosyasına yalnız root erişimiyle (0600) kaydedildi.')
        else:
            result = status_request(load_token())
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (ApiError, PermissionError) as error:
        message = str(error) if isinstance(error, ApiError) else 'Dosya erişim izni yetersiz.'
        parser.exit(1, message + '\n')
    except (KeyboardInterrupt, EOFError):
        parser.exit(1, '\nİşlem iptal edildi.\n')
    except Exception:
        # A traceback/exception message can include server-controlled or secret text.
        parser.exit(1, 'Bağlantı/yapılandırma işlemi tamamlanamadı; ayrıntılı yanıt güvenlik gereği yazdırılmadı.\n')


if __name__ == '__main__':
    main()
