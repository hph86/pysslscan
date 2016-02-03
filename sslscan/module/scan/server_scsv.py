from sslscan import modules
from sslscan.module.scan import BaseScan

import flextls
from flextls.field import CipherSuiteField
from flextls.protocol.handshake import Handshake, ServerHello
from flextls.protocol.alert import Alert
import six
from sslscan.exception import Timeout

if six.PY2:
    import socket
    ConnectionError = socket.error


class ServerSCSV(BaseScan):
    """
    Detect if the server supports the Signaling Cipher Suite Value (SCSV).
    """

    name = "server.scsv"
    alias = ("scsv",)

    def __init__(self, **kwargs):
        BaseScan.__init__(self, **kwargs)

    def _connect_with_scsv(self, protocol_version, cipher_suites):
        def hook_cipher_suites(record, cipher_suites=None):
            for i in cipher_suites:
                cipher = CipherSuiteField()
                cipher.value = i
                record.payload.cipher_suites.append(cipher)

            cipher = CipherSuiteField()
            cipher.value = 0x5600
            record.payload.cipher_suites.append(cipher)

            return record

        def stop_condition(record, records):
            return (isinstance(record, Handshake) and
                    isinstance(record.payload, ServerHello))

        ver_major, ver_minor = flextls.helper.get_tls_version(protocol_version)

        is_dtls = False
        if protocol_version & flextls.registry.version.DTLS != 0:
            is_dtls = True

        if is_dtls:
            self.build_dtls_client_hello_hooks.connect(
                hook_cipher_suites,
                name="cipher_suites",
                args={
                    "cipher_suites": cipher_suites
                }
            )
        else:
            self.build_tls_client_hello_hooks.connect(
                hook_cipher_suites,
                name="cipher_suites",
                args={
                    "cipher_suites": cipher_suites
                }
            )

        records = self.connect(
            protocol_version,
            stop_condition=stop_condition
        )

        if records is None:
            return None

        for record in records:
            if isinstance(record, Handshake):
                if isinstance(record.payload, ServerHello):
                    if record.payload.version.major == ver_major and \
                            record.payload.version.minor == ver_minor:
                        return False
            elif isinstance(record, Alert):
                if record.level == 2 and record.description == 86:
                    return True

    def run(self):
        kb = self._scanner.get_knowledge_base()
        protocol_versions = self._scanner.get_enabled_versions()
        protocol_versions.reverse()
        scsv_status = None
        kb.set("server.security.scsv", None)
        for protocol_version in protocol_versions:
            if protocol_version != flextls.registry.version.SSLv2:
                cipher_suites = flextls.registry.tls.cipher_suites.get_ids()
                scsv_cur_status = None
                try:
                    scsv_cur_status = self._connect_with_scsv(
                        protocol_version,
                        cipher_suites
                    )
                except Timeout:
                    continue

                if scsv_cur_status is None:
                    continue

                if scsv_cur_status is True:
                    kb.set("server.security.scsv", True)
                    break

                # At least two protocol versions must reach a ServerHello in
                # order to falsify SCSV security. Otherwise, if we
                # coincidentally use the highest protocol version that the
                # server supports, the server has to proceed with the
                # handshake, even if the SCSV suite is present (see RFC 7507,
                # section 3).
                if scsv_status is False and scsv_cur_status is False:
                    kb.set("server.security.scsv", False)
                    break

                scsv_status = scsv_cur_status


modules.register(ServerSCSV)
