from sslscan import modules
from sslscan._helper.openssl import (
    version_openssl,
    version_pyopenssl,
    convert_versions2methods
    )
from sslscan.module import STATUS_OK, STATUS_ERROR
from sslscan.module.scan import BaseInfoScan

openssl_enabled = False
version_info = []
try:
    from OpenSSL import _util

    openssl_enabled = True
    if version_pyopenssl:
        version_info.append("pyOpenSSL version {}".format(version_pyopenssl))
    if version_openssl:
        version_info.append("OpenSSL version {}".format(version_openssl))
except ImportError:
    pass


class ServerRenegotiation(BaseInfoScan):
    """
    Test if renegotiation is supported by the server.
    """

    name = "server.renegotiation"
    alias = ("renegotiation",)
    status = STATUS_OK if openssl_enabled else STATUS_ERROR
    status_messages = [
        "OpenSSL is {}".format("available" if openssl_enabled else "missing")
    ] + version_info

    def __init__(self, **kwargs):
        BaseInfoScan.__init__(self, **kwargs)

    def _supports_client_initiated_renegotiation(self, conn_ssl):
        tr = _util.lib.SSL_total_renegotiations(conn_ssl._ssl)
        if _util.lib.SSL_renegotiate(conn_ssl._ssl) != 1:
            return False
        if _util.lib.SSL_do_handshake(conn_ssl._ssl) != 1:
            return False

        # Check that
        # - renegotiation counter has increased and
        # - no renegotiations are pending
        if (_util.lib.SSL_total_renegotiations(conn_ssl._ssl) == tr + 1 and
                _util.lib.SSL_renegotiate_pending(conn_ssl._ssl) == 0):
            return True
        else:
            return False

    def run(self):
        kb = self._scanner.get_knowledge_base()

        protocol_versions = self._scanner.get_enabled_versions()

        methods = convert_versions2methods(protocol_versions)
        methods.reverse()

        for method in methods:
            ctx_options = (_util.lib.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION,)
            conn_ssl = self._connect_openssl(
                methods=(method,),
                ctx_options=ctx_options
            )
            if conn_ssl is None:
                continue

            # Does server signal support for secure renegotiation?
            if (_util.lib.SSL_get_secure_renegotiation_support(conn_ssl._ssl)
                    == 1):
                kb.set("server.renegotiation.secure", True)
            else:
                kb.set("server.renegotiation.secure", False)

            # Setting ci_secure to False because pySSLScan can detect this
            # feature in all cases and set True if needed.
            kb.set("server.renegotiation.ci_secure", False)

            # Setting ci_insecure to None because pySSLScan lacks support for
            # checking insecure, client-initiated renegotitations if the server
            # provides secure renegotiation support. None prevents misleading
            # output in this case.
            # If the server does not provide secure renegotiation support, any
            # client-initiated renegotiation must be considered insecure. In
            # this case, True and False are set correctly for ci_insecure.
            kb.set("server.renegotiation.ci_insecure", None)

            # Does the server accept client-initiated renegotiatons?
            if self._supports_client_initiated_renegotiation(conn_ssl):
                if kb.get("server.renegotiation.secure"):
                    # Renegotiation was performed securely, we do not know
                    # about insecure renegotiations yet.
                    kb.set("server.renegotiation.ci_secure", True)
                else:
                    # Renegotiation was performed insecurely, no need to check
                    # any further.
                    kb.set("server.renegotiation.ci_insecure", True)
            else:
                if not kb.get("server.renegotiation.secure"):
                    # Server does not support secure renegotitation and client-
                    # initiated renegotiation attempt failed. Thus, the server
                    # does not allow client-initiated insecure renegotiations
                    # either.
                    kb.set("server.renegotiation.ci_insecure", False)

            # TODO: Implement insecure, client-initiated renegotiation (i.e.
            #       without RFC5746-compliance) for scenarios where the server
            #       provides secure renegotiation support.

            conn_ssl.close()

modules.register(ServerRenegotiation)
