import ffilib

_openssl = ffilib.open("libssl")

# Init.
SSL_library_init = _openssl.func("v", "SSL_library_init", "")
SSL_load_error_strings = _openssl.func("v", "SSL_load_error_strings", "")

# Versions
SSL3_VERSION = 0x0300
TLS1_VERSION = 0x0301
TLS1_1_VERSION = 0x0302
TLS1_2_VERSION = 0x0303

# TLS methods.
SSLv23_server_method = _openssl.func("p", "SSLv23_server_method", "")
SSLv23_client_method = _openssl.func("p", "SSLv23_client_method", "")
SSLv23_method = _openssl.func("p", "SSLv23_method", "")
SSLv3_server_method = _openssl.func("p", "SSLv3_server_method", "")
SSLv3_client_method = _openssl.func("p", "SSLv3_client_method", "")
SSLv3_method = _openssl.func("p", "SSLv3_method", "")
TLSv1_server_method = _openssl.func("p", "TLSv1_server_method", "")
TLSv1_client_method = _openssl.func("p", "TLSv1_client_method", "")
TLSv1_method = _openssl.func("p", "TLSv1_method", "")
TLSv1_1_server_method = _openssl.func("p", "TLSv1_1_server_method", "")
TLSv1_1_client_method = _openssl.func("p", "TLSv1_1_client_method", "")
TLSv1_1_method = _openssl.func("p", "TLSv1_1_method", "")
TLSv1_2_server_method = _openssl.func("p", "TLSv1_2_server_method", "")
TLSv1_2_client_method = _openssl.func("p", "TLSv1_2_client_method", "")
TLSv1_2_method = _openssl.func("p", "TLSv1_2_method", "")

# SSL context.
SSL_CTX_new = _openssl.func("p", "SSL_CTX_new", "p")
SSL_CTX_free = _openssl.func("p", "SSL_CTX_free", "p")
# # <int success> | <SSL_new socket>, <int version>
# SSL_CTX_set_min_proto_version = _openssl.func("i", "SSL_CTX_set_min_proto_version", "pi")
# SSL_CTX_set_max_proto_version = _openssl.func("i", "SSL_CTX_set_max_proto_version", "pi")

# Sockets and sockets operations.
# <SSL_new socket> | <SSL_CTX_new context>
SSL_new = _openssl.func("p", "SSL_new", "p")
# # <int success> | <SSL_new socket>
# SSL_up_ref = _openssl.func("i", "SSL_up_ref", "p")
# # <int success> | <SSL_new socket>, <int version>
# SSL_set_min_proto_version = _openssl.func("i", "SSL_set_min_proto_version", "pi")
# SSL_set_max_proto_version = _openssl.func("i", "SSL_set_max_proto_version", "pi")
# <int success> | <SSL_new socket>, <int socket_file_descriptor> ->
SSL_set_fd = _openssl.func("i", "SSL_set_fd", "pi")
SSL_set_rfd = _openssl.func("i", "SSL_set_rfd", "pi")
SSL_set_wfd = _openssl.func("i", "SSL_set_wfd", "pi")
# <int error> | <SSL_new socket>, <int ret>
SSL_get_error = _openssl.func("i", "SSL_get_error", "pi")
# <int connected> | <SSL_new socket>
SSL_connect = _openssl.func("i", "SSL_connect", "p")
SSL_accept = _openssl.func("i", "SSL_accept", "p")
# <int pending_bytes> | <SSL_new socket>
SSL_pending = _openssl.func("i", "SSL_pending", "p")
# <int size> | <SSL_new socket>, <char buffer>, <int size>
SSL_read = _openssl.func("i", "SSL_read", "ppi")
SSL_write = _openssl.func("i", "SSL_write", "ppi")
# <int success> | <SSL_new socket>
SSL_clear = _openssl.func("i", "SSL_clear", "p")
SSL_shutdown = _openssl.func("i", "SSL_shutdown", "p")
# <SSL_new socket>
SSL_free = _openssl.func("v", "SSL_free", "p")

# Execute on first import only.
SSL_library_init()
SSL_load_error_strings()
