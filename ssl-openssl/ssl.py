try:
	from . import libssl
except ImportError:
	import libssl


class SSLError(Exception):
	def __init__(self, value, ret=None):
		self.value = value
		self.ret = ret

	def __str__(self):
		return "%s; ret = %d" % (repr(self.value), self.ret)


class SSLZeroReturnError(SSLError):
	pass


class SSLWantReadError(SSLError):
	pass


class SSLWantWriteError(SSLError):
	pass


class SSLWantAccept(SSLError):
	pass


class SSLWantConnect(SSLError):
	pass


class CertificateError(SSLError):
	pass


_c_method = libssl.TLSv1_2_method()
if not _c_method:
	raise SSLError("Method initialisation failed.")
_c_context = libssl.SSL_CTX_new(_c_method)

CERT_NONE = 0
CERT_OPTIONAL = 1
CERT_REQUIRED = 2

SSL_ERROR_NONE = 0
SSL_ERROR_SSL = 1
SSL_ERROR_WANT_READ = 2
SSL_ERROR_WANT_WRITE = 3
SSL_ERROR_WANT_X509_LOOKUP = 4
SSL_ERROR_SYSCALL = 5
SSL_ERROR_ZERO_RETURN = 6
SSL_ERROR_WANT_CONNECT = 7
SSL_ERROR_WANT_ACCEPT = 8


class SSLSocket(object):
	_errors = {
		SSL_ERROR_NONE: None,
		SSL_ERROR_SSL: SSLError,
		SSL_ERROR_WANT_READ: SSLWantReadError,
		SSL_ERROR_WANT_WRITE: SSLWantWriteError,
		SSL_ERROR_WANT_X509_LOOKUP: CertificateError,
		SSL_ERROR_SYSCALL: OSError,
		SSL_ERROR_ZERO_RETURN: SSLError,
		SSL_ERROR_WANT_ACCEPT: SSLWantAccept,
		SSL_ERROR_WANT_CONNECT: SSLWantConnect,
	}

	def __init__(self, sock):
		self._c_ssl_socket = None
		self._c_ssl_socket = libssl.SSL_new(_c_context)
		if not self._c_ssl_socket:
			raise SSLError("Socket initialization failed.")
		self._socket = sock
		self._fd = sock.fileno()
		self._set_fd(self._fd)
		self.connect()

	def __del__(self):
		if self._c_ssl_socket:
			libssl.SSL_free(self._c_ssl_socket)

	def _get_error(self, ret):
		error = libssl.SSL_get_error(self._c_ssl_socket, ret)
		exception = SSLSocket._errors[error]

		if exception:
			raise exception("Get error was called.", ret)

	def _set_fd(self, fd):
		ret = libssl.SSL_set_fd(self._c_ssl_socket, fd)

		if ret != 1:
			self._get_error(ret)

	def connect(self):
		ret = libssl.SSL_connect(self._c_ssl_socket)

		if ret != 1:
			self._get_error(ret)

	def read(self, size):
		buf = bytes(size)
		recv_size = libssl.SSL_read(self._c_ssl_socket, buf, size)
		return buf[:recv_size]

	def recv(self, size=4096):
		return self.read(size)

	def send(self, buf):
		return self.write(buf)

	def write(self, buf):
		return libssl.SSL_write(self._c_ssl_socket, buf, len(buf))

	def shutdown(self):
		ret = libssl.SSL_shutdown(self._c_ssl_socket)

		if ret != 1:
			self._get_error(ret)

	def close(self):
		ret = libssl.SSL_clear(self._c_ssl_socket)

		if ret != 1:
			self._get_error(ret)


def wrap_socket(sock, keyfile=None, certfile=None, server_side=False, cert_reqs=CERT_NONE, ssl_version_min=None, ssl_version_max=None, ca_certs=None):
	return SSLSocket(sock)
