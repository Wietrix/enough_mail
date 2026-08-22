import 'dart:convert';
import 'dart:io';

import 'package:enough_mail_plus/enough_mail.dart';
import 'package:test/test.dart';

// Self-signed test certificates for 127.0.0.1 (valid until 2126). The
// server presents the first; the second is an unrelated one.
const _serverCert = '''
-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUYGkjr5UbTdFM/PGP0aj3leiNXYEwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkyNzIxNTcwMVoYDzIxMjYwOTAz
MjE1NzAxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATZOggMlLZyk36pO0lmqmPP3jJuCpmcInyn55ZDdnKdYVXlC+1pJgYK
WPsjq0l9x4/bWk3A+KnOCMGGPa1W4Qyfo28wbTAdBgNVHQ4EFgQUJOlOi40jkRvE
Y68E8Ty32pMJEh4wHwYDVR0jBBgwFoAUJOlOi40jkRvEY68E8Ty32pMJEh4wDwYD
VR0TAQH/BAUwAwEB/zAaBgNVHREEEzARhwR/AAABgglsb2NhbGhvc3QwCgYIKoZI
zj0EAwIDSAAwRQIgG2urPTSyMJdDwQfHG/hKfsY4kWdB6/O6gDSCVhcYqnoCIQC0
NmoYYcIFKEyZnyTLv6MDxU4HrRqoJNxpjD/XjeTlmA==
-----END CERTIFICATE-----
''';
const _serverKey = '''
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEUq+kB+jT12tZ5sl
887gBHWSgjCKbZe2ILxcAySqV76hRANCAATZOggMlLZyk36pO0lmqmPP3jJuCpmc
Inyn55ZDdnKdYVXlC+1pJgYKWPsjq0l9x4/bWk3A+KnOCMGGPa1W4Qyf
-----END PRIVATE KEY-----
''';
const _otherCert = '''
-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUEByTki58VBtvzTvxTdK6GrWslm0wCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDkyNzIxNTcwMVoYDzIxMjYwOTAz
MjE1NzAxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQn6Cz5kfH2gSlrkPMNzqWgf1tFkkIETtUkDQAyOVsuXedOafS5PMm3
6dKS0lRquiamBUZtB5eoiW6O9sjbEvUmo28wbTAdBgNVHQ4EFgQUKUkf7swUlNLH
nQKXQha05R7X8JEwHwYDVR0jBBgwFoAUKUkf7swUlNLHnQKXQha05R7X8JEwDwYD
VR0TAQH/BAUwAwEB/zAaBgNVHREEEzARhwR/AAABgglsb2NhbGhvc3QwCgYIKoZI
zj0EAwIDSAAwRQIhAILUeS1+DTnDkK6BqVQnGvJsC9y4GT3fs+7w6LcwMv+KAiBA
e1Rm9g94hPSW8mQY6vLxFl1oJ6b1r+rnhP665nx9mA==
-----END CERTIFICATE-----
''';

/// An IMAP server on direct TLS that greets and refuses everything, and
/// records every line it receives.
Future<(SecureServerSocket, List<String>)> _tlsServer() async {
  final context = SecurityContext()
    ..useCertificateChainBytes(utf8.encode(_serverCert))
    ..usePrivateKeyBytes(utf8.encode(_serverKey));
  final server = await SecureServerSocket.bind(
    InternetAddress.loopbackIPv4,
    0,
    context,
  );
  final received = <String>[];
  server.listen((socket) {
    socket.write('* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready\r\n');
    utf8.decoder.bind(socket).transform(const LineSplitter()).listen((line) {
      received.add(line);
      socket.write('${line.split(' ').first} NO nope\r\n');
    }, onError: (_) {});
  }, onError: (_) {});
  return (server, received);
}

MailAccount _account(int port) => MailAccount.fromManualSettings(
  name: 'user',
  email: 'user@example.org',
  userName: 'user',
  password: 'SECRET-PASSWORD',
  incomingHost: '127.0.0.1',
  incomingPort: port,
  outgoingHost: '127.0.0.1',
  outgoingPort: 1,
);

SecurityContext _trusting(String pem) =>
    SecurityContext(withTrustedRoots: false)
      ..setTrustedCertificatesBytes(utf8.encode(pem));

void main() {
  test(
    'a context trusting the server certificate lets the login through',
    () async {
      final (server, received) = await _tlsServer();
      addTearDown(server.close);

      final client = MailClient(
        _account(server.port),
        securityContext: _trusting(_serverCert),
      );
      // The fake server refuses the login; getting that far is the point.
      await expectLater(client.connect(), throwsA(isA<MailException>()));
      expect(received.join('\n'), contains('SECRET-PASSWORD'));
    },
  );

  test('a context trusting another certificate stops the handshake', () async {
    final (server, received) = await _tlsServer();
    addTearDown(server.close);

    final client = MailClient(
      _account(server.port),
      securityContext: _trusting(_otherCert),
    );
    await expectLater(client.connect(), throwsA(anything));
    expect(received, isEmpty);
  });
}
