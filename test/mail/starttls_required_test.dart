import 'dart:convert';
import 'dart:io';

import 'package:enough_mail_plus/enough_mail.dart';
import 'package:test/test.dart';

/// A server that plays along until STARTTLS, then refuses it — which is
/// what a man in the middle stripping STARTTLS looks like to the client.
/// Records every line it receives.
Future<(ServerSocket, List<String>)> _strippingServer({
  required String greeting,
  required String Function(String line) reply,
}) async {
  final server = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
  final received = <String>[];
  server.listen((socket) {
    socket.write(greeting);
    utf8.decoder.bind(socket).transform(const LineSplitter()).listen((line) {
      received.add(line);
      socket.write(reply(line));
    }, onError: (_) {});
  });
  return (server, received);
}

MailAccount _account({required int imapPort, required int smtpPort}) =>
    MailAccount.fromManualSettings(
      name: 'victim',
      email: 'victim@example.org',
      userName: 'victim',
      password: 'SECRET-PASSWORD',
      incomingHost: '127.0.0.1',
      incomingPort: imapPort,
      outgoingHost: '127.0.0.1',
      outgoingPort: smtpPort,
      incomingSocketType: SocketType.starttls,
      outgoingSocketType: SocketType.starttls,
    );

void main() {
  test('IMAP refuses to log in when STARTTLS is stripped', () async {
    final (server, received) = await _strippingServer(
      // No STARTTLS in the capabilities, as a stripping attacker would send.
      greeting: '* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready\r\n',
      reply: (line) => '${line.split(' ').first} BAD not here\r\n',
    );
    addTearDown(server.close);

    final client = MailClient(_account(imapPort: server.port, smtpPort: 1));
    await expectLater(
      client.connect(timeout: const Duration(seconds: 5)),
      throwsA(anything),
    );
    expect(received.join('\n'), isNot(contains('SECRET-PASSWORD')));
  });

  test('SMTP refuses to log in when STARTTLS is stripped', () async {
    final (server, received) = await _strippingServer(
      greeting: '220 fake ESMTP\r\n',
      reply: (line) {
        final upper = line.toUpperCase();
        if (upper.startsWith('EHLO')) {
          return '250-fake\r\n250 AUTH PLAIN LOGIN\r\n';
        }
        if (upper.startsWith('STARTTLS')) {
          return '502 not implemented\r\n';
        }
        return '235 ok\r\n';
      },
    );
    addTearDown(server.close);

    final client = MailClient(_account(imapPort: 1, smtpPort: server.port));
    final message = MessageBuilder.buildSimpleTextMessage(
      const MailAddress('victim', 'victim@example.org'),
      [const MailAddress('other', 'other@example.org')],
      'hello',
      subject: 'test',
    );
    await expectLater(
      client.sendMessage(message, appendToSent: false),
      throwsA(anything),
    );
    expect(received.join('\n'), isNot(contains('AUTH')));
  });
}
