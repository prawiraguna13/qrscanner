import 'package:flutter/material.dart';
import 'package:qr_code_scanner_plus/qr_code_scanner_plus.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';
import 'dart:convert';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      title: 'Scanner QR',
      theme: ThemeData(
        primarySwatch: Colors.blueGrey,
      ),
      home: const QRViewExample(),
    );
  }
}

class QRViewExample extends StatefulWidget {
  const QRViewExample({super.key});

  @override
  State<StatefulWidget> createState() => _QRViewExampleState();
}

class _QRViewExampleState extends
State<QRViewExample> {
  final GlobalKey qrKey =
  GlobalKey(debugLabel: 'QR');
  Barcode? result;
  QRViewController? controller;

  @override
  void reassemble() {
    super.reassemble();
    controller!.pauseCamera();
    controller!.resumeCamera();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('QR Web Scanner')),
      body: Column(
        children: <Widget>[
          Expanded(flex: 4, child: _buildQrView(context)),
          Expanded(
            flex: 1,
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: <Widget>[
                if (result != null)
                  Text('Result:${result!.code}')
                else
                  const Text('Scan a code'),
                ElevatedButton(
                  onPressed: result != null &&
                      result!.code != null
                      ? () => _checkWithVirusTotal(result!.code!) : null,
                  child: const Text('Check with VirusTotal'),
                ),
              ],
            ),
          )
        ],
      ),
    );
  }

  Widget _buildQrView(BuildContext
  context) {
    return QRView(
      key: qrKey,
      onQRViewCreated: _onQRViewCreated,
      overlay: QrScannerOverlayShape(
        borderColor: Colors.white,
        borderRadius: 10,
        borderLength: 30,
        borderWidth: 10,
        cutOutSize:
        MediaQuery
            .of(context)
            .size
            .width * 0.8,
      ),
    );
  }

  void _onQRViewCreated(QRViewController controller) {
    setState(() {
      this.controller = controller;
    });
    controller.scannedDataStream.listen((scanData) {
      setState(() {
        result = scanData;
      });
    });
  }
  Future<void> _checkWithVirusTotal(String url)
  async {
    const apiKey =
        '6ccdc29db8079c8d7d24b319aa48751a8e9bb09a844baf75958ea44d55ba5513';
    final encodedUrl = base64Url.encode(utf8.encode(url)).replaceAll(' =', ''); // Encode and remove padding
    final apiUrl =
        'https://www.virustotal.com/api/v3/urls/$encodedUrl';
    try {
      final response = await http.get(
        Uri.parse(apiUrl),
        headers: {
          'x-apikey': apiKey,
          'Content-Type': 'application/json',
        },
      );
      if (response.statusCode == 200) {
        final jsonResponse = json.decode(response.body);
// Tampilkan hasil dari VirusTotal (misalnya dideteksi atau aman)
        final scanResult = jsonResponse['data']['attributes']['last_analysis_stats'];

        if (scanResult is Map) {
          int jml_data_jahat = scanResult['malicious'] ?? 0;
          int jml_data_mencurigakan = scanResult['suspicious'] ?? 0;
          final Uri url = Uri.parse('${result!.code}');

          Future<void> _launchUrl() async {
            if (!await launchUrl(url)) {
              throw Exception('Tidak bisa membuka $url');
              }
              }

            if (jml_data_mencurigakan > 0 || jml_data_jahat > 0) {
              showDialog(context: context,
              builder: (_) => AlertDialog(
                title: const Text('Website berbahaya! Tidak dapat pergi ke website tersebut!'),
                content: Text('Website tersebut mengandung:\nData Jahat = ${jml_data_jahat.toString()} \nData Mencurigakan = ${jml_data_jahat.toString()}'),
                actions: <Widget>[
                  TextButton(
                    child: const Text('tutup'),
                    onPressed: () {
                  Navigator.of(context).pop();
                },
              ),
            ],
          ),
        );
          } else {
            showDialog(context: context,
              builder: (_) => AlertDialog(
                title: const Text('Website aman!'),
                content: Text('Website tersebut mengandung:\nData Jahat = ${jml_data_jahat.toString()}\nData Mencurigakan = ${jml_data_jahat.toString()}'),
                actions: <Widget>[
                  TextButton(
                    onPressed: _launchUrl,
                    child: const Text('Buka URL'),
              ),
               TextButton(
                    child: const Text('OK'),
                    onPressed: () {
                  Navigator.of(context).pop();
                },
              ),
            ],
          ),
        );
          }
        }
      } else {
        _showErrorDialog('Tidak bisa scan web tersebut menggunakan VirusTotal.');
      }
    } catch (e) {
      _showErrorDialog('Error: $e');
    }
  }
   void _showErrorDialog(String message) {
    showDialog(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Error'),
        content: Text(message),
        actions: <Widget>[
          TextButton(
            child: const Text('OK'),
            onPressed: () {
              Navigator.of(context).pop();
            },
          ),
        ],
      ),
    );
  }
  @override
  void dispose() {
    controller?.dispose();
    super.dispose();
  }
}

