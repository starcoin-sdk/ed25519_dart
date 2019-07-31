import 'dart:typed_data' show Uint8List;
import 'package:ed25519_dart/ed25519_dart.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:hex/hex.dart';

Uint8List hexToBytes(String hex) {
  return Uint8List.fromList(HEX.decode(hex));
}

String byteToHex(Uint8List bytes) {
  return HEX.encode(bytes).toUpperCase();
}

void main() {
  test('bitClamp() clamps bits in provided lists as expected', () {
    var testData = new Uint8List(32);
    var testData2 = hexToBytes(
        '0102030405060708090A0B000000000000000000000000000000000000000000');
    expect(
        byteToHex(bitClamp(testData)),
        equals(
            '0000000000000000000000000000000000000000000000000000000000000040'));
    expect(
        byteToHex(bitClamp(testData2)),
        equals(
            '0002030405060708090A0B000000000000000000000000000000000000000040'));
  });

  test('bytesFromList() converts List into Uint8List', () {
    var testData = new List<int>.filled(32, 0);
    var expected = new Uint8List(32);
    expect(bytesFromList(testData), equals(expected));
    expect((bytesFromList(testData) is Uint8List), equals(true));
  });

  test('bytesToInteger() converts List of integers into integer', () {
    var testData = List<int>.filled(32, 0);
    var testData2 = List<int>.filled(32, 2);
    var expected = BigInt.zero;
    var expected2 = BigInt.parse(
        '908173248920127022929968509872062022378588115024631874819275168689514742274');
    expect(bytesToInteger(testData), equals(expected));
    expect(bytesToInteger(testData2), equals(expected2));
  });

  test('bytesToInteger() converts List of integers into integer two', () {
    var l = List<int>.generate(32, (int i) => i + i); // [0, ..., 60, 62]
    var expected = BigInt.parse(
        '28149809252802682310739102360897169509334746906488981719888435032634998129152');
    expect(bytesToInteger(l), equals(expected));
  });

  test('decodePoint() creates expected point x-y point from passed integer',
      () {
    var testData = BigInt.from(1024128256);
    var expected = [
      BigInt.parse(
          '5049901154188754798176685959377395864974690556190068451341045359400187598236'),
      BigInt.from(1024128256)
    ];
    expect(decodePoint(testData), equals(expected));
  });

  test('edwards() adds two x-y points with expected result', () {
    var testData = [BigInt.from(1), BigInt.from(2)];
    var expected = [
      BigInt.parse(
          '38630462183868106874449484850498687242488459434265729964110945788313160992017'),
      BigInt.parse(
          '2091706204615399755245742503625476174616215419841867942895091432328977195802')
    ];
    expect(edwards(testData, testData), equals(expected));
  });

  test('encodePoint() creates expected Uint8List from x-y point', () {
    var testData = [BigInt.from(1), BigInt.from(2)];
    expect(
        byteToHex(encodePoint(testData)),
        equals(
            '0200000000000000000000000000000000000000000000000000000000000080'));
  });

  test('Hash() hashes passed Uint8List into expected digest', () {
    var testData = new Uint8List(2);
    expect(
        byteToHex(Hash(testData)),
        equals(
            '5EA71DC6D0B4F57BF39AADD07C208C35F06CD2BAC5FDE210397F70DE11D439C62EC1CDF3183758865FD387FCEA0BADA2F6C37A4A17851DD1D78FEFE6F204EE54'));
  });

  test('integerToBytes() converts passed integer into expected Uint8List', () {
    var testData = BigInt.from(1024);
    expect(
        byteToHex(integerToBytes(testData, 32)),
        equals(
            '0004000000000000000000000000000000000000000000000000000000000000'));
    expect(integerToBytes(testData, 32).length, equals(32));
  });

  test('isOnCurve() checks if passed point is on curve', () {
    var testData = [
      BigInt.parse(
          '15112221349535400772501151409588531511454012693041857206046113283949847762202'),
      BigInt.parse(
          '46316835694926478169428394003475163141307993866256225615783033603165251855960')
    ];
    var testData2 = [BigInt.from(1), BigInt.from(2)];
    expect(isOnCurve(testData), equals(true));
    expect(isOnCurve(testData2), equals(false));
  });

  test('modularInverse() returns expected modular inverse', () {
    var testData = BigInt.from(2);
    var expected = BigInt.parse(
        '28948022309329048855892746252171976963317496166410141009864396001978282409975');
    expect(modularInverse(testData), equals(expected));
  });

  test('publicKey() creates expected public key from passed secret key', () {
    expect(
        byteToHex(publicKey(hexToBytes('059B5430B9A42947DDA68A69900A897CB1F91F404D2BD07AA4BC86902A8C55B4'))),
        equals(
            '4A93F2F2BBE636EB0F3A5E6F4098783A2E06B8F614F6B85E3B4290D17081CD84'));
  });

  test('scalarMult() returns expected scalar multiplication of point', () {
    var testData = [BigInt.from(1), BigInt.from(2)];
    var expected = [
      BigInt.parse(
          '2985072665741473095974513523900639186165599576139095168757154406154247914422'),
      BigInt.parse(
          '48018218743393111964698292971632252982314570786198777847490644689840463716666')
    ];
    expect(scalarMult(testData, BigInt.from(10)), equals(expected));
  });

  test('secretKey() returns random Uint8List with length 64', () {
    expect(secretKey().length, equals(64));
    expect((secretKey() is Uint8List), equals(true));
    expect(secretKey(1024).length, equals(64));
    expect((secretKey(1024) is Uint8List), equals(true));
  });

  test('sign() creates expected signature from passed parameters', () {
    var testData = new Uint8List(32);
    expect(
        byteToHex(sign(testData, testData, testData)),
        equals(
            '3DA1EBDFA96EDD181DBE3659D1C051C431F056A5AD6A97A60D5CCA1046043878F4629EDB9F6D2DFDF1D792BC2652EFF89A5E8DB007C918D163FBC0383398640D'));
    var privateKey = hexToBytes(
        '059B5430B9A42947DDA68A69900A897CB1F91F404D2BD07AA4BC86902A8C55B4');
    var publicKey = hexToBytes(
        '4A93F2F2BBE636EB0F3A5E6F4098783A2E06B8F614F6B85E3B4290D17081CD84');
    var hash = hexToBytes(
        'fa8947c810e09db035a24b85f8d36f403c0b264c4976f29c1838793f58adb4a7');
    expect(
        byteToHex(sign(hash, privateKey, publicKey)),
        equals(
            '8C3F6384CA9898EE630B97B82590A34EBEF15DF47AE52411EF1012BBFC97B572ACECFEA5ADD9050C71A2ACB014BF817EE2FFC3743136E5A50E1FB51FA57B3404'));
  });

  test('verifySignature() verifies signature by passed parameters', () {
    var signature = hexToBytes(
        '8C3F6384CA9898EE630B97B82590A34EBEF15DF47AE52411EF1012BBFC97B572ACECFEA5ADD9050C71A2ACB014BF817EE2FFC3743136E5A50E1FB51FA57B3404');
    var publicKey = hexToBytes(
        '4A93F2F2BBE636EB0F3A5E6F4098783A2E06B8F614F6B85E3B4290D17081CD84');
    var hash = hexToBytes(
        'fa8947c810e09db035a24b85f8d36f403c0b264c4976f29c1838793f58adb4a7');
    expect(verifySignature(signature, hash, publicKey), equals(true));
  });

  test('xRecover() computes expected value from passed integer', () {
    var testData = BigInt.from(5);
    var expected = BigInt.parse(
        '39662079413846548812394406357884595898465868971068617279194812783497449546402');
    expect(xRecover(testData), equals(expected));
  });
}
