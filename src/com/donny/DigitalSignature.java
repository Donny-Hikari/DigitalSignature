package com.donny;

/*
 * DigitalSignature
 * 
 * Copyright (c) 2017 Donny
 * 
 * https://github.com/Donny-Hikari
 * 
 */

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;

public class DigitalSignature {

	static boolean bLangCHS = true;

	// RSA密钥类
	public static class RSAKey {
		BigInteger e; // 公钥
		BigInteger n; // 模数

		BigInteger d; // 密钥
		BigInteger p; // 素数1
		BigInteger q; // 素数2
	}

	// 生成RSA密钥
	public static RSAKey generateRSAKey(final int length) {
		RSAKey rsaKey = new RSAKey();

		final int primeLength = length / 2;
		Random rnd = new Random();

		// 生成两个素数p和q
		BigInteger p = BigInteger.probablePrime(primeLength, rnd);
		BigInteger q = BigInteger.probablePrime(primeLength, rnd);
		rsaKey.p = p;
		rsaKey.q = q;

		// 模数 n = p * q
		rsaKey.n = p.multiply(q);
		// n 的欧拉函数 en = (p - 1)*(q - 1) = p*q - p - q + 1
		BigInteger en = rsaKey.n.subtract(p).subtract(q).add(BigInteger.ONE);

		// 公钥e
		BigInteger e = new BigInteger(24, rnd);
		// 确保 gcd(e, en) = 1
		while ((e.bitLength() != 24) || (en.gcd(e).compareTo(BigInteger.ONE) != 0)) {
			e = new BigInteger(24, rnd);
		}
		rsaKey.e = e;
		// 密钥d为e模en的乘法逆
		rsaKey.d = e.modInverse(en);

		return rsaKey;
	}

	public static int rightrotate(int num, int bits) {
		return (num << (32 - bits)) | (num >>> bits);
	}

	// Secure Hash Algorithm - 256
	public static int[] sha256(final byte[] rawBytes) {
		int[] H = new int[8];
		int a, b, c, d, e, f, g, h, t1, t2;

		// 初始化hash值数组
		H[0] = 0x6a09e667;
		H[1] = 0xbb67ae85;
		H[2] = 0x3c6ef372;
		H[3] = 0xa54ff53a;
		H[4] = 0x510e527f;
		H[5] = 0x9b05688c;
		H[6] = 0x1f83d9ab;
		H[7] = 0x5be0cd19;

		// 初始化常数
		final int k[] = new int[] { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
				0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
				0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc,
				0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351,
				0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
				0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585,
				0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
				0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
				0xc67178f2 };

		final int ognBytesLen = rawBytes.length;
		final int ognBitsCount = ognBytesLen * 8;
		final int lenMod512 = ognBitsCount % 512;
		final int dataBitsCount;
		final int dataBytesLen;
		// 计算总的Bits数
		if (lenMod512 < 448) {
			dataBitsCount = ognBitsCount + 512 - lenMod512;
		} else { // lenMod512 >= 448
			dataBitsCount = ognBitsCount + 512 - lenMod512 + 512;
		}
		dataBytesLen = dataBitsCount / 8;

		byte[] rawData = new byte[dataBytesLen];
		for (int i = 0; i < ognBytesLen; ++i) {
			rawData[i] = rawBytes[i];
		}
		// 末尾补1000...
		rawData[ognBytesLen] = (byte) 0x80;
		for (int i = ognBytesLen + 1; i < dataBytesLen - 8; ++i) {
			rawData[i] = (byte) 0;
		}
		// 加上有效数据比特数
		for (int i = dataBytesLen - 8, j = 56; i < dataBytesLen; ++i, j -= 8) {
			rawData[i] = (byte) ((long) ognBitsCount >> j);
		}

		int w[] = new int[64];
		// 每次处理 512/8=64 字节,共512比特
		for (int pos = 0; pos < dataBytesLen; pos += 64) {
			for (int i = 0; i < 16; ++i) {
				// 将4个8位数字节放入一个32位整型中
				w[i] = ((rawData[pos + i * 4] & 0xff) << 24) | ((rawData[pos + i * 4 + 1] & 0xff) << 16)
						| ((rawData[pos + i * 4 + 2] & 0xff) << 8) | (rawData[pos + i * 4 + 3] & 0xff);
			}

			// 扩充w
			for (int i = 16; i < 64; ++i) {
				w[i] = w[i - 16] + w[i - 7]
						+ (rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >>> 3))
						+ (rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >>> 10));
			}

			// 初始化
			a = H[0];
			b = H[1];
			c = H[2];
			d = H[3];
			e = H[4];
			f = H[5];
			g = H[6];
			h = H[7];

			for (int i = 0; i < 64; ++i) {
				t1 = h + k[i] + w[i] + (rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25))
						+ ((e & f) ^ (~e & g));
				t2 = (rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));

				h = g;
				g = f;
				f = e;
				e = d + t1;
				d = c;
				c = b;
				b = a;
				a = t1 + t2;
			}

			// 累加当前结果
			H[0] = H[0] + a;
			H[1] = H[1] + b;
			H[2] = H[2] + c;
			H[3] = H[3] + d;
			H[4] = H[4] + e;
			H[5] = H[5] + f;
			H[6] = H[6] + g;
			H[7] = H[7] + h;

		}

		return H;
	}

	public static byte[] ints2bytes(final int[] intCode) {
		byte[] byteCode = new byte[intCode.length * 4];
		for (int i = 0; i < intCode.length; ++i) {
			byteCode[i * 4] = (byte) ((intCode[i] >>> 24) & 0xff);
			byteCode[i * 4 + 1] = (byte) ((intCode[i] >>> 16) & 0xff);
			byteCode[i * 4 + 2] = (byte) ((intCode[i] >>> 8) & 0xff);
			byteCode[i * 4 + 3] = (byte) (intCode[i] & 0xff);
		}
		return byteCode;
	}

	// 签名
	public static BigInteger signature(final RSAKey key, final int[] hashVal) {
		BigInteger m = new BigInteger(ints2bytes(hashVal));
		BigInteger s;
		if ((key.n == null) || (key.n.compareTo(BigInteger.ZERO) == 0))
			s = m.modPow(key.d, key.p.multiply(key.q));
		else
			s = m.modPow(key.d, key.n);
		return s;
	}

	// 验证签名
	public static boolean verify(final BigInteger e, final BigInteger n, final BigInteger s, final int[] hashVal) {
		BigInteger m = s.modPow(e, n);
		byte[] real = ints2bytes(hashVal);
		byte[] found = m.toByteArray();
		if (real.length != found.length)
			return false;
		for (int i = 0; i < real.length; ++i) {
			if (real[i] != found[i])
				return false;
		}
		return true;
	}

	// 验证签名
	public static boolean verify(final RSAKey key, final BigInteger s, final int[] hashVal) {
		return verify(key.e, key.n, s, hashVal);
	}

	// 导出RSA密钥
	public static boolean exportRSAKey(final RSAKey key, final String filename) {
		final String pvkfilename = filename + ".pvk";
		final String pukfilename = filename + ".puk";

		byte[] e = key.e.toByteArray();
		byte[] n = key.n.toByteArray();
		byte[] d = key.d.toByteArray();
		byte[] p = key.p.toByteArray();
		byte[] q = key.q.toByteArray();

		FileOutputStream pvkfile, pukfile;
		DataOutputStream pvkdata, pukdata;
		try {
			System.out.println("Exporting private key...");
			pvkfile = new FileOutputStream(pvkfilename);
			pvkdata = new DataOutputStream(pvkfile);

			pvkdata.writeInt(d.length);
			pvkdata.write(d);
			pvkdata.writeInt(p.length);
			pvkdata.write(p);
			pvkdata.writeInt(q.length);
			pvkdata.write(q);

			pvkdata.close();
			pvkfile.close();
			System.out.println("Private key export to " + pvkfilename);

			System.out.println("Exporting public key...");
			pukfile = new FileOutputStream(pukfilename);
			pukdata = new DataOutputStream(pukfile);

			pukdata.writeInt(e.length);
			pukdata.write(e);
			pukdata.writeInt(n.length);
			pukdata.write(n);

			pukdata.close();
			pukfile.close();
			System.out.println("Private key export to " + pukfilename);
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return false;
		} catch (IOException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
			return false;
		}

		return true;
	}

	// 导入RSA密钥
	// 根据需要保证 pvkfilename 和 pukfilename 至少一个是有效的文件名。
	public static RSAKey importRSAKey(final String pvkfilename, final String pukfilename) {
		RSAKey rsaKey = new RSAKey();
		int byteCount = 0;
		byte[] buff;

		FileInputStream pvkfile;
		DataInputStream pvkdata;

		try {
			if (pvkfilename == null)
				throw new FileNotFoundException();

			pvkfile = new FileInputStream(pvkfilename);
			System.out.println("Loading private key...");
			pvkdata = new DataInputStream(pvkfile);

			// Load d
			byteCount = pvkdata.readInt();
			buff = new byte[byteCount];
			pvkdata.read(buff);
			rsaKey.d = new BigInteger(buff);

			// Load p
			byteCount = pvkdata.readInt();
			buff = new byte[byteCount];
			pvkdata.read(buff);
			rsaKey.p = new BigInteger(buff);

			// Load q
			byteCount = pvkdata.readInt();
			buff = new byte[byteCount];
			pvkdata.read(buff);
			rsaKey.q = new BigInteger(buff);

			System.out.println("Private key loaded.");
			pvkdata.close();
			pvkfile.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			System.out.println("Not loading private key.");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Fail to load private key.");
		}

		FileInputStream pukfile;
		DataInputStream pukdata;

		try {
			if (pukfilename == null)
				throw new FileNotFoundException();

			pukfile = new FileInputStream(pukfilename);
			System.out.println("Loading public key...");
			pukdata = new DataInputStream(pukfile);

			// Load e
			byteCount = pukdata.readInt();
			buff = new byte[byteCount];
			pukdata.read(buff);
			rsaKey.e = new BigInteger(buff);

			// Load n
			byteCount = pukdata.readInt();
			buff = new byte[byteCount];
			pukdata.read(buff);
			rsaKey.n = new BigInteger(buff);

			System.out.println("Public key loaded.");
			pukdata.close();
			pukfile.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			System.out.println("Not loading public key.");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Fail to load public key.");
		}

		return rsaKey;
	}

	// 保存签名到文件
	public static boolean saveSignature(final BigInteger signature, final String filename) {
		final String sigfilename = filename + ".sig";

		byte[] s = signature.toByteArray();

		FileOutputStream sigfile;
		DataOutputStream sigdata;
		try {
			System.out.println("Saving signature...");
			sigfile = new FileOutputStream(sigfilename);
			sigdata = new DataOutputStream(sigfile);

			sigdata.writeInt(s.length);
			sigdata.write(s);

			sigdata.close();
			sigfile.close();
			System.out.println("Signature saved to " + sigfilename);
		} catch (FileNotFoundException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
			return false;
		} catch (IOException e2) {
			// TODO Auto-generated catch block
			e2.printStackTrace();
			return false;
		}

		return true;
	}

	// 读取签名文件
	public static BigInteger loadSignature(final String sigfilename) {
		BigInteger s = null;
		int byteCount = 0;
		byte[] buff;

		FileInputStream sigfile;
		DataInputStream sigdata;

		try {
			sigfile = new FileInputStream(sigfilename);
			System.out.println("Loading signature...");
			sigdata = new DataInputStream(sigfile);

			// Load e
			byteCount = sigdata.readInt();
			buff = new byte[byteCount];
			sigdata.read(buff);
			s = new BigInteger(buff);

			System.out.println("Signature loaded.");
			sigdata.close();
			sigfile.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			// e.printStackTrace();
			System.out.println("Not loading signature.");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Fail to load signature.");
		}

		return s;
	}

	public static int[] sha256(final String rawStr) {
		return sha256(rawStr.getBytes());
	}

	// 获得文件的hash值
	public static int[] sha256File(final String filename) {
		int byteCount = 0;
		byte[] buff;

		FileInputStream filein;
		DataInputStream datain;

		try {
			filein = new FileInputStream(filename);
			datain = new DataInputStream(filein);

			byteCount = filein.available();
			buff = new byte[byteCount];
			datain.read(buff);

			datain.close();
			filein.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Fail to load file " + filename);
			return null;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.out.println("Fail to load file " + filename);
			return null;
		}

		return sha256(buff);
	}

	public static void printHex(final byte[] data) {
		for (int i = 0; i < data.length; ++i) {
			System.out.print(String.format("%02x", data[i]));
		}
		System.out.println("");
	}

	public static void printHex(final int[] data) {
		for (int i = 0; i < data.length; ++i) {
			System.out.print(String.format("%08x", data[i]));
		}
		System.out.println("");
	}

	public static void printRSAKey(RSAKey rsaKey) {
		System.out.println("RSA key infomation:");
		System.out.println("e: " + rsaKey.e.bitLength() + "\n" + rsaKey.e);
		System.out.println("n: " + rsaKey.n.bitLength() + "\n" + rsaKey.n);
		System.out.println("d: " + rsaKey.d.bitLength() + "\n" + rsaKey.d);
		System.out.println("p: " + rsaKey.p.bitLength() + "\n" + rsaKey.p);
		System.out.println("q: " + rsaKey.q.bitLength() + "\n" + rsaKey.q);
	}

	public static void proc1() {

		int[] hashCode = sha256("Hello");
		System.out.println("Hash code:");
		printHex(hashCode);

		RSAKey rsaKey = generateRSAKey(2048);
		printRSAKey(rsaKey);

		exportRSAKey(rsaKey, "myfirstKey");

		BigInteger s = signature(rsaKey, hashCode);
		if (verify(rsaKey, s, hashCode))
			System.out.println("Great!");
		else
			System.out.println("Shit!");

		saveSignature(s, "myfirstSig");

	}

	public static void proc2() {

		RSAKey rsaKey = importRSAKey("myfirstKey.pvk", "myfirstKey.puk");
		BigInteger s = loadSignature("myfirstSig.sig");

		int[] hashCode = sha256("Hello");
		if (verify(rsaKey, s, hashCode))
			System.out.println("Great!");
		else
			System.out.println("Shit!");

	}

	public static void proc3() {

		RSAKey rsaKey = importRSAKey("test/myfirstKey.pvk", "test/myfirstKey.puk");

		int[] hashCode = sha256File("test/gmp-6.1.2.tar.lz");
		BigInteger s = signature(rsaKey, hashCode);
		saveSignature(s, "test/my_gmp_sig");

	}

	public static void proc4() {

		RSAKey rsaKey = importRSAKey("test/myfirstKey.pvk", "test/myfirstKey.puk");
		BigInteger s = loadSignature("test/my_gmp_sig.sig");

		int[] hashCode = sha256File("test/gmp-6.1.2.tar.lz");
		if (verify(rsaKey, s, hashCode))
			System.out.println("Pass!");
		else
			System.out.println("Shit!");

		System.out.println("文件gmp-6.1.2.tar.lz的hash值为：");
		printHex(hashCode);

	}

	public static void printUsageCHS() {
		System.out.println("Usage: DigitalSignature [GenerateRSAKey|GetHashValue|Signature|Verify]");
		System.out.println("\tGenerateRSAKey 密钥长度  导出文件名");
		System.out.println("\tGetHashValue 文件名");
		System.out.println("\tSignature 私钥文件名  文件名  签名输出文件名");
		System.out.println("\tVerify 公钥文件名  文件名  签名文件名");
	}

	public static void printUsage() {
		if (bLangCHS)
			printUsageCHS();
		else {
			System.out.println("Usage: DigitalSignature [GenerateRSAKey|GetHashValue|Signature|Verify]");
			System.out.println("\tGenerateRSAKey keyLen exportFilename");
			System.out.println("\tGetHashValue filename");
			System.out.println("\tSignature privateKeyFilename filename signatureOutputFilename");
			System.out.println("\tVerify publicKeyFilename filename signatureFilename");
		}
	}

	public static void main(String[] args) {

		if (args.length <= 0) {
			printUsage();
		} else {
			switch (args[0]) {
			case "GenerateRSAKey": // keyLen exportFilename
				if (args.length != 3) {
					printUsage();
				} else {
					try {
						int keylen = Integer.parseInt(args[1]);
						RSAKey rsaKey = generateRSAKey(keylen);
						printRSAKey(rsaKey);
						exportRSAKey(rsaKey, args[2]);
					} catch (NumberFormatException e1) {
						printUsage();
					}
				}
				break;
			case "GetHashValue": // filename
				if (args.length != 2) {
					printUsage();
				} else {
					int[] hashVal = sha256File(args[1]);
					System.out.println("Hash code of " + args[1] + " is:");
					printHex(hashVal);
				}
				break;
			case "Signature": // privateKeyFilename filename signatureOutputFilename
				if (args.length != 4) {
					printUsage();
				} else {
					RSAKey rsaKey = importRSAKey(args[1], null);
					int[] hashVal = sha256File(args[2]);
					System.out.println("Hash code of " + args[2] + " is:");
					printHex(hashVal);
					System.out.println("Signaturing " + args[2] + " ...");
					BigInteger s = signature(rsaKey, hashVal);
					System.out.println("Signature of " + args[2] + " is:");
					printHex(s.toByteArray());
					saveSignature(s, args[3]);
				}
				break;
			case "Verify": // publicKeyFilename filename signatureFilename
				if (args.length != 4) {
					printUsage();
				} else {
					RSAKey rsaKey = importRSAKey(null, args[1]);
					BigInteger s = loadSignature(args[3]);
					int[] hashVal = sha256File(args[2]);
					System.out.println("Hash code of " + args[2] + " is:");
					printHex(hashVal);
					if (verify(rsaKey, s, hashVal)) {
						System.out.println("Pass!");
						System.out.println("The file " + args[2] + " is verified!");
					} else {
						System.out.println("Failed!");
						System.out.println("The file " + args[2] + " is NOT verified!");
					}
				}
				break;
			default:
				printUsage();
				break;
			}
		}

	}

}
