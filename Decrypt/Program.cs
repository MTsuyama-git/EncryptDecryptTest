using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using Utility;
using System.Linq;
using System.Numerics;

namespace Decrypt
{
    class Program
    {
        // struct sshcipher_ctx {
        //     int    plaintext;
        //     int    encrypt;
        //     EVP_CIPHER_CTX *evp;
        //     struct chachapoly_ctx *cp_ctx;
        //     struct aesctr_ctx ac_ctx; /* XXX union with evp? */
        //     const struct sshcipher *cipher;
        // };

        private string keyPath = "";


        private void check_padding(ConsumableData decrypted)
	{
	    byte pad;
	    UInt64 i;
	    i = 0;
	    while (decrypted.Remain > 0) {
		pad = decrypted.U8;
		if (pad != (++i & 0xff)) {
		    Console.WriteLine(i + "," + pad);
		    throw new Exception("Invalid padding");
		}
	    }
	    /* success */
	}



        public RSAParameters deserializeKey(ConsumableData buf) {
            string tname = buf.StrData;
            Console.WriteLine("tname:" + tname);
            ConsumableData rsa_n = new(buf.trimmedRawData);
            // sshkey_from_blob_internal
            ConsumableData rsa_e = new(buf.trimmedRawData);
            ConsumableData rsa_d = new(buf.rawData);
            ConsumableData rsa_iqmp = new(buf.trimmedRawData);
            ConsumableData rsa_p = new(buf.rawData);
            ConsumableData rsa_q = new(buf.rawData);

            string comment = buf.StrData;
            check_padding(buf);

	    var d_data = rsa_d.SubArray();
	    Array.Reverse(d_data);
	    var p_data = rsa_p.SubArray();
	    Array.Reverse(p_data);
	    var q_data = rsa_q.SubArray();
	    Array.Reverse(q_data);


            BigInteger brsa_p = new(p_data);
            BigInteger brsa_q = new(q_data);
            BigInteger brsa_d = new(d_data);

	    brsa_p -= 1;
	    brsa_q -= 1;
	    
            BigInteger brsa_dp1 = brsa_d & brsa_p;
            BigInteger brsa_dq1 = brsa_d % brsa_q;

	    var dmp1b = brsa_dp1.ToByteArray();
	    var dmq1b = brsa_dq1.ToByteArray();

	    Array.Reverse(dmp1b);
	    Array.Reverse(dmq1b);

            return new RSAParameters {
                Exponent = rsa_e.SubArray(),
                Modulus  = rsa_n.SubArray(),
                D        = ByteConverter.trim(rsa_d.SubArray()),
                P        = ByteConverter.trim(rsa_p.SubArray()),
                Q        = ByteConverter.trim(rsa_q.SubArray()),
                InverseQ = rsa_iqmp.SubArray(),
                DP       = ByteConverter.trim(dmp1b),
                DQ       = ByteConverter.trim(dmq1b),
            };
        }


        private readonly char[] del = { '\n' };
        public void readSSHPrivateKey(string contents) 
	{
	    const string RsaPrivateKeyHeader = @"-----BEGIN RSA PRIVATE KEY-----";
	    const string RsaPrivateKeyFooter = @"-----END RSA PRIVATE KEY-----";
	    const string OpenSSHPrivateKeyHeader = @"-----BEGIN OPENSSH PRIVATE KEY-----";
	    const string OpenSSHPrivateKeyFooter = @"-----END OPENSSH PRIVATE KEY-----";

			if (contents.Substring(0, RsaPrivateKeyHeader.Length) == RsaPrivateKeyHeader) {
				// TODO: old style
				Console.WriteLine(RsaPrivateKeyHeader);
				contents = contents.Replace("\r", String.Empty);
				string[] contentlines = contents.Split(del, StringSplitOptions.RemoveEmptyEntries);
				contents = String.Empty;
				List<string> headers = new();
				foreach (string line in contentlines) {
					if (line.Contains(':'))
					{
						headers.Add(line);
						continue;
					}
					else if (line.Length == 0)
					{
						continue;
					}
					contents += line;
				}
				contents = contents.Replace(RsaPrivateKeyHeader, String.Empty).Replace(RsaPrivateKeyFooter, String.Empty).Replace("\n", String.Empty);
				Console.WriteLine(contents);
				byte[] encrypted_data = Convert.FromBase64String(contents);
				ConsumableData data = new(encrypted_data);
				data.dump();
				SshCipher cipher = null;
				string encryptInfo;
				int ivlen;
				byte[] iv = null;
				foreach (string header in headers)
				{
					var h = header.Split(":");
					if (h[0] == "DEK-Info")
					{
						encryptInfo = h[1].Split(",")[0].Replace(" ", String.Empty);
						encryptInfo = encryptInfo.ToLower();
						string ivInfo = h[1].Split(",")[1].Replace(" ", String.Empty);
						iv = ByteConverter.ParseStrAsByteArray(ivInfo);
						new ConsumableData(iv).dump();
						//cipher = SshCipher.ciphers[encryptInfo];
					}
				}

				if (iv == null)
				{
					Console.WriteLine("Cannot load IV");
					return;
				}
				if (cipher != null)
				{
					Console.WriteLine("IVLEN:{0}, KEYLEN: {1}", cipher.ivLen, cipher.keyLen);
					ivlen = cipher.ivLen;
				}
				else
				{
					ivlen = 16;
				}
				using MD5 md5 = MD5.Create();
				md5.Initialize();
				byte[] result = null;
				// using(MemoryStream s = new()) {
				//     s.Write(ByteConverter.Str2ByteArray("testtest"), 0, 8);
				//     buf = s.GetBuffer();
				//     s.Write(iv, 0, 8);
				//     result = md5.ComputeHash(s.ToArray());
				// }

				// Console.Write("md5:");
				// new ConsumableData(result).dump();

				ConsumableData cd = new(ByteConverter.Str2ByteArray("testtest"));
				ConsumableData cd2 = new(Misc.BlockCopy(iv, 0, 8));
				ConsumableData cd3 = cd + cd2;

				result = md5.ComputeHash(cd3.SubArray());
				Console.Write("md5:");
				new ConsumableData(result).dump();
				byte[] decrypted = null;
				using (AesManaged aes = new ())
                {
					aes.KeySize = 16*8;
					aes.BlockSize = 16*8;
					aes.IV = iv;
					aes.Key = result;
					aes.Mode = CipherMode.CBC;
					aes.Padding = PaddingMode.PKCS7;
					using (var decryptor = aes.CreateDecryptor())
					using (var mstream1 = new MemoryStream(encrypted_data))
					using (var cstream = new CryptoStream(mstream1, decryptor, CryptoStreamMode.Read))
					using (var mstream2 = new MemoryStream())
					{
						cstream.CopyTo(mstream2);
						decrypted = mstream2.ToArray();
					}
					new ConsumableData(decrypted).dump();


				}
                //using(RijndaelManaged rijndael = new())
                //{
                //   rijndael.BlockSize = 128;
                //  rijndael.KeySize = 128;
                //}


            }
            else if(contents.Substring(0, OpenSSHPrivateKeyHeader.Length) == OpenSSHPrivateKeyHeader) {
		// newer style
		contents = contents.Replace(OpenSSHPrivateKeyHeader, String.Empty).Replace(OpenSSHPrivateKeyFooter, String.Empty).Replace("\r", String.Empty).Replace("\n", String.Empty);
		ConsumableData data = new(Convert.FromBase64String(contents));
		string magic = data.readString(14);
		data.Consume(1);
		string cipher_name = data.StrData;
		string kdf_name = data.StrData;
		// ConsumableData kdf = new(data.StrData);
		// string kdf = data.StrData;
		ConsumableData kdf = new(data.rawData);
		uint    nkeys = data.U32;
		ConsumableData pubkey = new(data.rawData);
		uint encryptedLen = data.U32;
        
		Console.WriteLine(magic);
		Console.WriteLine(cipher_name);
		Console.WriteLine(kdf_name);
		// kdf.dump();
		Console.WriteLine("kdf:" + kdf.Size);
		Console.WriteLine("nkeys:" + nkeys);
		Console.WriteLine("encryptedLen:" + encryptedLen);
		Console.WriteLine("pubKey:" + pubkey.Size);
		Console.WriteLine("pubKeyType:" + pubkey.StrData);
		Console.Write("pubkey:");
		pubkey.dump();
		byte[] rsa_e = pubkey.trimmedRawData;
		byte[] rsa_n = pubkey.trimmedRawData;
		// Console.Write("RSA_E:");
		// new ConsumableData(rsa_e).dump();
		// Console.Write("RSA_N:");
		// new ConsumableData(rsa_n).dump();
		SshCipher cipher = SshCipher.ciphers[cipher_name];
		int keyLen = cipher.keyLen;
		int ivLen  = cipher.ivLen;
		int authLen = cipher.authLen;
		int blockSize = cipher.blockSize;
		Console.WriteLine("keyLen:" + keyLen);
		Console.WriteLine("ivLen:" + ivLen);
		Console.WriteLine("authLen:" + authLen);
		Console.WriteLine("blockSize:" + blockSize);
		if( encryptedLen < blockSize || (encryptedLen % blockSize) != 0) {
		    throw new Exception("Invalid Key Format");
		}
		byte[] key = new byte[keyLen + ivLen];
		Array.Fill<byte>(key, 1);
		if(kdf_name == "bcrypt") {
		    Console.Write("kdf:"); kdf.dump();
		    byte[] salt = kdf.rawData;
		    uint round = kdf.U32;
		    string passphrase = "testtest";
		    Console.Write("salt:"); new ConsumableData(salt).dump();
		    // var sw = new System.Diagnostics.Stopwatch(); // 
		    // sw.Restart();				 // 
		    if(Bcrypt.pbkdf(passphrase, salt, ref key, (int)round) < 0) {
			throw new Exception("Invalid format@pbkdf");
		    }
		    else {
			// sw.Stop();	// 
			// Console.WriteLine($"PBKDF elapsed: {sw.ElapsedMilliseconds} ms"); // 
			ConsumableData cdkey = new(key);
			Console.Write("key:");
			cdkey.dump();
			
		    }
		}

		if(data.Remain < authLen || data.Remain - authLen < encryptedLen) {
		    throw new Exception("INVALID format@RemainCheck");
		}
		byte[] keyBody = Misc.BlockCopy(key, 0, keyLen);
		byte[] ivBody = Misc.BlockCopy(key, keyLen, ivLen);
		Console.Write("keyBody:"); new ConsumableData(keyBody).dump();
		Console.Write("ivBody:"); new ConsumableData(ivBody).dump();
		SshCipherCtx cipherCtx = new(cipher, keyBody, ivBody, false);
		ConsumableData decrypted = new(cipherCtx.Crypt(0, data.Remains, (int)encryptedLen, 0, authLen));
		// Console.Write("Decrypted:");
		// decrypted.dump();
		data.Consume((int)(encryptedLen + authLen));
		if(data.Remain != 0) {
		    throw new Exception("INVALID FORMAT of data");
		}
		uint check1 = decrypted.U32;
		uint check2 = decrypted.U32;
		if(check1 != check2) {
		    throw new Exception("Wrong Pass pharase");
		}
		RSAParameters params0 = deserializeKey(decrypted);
		using (var rsa = new RSACryptoServiceProvider()) {
		    rsa.ImportParameters(params0);

		    byte[] encrypted = new byte[]{0x1C, 0x9C, 0xF4, 0xB3, 0x02, 0x0C, 0x0B, 0x75, 0x86, 0x12, 0x6C, 0x4A, 0xFD, 0xEF, 0x29, 0x78, 0x94, 0x81, 0x9C, 0x9C, 0x77, 0x09, 0xD2, 0x31, 0x8B, 0xA6, 0x53, 0xED, 0x1A, 0xFD, 0xF6, 0x5F, 0xF5, 0xAE, 0xAB, 0x45, 0xBB, 0x6D, 0xA1, 0x47, 0x24, 0x09, 0x93, 0x22, 0x18, 0xC4, 0x5E, 0x02, 0xF6, 0xD4, 0xB1, 0x66, 0xDC, 0x97, 0x27, 0x34, 0x7D, 0xD9, 0x97, 0x71, 0x81, 0xB8, 0xD9, 0xC8, 0xBA, 0x5B, 0xBE, 0x83, 0xBD, 0x37, 0xA3, 0xEB, 0xCC, 0x3D, 0xE2, 0x64, 0x57, 0xAB, 0x37, 0x1F, 0x16, 0xE1, 0x41, 0xB1, 0xC6, 0xA7, 0x63, 0x8A, 0x78, 0xC1, 0x6C, 0x6F, 0x31, 0x16, 0x5B, 0x19, 0x03, 0xE1, 0xDB, 0x1B, 0xCF, 0x4E, 0xA5, 0x11, 0x09, 0x27, 0x42, 0x86, 0xBE, 0xAC, 0x8D, 0x68, 0xF5, 0x91, 0x83, 0x29, 0xE6, 0x9C, 0x9D, 0xAE, 0xAF, 0xD1, 0xAC, 0xBC, 0x0E, 0x9E, 0x6E, 0x4D, 0xDA, 0x8E, 0x0F, 0x69, 0x43, 0x3F, 0xC1, 0xB1, 0x81, 0xAB, 0x67, 0x44, 0x4A, 0xF6, 0x42, 0x6D, 0x78, 0x6E, 0x1A, 0x70, 0x90, 0x35, 0x36, 0x24, 0x73, 0xC7, 0x64, 0xF8, 0xB6, 0x38, 0x38, 0xC4, 0x88, 0xFD, 0x04, 0xC9, 0xE1, 0xF6, 0x94, 0xBC, 0x4A, 0x3F, 0xAD, 0x54, 0x39, 0xC7, 0x00, 0xC2, 0xC2, 0x4F, 0x27, 0xD7, 0x1A, 0xC5, 0xC5, 0x85, 0xCF, 0xD3, 0x63, 0x30, 0x43, 0xF7, 0x11, 0x4A, 0xC2, 0xC8, 0x8E, 0x5D, 0xC6, 0x67, 0xD6, 0x8C, 0x2B, 0x5B, 0x66, 0xD9, 0x28, 0xAF, 0x4F, 0x10, 0xCB, 0x12, 0x3A, 0xD8, 0x92, 0xA1, 0x0D, 0x1A, 0x09, 0x0A, 0xD4, 0x93, 0x58, 0x8C, 0xC6, 0x88, 0x45, 0x21, 0x7A, 0x86, 0x75, 0x55, 0xEA, 0x22, 0xF6, 0x6F, 0x63, 0x2D, 0x97, 0xAF, 0x19, 0x52, 0x1F, 0xDA, 0x07, 0x33, 0xD5, 0x4E, 0x32, 0x80, 0xDD, 0xCB, 0xDD, 0x15, 0xC8, 0xE4, 0xCB, 0x30, 0x32, 0x7B, 0x66, 0x4B, 0x0C, 0x3D, 0xD9, 0x41, 0x23, 0x12, 0x79, 0x69, 0x9A, 0x8A, 0xF1, 0x21, 0xDD, 0x1B, 0x10, 0xEF, 0x71, 0x3B, 0xF0, 0xD5, 0x3E, 0x88, 0x2D, 0x76, 0x76, 0x63, 0x1B, 0x98, 0xAC, 0xDE, 0xCB, 0x81, 0x51, 0x90, 0xAA, 0x1B, 0xB5, 0x35, 0x2A, 0x52, 0x89, 0xDD, 0x70, 0x93, 0x42, 0x3D, 0x52, 0xAF, 0x65, 0x9A, 0x37, 0xE0, 0xFF, 0xDD, 0x83, 0xE0, 0xF0, 0xD4, 0xD1, 0x0B, 0x3F, 0x22, 0xB4, 0xBF, 0xC1, 0xE2, 0xE5, 0x61, 0x8C, 0xB6, 0x3D, 0x97, 0x19, 0xCC, 0x8F, 0xAC, 0x74, 0x40, 0x20, 0xC4, 0x51, 0xCF, 0xCE, 0x2D, 0xB9, 0xA3, 0x44, 0x85, 0x59, 0x46, 0x27, 0xC2, 0x2C, 0x98, 0xE5, 0x86, 0xDD, 0x52, 0xAA, 0x33, 0x84, 0x58, 0x62, 0xE3, 0x41, 0x2E, 0xAD, 0x33, 0xD7, 0xF5, 0x0B, 0x74, 0x26, 0xB2, 0x0B, 0x4E, 0x1C, 0xCA, 0x57, 0xD2, 0xD4, 0x47, 0x88, 0x7E};
		    byte[] decryptedData = rsa.Decrypt(encrypted, RSAEncryptionPadding.Pkcs1);
		    Encoding enc = Encoding.GetEncoding("UTF-8");
		    Console.WriteLine(enc.GetString(decryptedData));
                        
		}
	    }
	    else {
		throw new Exception("Invalid SSH key type");
	    }
        
	}


        public Program(string[] args)
	{
	    if (args.Length < 2)
	    {
		Assembly myAssembly = Assembly.GetEntryAssembly();
		Console.WriteLine("Usage: {0} input output", System.IO.Path.GetFileName(myAssembly.Location));
		return;
	    }

	    string eintity = args[0];
	    string dest = args[1];

	    if (args.Length >= 3)
	    {
		keyPath = args[2];
	    }
	    else
	    {
		string userprofile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
		keyPath = System.IO.Path.Combine(userprofile, ".ssh", "id_rsa");
	    }
	    Console.WriteLine(keyPath);

        
	    readSSHPrivateKey(System.IO.File.ReadAllText(keyPath));
	    // var kp = readRSAPrivateKey(pemContents);
	    // if(kp == null)
	    //     System.Environment.Exit(1);
	    // Console.WriteLine(kp);
	}

        static void Main(string[] args)
	{ 
	    _ = new Program(args);
	}
    }
}
