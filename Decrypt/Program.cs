using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using Utility;

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

        public void readSSHPrivateKey(string contents) 
        {
            const string RsaPrivateKeyHeader = @"-----BEGIN RSA PRIVATE KEY-----";
            const string RsaPrivateKeyFooter = @"-----END RSA PRIVATE KEY-----";
            const string OpenSSHPrivateKeyHeader = @"-----BEGIN OPENSSH PRIVATE KEY-----";
            const string OpenSSHPrivateKeyFooter = @"-----END OPENSSH PRIVATE KEY-----";

            if(contents.Substring(0, RsaPrivateKeyHeader.Length) == RsaPrivateKeyHeader) {
                // TODO: old style
                Console.WriteLine(RsaPrivateKeyHeader);
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
                Console.Write("RSA_E:");
                new ConsumableData(rsa_e).dump();
                Console.Write("RSA_N:");
                new ConsumableData(rsa_n).dump();
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
		Console.Write("Decrypted:");
		decrypted.dump();
		data.Consume((int)(encryptedLen + authLen));
		if(data.Remain != 0) {
		    throw new Exception("INVALID FORMAT of data");
		}
		uint check1 = decrypted.U32;
		uint check2 = decrypted.U32;
		if(check1 != check2) {
		    throw new Exception("Wrong Pass pharase");
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
