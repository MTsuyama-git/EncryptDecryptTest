using System;
using System.Security.Cryptography;
using System.Reflection;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Utility;

namespace Encrypt
{
    class Program
    {
        private readonly char[] del = { '\t', ' ' };

        public Program(string[] args)
            {
                if (args.Length < 2)
                {
                    Assembly myAssembly = Assembly.GetEntryAssembly();
                    Console.WriteLine("Usage: {0} input output (path to pubkey)", System.IO.Path.GetFileName(myAssembly.Location));
                    return;
                }

                string eintity = args[0];
                string dest = args[1];
                string keyPath = "";

		if(eintity == dest) {
		    Console.WriteLine("Eintity and dest are the same.");
		    return;
		}


                if (args.Length >= 3)
                {
                    keyPath = args[2];
                }
                else
                {
                    string userprofile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                    keyPath = System.IO.Path.Combine(userprofile, ".ssh", "id_rsa.pub");
                }
		RSACryptoServiceProvider provider = SSHKeyManager.ReadSSHPublicKey(keyPath);
		using (FileStream inputStream = File.Open(eintity, FileMode.Open)) {
		    using (FileStream outputStream = File.Open(dest, FileMode.Create)) {
			using (BinaryWriter bw = new BinaryWriter(outputStream)) {
			    Span<byte> readBuffer = new Span<byte>(new byte[8192]);

			    byte[] passKey = PassphraseGenerator.Generate(128);
			    var cipherBytes = provider.Encrypt(passKey, RSAEncryptionPadding.Pkcs1);
			    bw.Write(ByteConverter.convertToByte((UInt16)(cipherBytes.Length & 0xFFFF), Endian.LITTLE));
			    bw.Write(cipherBytes);
			    // generate salt
			    byte[] magic = Encoding.UTF8.GetBytes("Salted__"); // magic
			    byte[] salt = PassphraseGenerator.Generate(8); // PKCS5_SALT_LEN = 8
			    bw.Write(magic);
			    bw.Write(salt);
			    Console.Write("magic:");new ConsumableData(magic).dump();
			    Console.Write("salt:");new ConsumableData(salt).dump();
			    Rfc2898DeriveBytes b = new(passKey, salt, 10000, HashAlgorithmName.SHA256);
			    byte[] keyIv = b.GetBytes(48);
			    byte[] key = Misc.BlockCopy(keyIv, 0, 32);
			    byte[] iv = Misc.BlockCopy(keyIv, 32, 16);
			    Console.Write("key:"); new ConsumableData(key).dump();
			    Console.Write("iv:"); new ConsumableData(iv).dump();
			    Aes encAlg = Aes.Create();
			    encAlg.Key = key;
			    encAlg.IV = iv;
			    int readLen = 0;

			    using(CryptoStream encrypt = new(outputStream, encAlg.CreateEncryptor(), CryptoStreamMode.Write)) {
				while((readLen = inputStream.Read(readBuffer)) > 0) {
				    encrypt.Write(readBuffer.ToArray(), 0, readLen);
				}
				encrypt.FlushFinalBlock();
				encrypt.Close();
			    }
			}
		    }
		}
		Console.WriteLine("done.");
	    }
        static void Main(string[] args)
            {
                _ = new Program(args);
                // Console.WriteLine("Hello World!");
            }
    }
}
