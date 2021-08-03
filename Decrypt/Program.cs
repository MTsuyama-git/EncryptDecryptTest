using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using Utility;
using System.Numerics;

namespace Decrypt
{
    class Program
    {
        private string keyPath = "";
	private static readonly int CHUNK_SIZE = 4096;

	string passwordCb() {
	    Console.Write("Input Passphrase:");
	    return Console.ReadLine();   
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

	    RSA rsa = SSHKeyManager.ReadSSHPrivateKey(keyPath, passwordCb);
	    using (FileStream inputStream = File.Open(eintity, FileMode.Open)) {
		using (FileStream outputStream = File.Open(dest, FileMode.Create)) {
		    using (BinaryReader br = new (inputStream)) {
			Span<byte> readBuffer = new Span<byte>(new byte[8192]);
			byte[] headerSizeB = new byte[2];
			br.Read(headerSizeB, 0, headerSizeB.Length);
			UInt16 headerSize = ByteConverter.convertToU16(headerSizeB, Endian.LITTLE);
			Console.WriteLine("headerSize:{0}", headerSize);
			byte[] cipherBytes = new byte[headerSize];
			br.Read(cipherBytes, 0, cipherBytes.Length);
			byte[] decrypted = rsa.Decrypt(cipherBytes, RSAEncryptionPadding.Pkcs1);
			
			byte[] magic = new byte[8];
			byte[] salt = new byte[8];
			br.Read(magic, 0, magic.Length);
			br.Read(salt, 0, salt.Length);
			Console.Write("magic:");new ConsumableData(magic).dump();
			Console.Write("salt:");new ConsumableData(salt).dump();
			var b = new Rfc2898DeriveBytes(decrypted, salt, 10000, HashAlgorithmName.SHA256);
			Console.WriteLine("hashAlgorithm:{0}", b.HashAlgorithm);
			byte[] keyIv = b.GetBytes(48);
			byte[] key = Misc.BlockCopy(keyIv, 0, 32);
			byte[] iv = Misc.BlockCopy(keyIv, 32, 16);
			Console.Write("keyIV:");new ConsumableData(keyIv).dump();
			Console.Write("key:");new ConsumableData(key).dump();
			Console.Write("iv:");new ConsumableData(iv).dump();
			Aes encAlg = Aes.Create();
			encAlg.Key = key;
			encAlg.IV = iv;
			int readLen = 0;
			using(CryptoStream decrypt = new(outputStream, encAlg.CreateDecryptor(), CryptoStreamMode.Write)) {
			    while((readLen = inputStream.Read(readBuffer)) > 0) {
				decrypt.Write(readBuffer.ToArray(), 0, readLen);
			    }
			    decrypt.FlushFinalBlock();
			    decrypt.Close();
			}

		    }
		}
	    }
	}

        static void Main(string[] args)
	{ 
	    _ = new Program(args);
	}
    }
}
