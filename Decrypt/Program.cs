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
	    using (BinaryReader br = new(File.Open(eintity, FileMode.Open))) {
		byte[] chunk;
		chunk = br.ReadBytes(CHUNK_SIZE);
		while(chunk.Length > 0) {
		    byte[] decryptedData = rsa.Decrypt(chunk, RSAEncryptionPadding.Pkcs1);
		    Encoding enc = Encoding.GetEncoding("UTF-8");
		    Console.WriteLine(enc.GetString(decryptedData));
		    chunk = br.ReadBytes(CHUNK_SIZE);
		}
	    }
	}

        static void Main(string[] args)
	{ 
	    _ = new Program(args);
	}
    }
}
