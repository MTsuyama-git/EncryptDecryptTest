using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Utility;

namespace Decrypt
{
    class Program
    {

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
		int    nkeys = data.U32;
		ConsumableData pubkey = new(data.rawData);
		int encryptedLen = data.U32;
		
		Console.WriteLine(magic);
		Console.WriteLine(cipher_name);
		Console.WriteLine(kdf_name);
		kdf.dump();
		Console.WriteLine("kdf:" + kdf.Size);
		Console.WriteLine("nkeys:" + nkeys);
		Console.WriteLine("encryptedLen:" + encryptedLen);
		Console.WriteLine("pubKey:" + pubkey.Size);
		pubkey.dump();

		string salt = kdf.StrData;
		int round = kdf.U32;
		Console.WriteLine("Salt:" + salt);
		Console.WriteLine("Round:" + round);
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
	    // 	System.Environment.Exit(1);
	    // Console.WriteLine(kp);
        }

        static void Main(string[] args)
        { 
            _ = new Program(args);
        }
    }
}
