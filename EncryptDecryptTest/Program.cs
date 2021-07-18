using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace EncryptDecryptTest
{
    class Program
    {
        private class PasswordFinder : IPasswordFinder
        {
            private readonly string password;

            public PasswordFinder(string password)
            {
                this.password = password;
            }


            public char[] GetPassword()
            {
                return password.ToCharArray();
            }
        }

        private string keyPath = "";

	public AsymmetricCipherKeyPair readRSAPrivateKey(string pemContents)
	{
	    var keyReader = new StringReader(pemContents);
	    // read key without password
	    AsymmetricCipherKeyPair kp = null;
	    try {
		PemReader pemReader0 = new PemReader(keyReader);
	        kp = (AsymmetricCipherKeyPair) pemReader0.ReadObject();
	    } catch(PasswordException pe) {
		try {
		    Console.Write("Password:");
		    var line = System.Console.ReadLine();
		    // read key with password
		    var keyReader2 = new StringReader(pemContents);
		    PemReader pemReader = new PemReader(keyReader2, pFinder: new PasswordFinder(line));
		    // object privateKeyObject = pemReader.ReadObject();
		    kp = (AsymmetricCipherKeyPair) pemReader.ReadObject();
		} catch  (InvalidCipherTextException ice) {
		    Console.WriteLine("Bad passphrase");
		}
	    }
	    return kp;
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

	    byte[] der = null;
	    const string RsaPrivateKeyHeader = "-----BEGIN RSA PRIVATE KEY-----";
	    const string RsaPrivateKeyFooter = "-----END RSA PRIVATE KEY-----";
	    string pemContents = System.IO.File.ReadAllText(keyPath);
	    var kp = readRSAPrivateKey(pemContents);
	    if(kp == null)
		System.Environment.Exit(1);
	    Console.WriteLine(kp);
        }

        static void Main(string[] args)
        {
            _ = new Program(args);
        }
    }
}
