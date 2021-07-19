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

	public void readRSAPrivateKeyCrypto(string pemContents)
        {
            var rsa = RSAOpenSsl.Create();
            string password = "hogehoge";
            const string RsaPrivateKeyHeader = @"-----BEGIN RSA PRIVATE KEY-----";
            const string RsaPrivateKeyFooter = @"-----END RSA PRIVATE KEY-----";
            var keybody = pemContents.Replace(RsaPrivateKeyHeader, String.Empty).Replace(RsaPrivateKeyFooter, String.Empty).Replace("\r", "").Replace("\n", "");
            Console.WriteLine(keybody);
            // var privateKeyBytes = Convert.FromBase64String(keybody);
            // rsa.ImportRSAPrivateKey(privateKeyBytes, out _); 

	    var der = Convert.FromBase64String(keybody);
	    string text = "";
	    string tmp = "";
            foreach(byte b in der)
            {
                text = string.Format("{0,3:X2}", b);
                tmp = text + tmp;
            }
            Console.WriteLine("\n" + tmp + "\n");
	    rsa.ImportRSAPrivateKey(der, out _ );
            // rsa.ImportEncryptedPkcs8PrivateKey(System.Text.Encoding.UTF8.GetBytes(password), der, out _);
            // rsa.ImportEncryptedPkcs8PrivateKey(System.Text.Encoding.UTF8.GetBytes(password), System.Text.Encoding.UTF8.GetBytes(keybody), out _);
        }

	public AsymmetricCipherKeyPair readRSAPrivateKey(string pemContents)
	{
	    var keyReader = new StringReader(pemContents);
	    // read key without password
	    AsymmetricCipherKeyPair kp = null;
	    try {
		PemReader pemReader0 = new PemReader(keyReader);
	        kp = (AsymmetricCipherKeyPair) pemReader0.ReadObject();
	    } catch (PasswordException)
            {
		try {
		    Console.Write("Password:");
		    var line = System.Console.ReadLine();
		    // read key with password
		    var keyReader2 = new StringReader(pemContents);
		    PemReader pemReader = new PemReader(keyReader2, pFinder: new PasswordFinder(line));
		    // object privateKeyObject = pemReader.ReadObject();
		    kp = (AsymmetricCipherKeyPair) pemReader.ReadObject();
		} catch  (InvalidCipherTextException) {
		    Console.WriteLine("Bad passphrase");
		}
	    } catch(PemException pe) {
		Console.WriteLine(pe);
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
	    readRSAPrivateKeyCrypto(pemContents);
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
