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
            // using (BinaryReader br = new(File.Open(keyPath, FileMode.Open)))
            // {
            //     var arr = br.ReadBytes(512);

            //     var rsa = RSA.Create();
            //     int nBytes = 0;
            //     rsa.ImportRSAPrivateKey(arr, out nBytes);
            // }
	    byte[] der = null;
	    const string RsaPrivateKeyHeader = "-----BEGIN RSA PRIVATE KEY-----";
	    const string RsaPrivateKeyFooter = "-----END RSA PRIVATE KEY-----";
	    string pemContents = System.IO.File.ReadAllText(keyPath);

	    // if (pemContents.StartsWith(RsaPrivateKeyHeader))
	    // {
	    // 	int endIdx = pemContents.IndexOf(
	    // 	    RsaPrivateKeyFooter,
	    // 	    RsaPrivateKeyHeader.Length,
	    // 	    StringComparison.Ordinal);

	    // 	string base64 = pemContents.Substring(
	    // 	    RsaPrivateKeyHeader.Length,
	    // 	    endIdx - RsaPrivateKeyHeader.Length);

	    // 	der = Convert.FromBase64String(base64);
	    // 	RSA rsa = RSA.Create();
	    // 	rsa.ImportRSAPrivateKey(der, out _);
	    // }
	    var keyReader = new StringReader(pemContents);
	    PemReader pemReader = new PemReader(keyReader, pFinder: new PasswordFinder("testtest"));
	    object privateKeyObject = pemReader.ReadObject();
	    RsaPrivateCrtKeyParameters rsaPrivatekey = (RsaPrivateCrtKeyParameters)privateKeyObject;
	    RsaKeyParameters rsaPublicKey = new RsaKeyParameters(false, rsaPrivatekey.Modulus, rsaPrivatekey.PublicExponent);
	    AsymmetricCipherKeyPair kp = new AsymmetricCipherKeyPair(rsaPublicKey, rsaPrivatekey);



	    // using(StreamReader stream = new(keyPath, Encoding.UTF8))
	    // {
	    // 	var key = stream.ReadToEnd();
	    // 	var encoded = key.Replace(@"-----BEGIN RSA PRIVATE KEY-----", string.Empty).
	    // 	    Replace(@"-----END RSA PRIVATE KEY-----", string.Empty);
	    // 	encoded = new Regex(@"\r?\n").Replace(encoded, string.Empty);
	    // 	Console.WriteLine(encoded);
	    // 	der = Convert.FromBase64String(encoded);
	    // }
	    
	    // var rsa = RSA.Create();
	    // int nBytes = 0;
	    // rsa.ImportRSAPrivateKey(der, out nBytes);

        }

        static void Main(string[] args)
        {
            _ = new Program(args);
        }
    }
}
