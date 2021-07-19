using System;
using System.Security.Cryptography;
using System.Reflection;
using System.IO;

namespace Encrypt
{
    class Program
    {

        public void readRSAPublicKey(string contents)
        {
            var rsa = RSAOpenSsl.Create();

	    const string RsaPublicKeyHeader = @"-----BEGIN RSA PUBLIC KEY-----";
	    const string RsaPublicKeyFooter = @"-----END RSA PUBLIC KEY-----";

            var body = contents.Replace(RsaPublicKeyHeader, String.Empty).Replace(RsaPublicKeyFooter, String.Empty).Replace("\r", String.Empty).Replace("\n", String.Empty);
            Console.WriteLine(body);
            var der = Convert.FromBase64String(body);
            // Console.WriteLine(der);

            string text = "";
            string tmp = "";
            foreach (byte b in der)
            {
                text = string.Format("{0,3:X2}", b);
                tmp = text + tmp;
            }
            Console.WriteLine("\n" + tmp + "\n");


            rsa.ImportRSAPublicKey(der, out _);
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
            string keyPath = "";

            if (args.Length >= 3)
            {
                keyPath = args[2];
            }
            else
            {
                string userprofile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                keyPath = System.IO.Path.Combine(userprofile, ".ssh", "id_rsa.pub");
            }
            Console.WriteLine(keyPath);
            string contents = System.IO.File.ReadAllText(keyPath);
            readRSAPublicKey(contents);
        }

        static void Main(string[] args)
        {
            _ = new Program(args);
            // Console.WriteLine("Hello World!");
        }
    }
}
