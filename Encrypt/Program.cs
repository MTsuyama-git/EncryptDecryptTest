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
		using (BinaryWriter bw = new BinaryWriter(File.Open(dest, FileMode.Create))) {
		    var plainBytes = Encoding.UTF8.GetBytes("testtest");
		    var cipherBytes = provider.Encrypt(plainBytes, RSAEncryptionPadding.Pkcs1);
		    bw.Write(cipherBytes);
		    
		}

            }

        static void Main(string[] args)
            {
                _ = new Program(args);
                // Console.WriteLine("Hello World!");
            }
    }
}
