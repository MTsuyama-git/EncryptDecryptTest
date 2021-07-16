using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;

namespace EncryptDecryptTest
{
    class Program
    {
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

            using (BinaryReader br = new(File.Open(keyPath, FileMode.Open)))
            {
                var arr = br.ReadBytes(512);

                var rsa = RSA.Create();
                int nBytes = 0;
                rsa.ImportRSAPrivateKey(arr, out nBytes);
            }

           

            


        }

        static void Main(string[] args)
        {
            _ = new Program(args);
        }
    }
}
