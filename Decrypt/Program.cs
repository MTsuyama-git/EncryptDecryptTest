using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using Utility;

namespace Decrypt
{
    class SshCipher {
        public readonly string name;
        public readonly int blockSize;
        public readonly int keyLen;
        public readonly int ivLen;
        public readonly int authLen;
        public readonly int cipherMode;

        public SshCipher(string name, int blockSize, int keyLen, int ivLen, int authLen, int cipherMode)
        {
            this.name = name;
            this.blockSize = blockSize;
            this.keyLen = keyLen;
            this.ivLen = ivLen;
            this.authLen = authLen;
            this.cipherMode = cipherMode;
        }

        public CipherMode cipherModeEnum  {
            get {
                return (CipherMode)Enum.ToObject(typeof(CipherMode), cipherMode);
            }
        }
    }

    class Program
    {
        // 0: CTR, 6: CHACHA20-poly, 7: none, 1-5 CipherMode
        static readonly Dictionary<string, SshCipher> ciphers = new () {
            {"3des-cbc", new SshCipher("3des-cbc", 8, 24, 0, 0, (int)CipherMode.CBC)},
            {"aes128-cbc", new SshCipher("aes128-cbc", 16, 16, 0, 0, (int)CipherMode.CBC)},
            {"aes192-cbc", new SshCipher("aes192-cbc", 16, 24, 0, 0, (int)CipherMode.CBC)},
            {"aes256-cbc", new SshCipher("aes256-cbc", 16, 32, 0, 0, (int)CipherMode.CBC)},
            {"aes128-ctr", new SshCipher("aes128-ctr", 16, 16, 0, 0, 0)},
            {"aes192-ctr", new SshCipher("aes192-ctr", 16, 24, 0, 0, 0)},
            {"aes256-ctr", new SshCipher("aes256-ctr", 16, 32, 0, 0, 0)},
            {"aes128-gcm@openssh.com", new SshCipher("aes128-gcm@openssh.com", 16, 16, 12, 16, 0)},
            {"aes256-gcm@openssh.com", new SshCipher("aes256-gcm@openssh.com", 16, 32, 12, 16, 0)},
            {"chacha20-poly1305@openssh.com", new SshCipher("chacha20-poly1305@openssh.com", 8, 64, 0, 16, 6)},
            {"none", new SshCipher("none", 8, 0, 0, 0, 7)},
        };

        // struct sshcipher_ctx {
        //     int    plaintext;
        //     int    encrypt;
        //     EVP_CIPHER_CTX *evp;
        //     struct chachapoly_ctx *cp_ctx;
        //     struct aesctr_ctx ac_ctx; /* XXX union with evp? */
        //     const struct sshcipher *cipher;
        // };

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
                SshCipher cipher = ciphers[cipher_name];
                int keyLen = cipher.keyLen;
                int ivLen  = cipher.ivLen;
                int authLen = cipher.authLen;
                int blockSize = cipher.blockSize;
                if( encryptedLen < blockSize || (encryptedLen % blockSize) != 0) {
                    throw new Exception("Invalid Key Format");
                }
                if(kdf_name == "bcrypt") {
                    string salt = kdf.StrData;
                    int round = kdf.U32;
                    Console.WriteLine("Salt:" + salt);
                    Console.WriteLine("Round:" + round);
                    if(1 <= cipher.cipherMode && cipher.cipherMode <= 5) {
                        
                    }
                }
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
            //     System.Environment.Exit(1);
            // Console.WriteLine(kp);
        }

        static void Main(string[] args)
        { 
            _ = new Program(args);
        }
    }
}
