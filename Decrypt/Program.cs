using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using Utility;
using Org.BouncyCastle.Math;
// using System.Numerics;

namespace Decrypt
{
    class Program
    {
        // struct sshcipher_ctx {
        //     int    plaintext;
        //     int    encrypt;
        //     EVP_CIPHER_CTX *evp;
        //     struct chachapoly_ctx *cp_ctx;
        //     struct aesctr_ctx ac_ctx; /* XXX union with evp? */
        //     const struct sshcipher *cipher;
        // };

        private string keyPath = "";


        private void check_padding(ConsumableData decrypted)
            {
                byte pad;
                UInt64 i;
                i = 0;
                while (decrypted.Remain > 0) {
                    pad = decrypted.U8;
                    if (pad != (++i & 0xff)) {
                        Console.WriteLine(i + "," + pad);
                        throw new Exception("Invalid padding");
                    }
                }
                /* success */
            }



        public RSAParameters deserializeKey(ConsumableData buf) {
            string tname = buf.StrData;
            Console.WriteLine("tname:" + tname);
            ConsumableData rsa_n = new(buf.trimmedRawData);
            // sshkey_from_blob_internal
            ConsumableData rsa_e = new(buf.trimmedRawData);
            Console.Write("rsa_n:");
            rsa_n.dump();
            Console.Write("rsa_e:");
            rsa_e.dump();
            ConsumableData rsa_d = new(buf.trimmedRawData);
            Console.Write("rsa_d:");
            rsa_d.dump();
            ConsumableData rsa_iqmp = new(buf.trimmedRawData);
            Console.Write("rsa_iqmp:");
            rsa_iqmp.dump();
            ConsumableData rsa_p = new(buf.trimmedRawData);
            Console.Write("rsa_p:");
            rsa_p.dump();
            ConsumableData rsa_q = new(buf.trimmedRawData);
            Console.Write("rsa_q:");
            rsa_q.dump();

            string comment = buf.StrData;
            Console.WriteLine("Comment:" + comment);
            check_padding(buf);
            Console.WriteLine("length of rsa_p:"+rsa_p.Size);
            Console.WriteLine("length of rsa_q:"+rsa_q.Size);
            Console.WriteLine("length of rsa_d:"+rsa_d.Size);

            BigInteger brsa_p = new (1, rsa_p.SubArray());
            BigInteger brsa_q = new (1, rsa_q.SubArray());
            BigInteger brsa_d = new (1, rsa_d.SubArray());

            brsa_q = brsa_q.Subtract(new BigInteger("1"));
            brsa_p = brsa_p.Subtract(new BigInteger("1"));

            BigInteger brsa_dp1 = brsa_d.Mod(brsa_p);
            BigInteger brsa_dq1 = brsa_d.Mod(brsa_q);

            

            // BigInteger bp = new (rsa_p.SubArray());
            // BigInteger bq = new (rsa_q.SubArray());
            // BigInteger bd = new (rsa_d.SubArray());
            // // Console.WriteLine("bp:" + bp);
            // // Console.WriteLine("bq:" + bq);
            // // Console.WriteLine("bd:" + bd);
            // // bp = bp - 1;
            // // bq = bq - 1;
            // bp = BigInteger.Subtract(bp, new BigInteger(1));
            // bq = BigInteger.Subtract(bq, new BigInteger(1));
            
            // ConsumableData aaa= new(bp.ToByteArray());
            // ConsumableData bbb= new(bq.ToByteArray());
            
            // aaa.dump();
            // Console.WriteLine();
            // bbb.dump();

            // BigInteger bdp = bd % bp;
            // BigInteger bdq = bd % bq;
            byte[] ref_exponent1 = new byte[]{
                0x2d, 0x4f, 0x44, 0x50, 0xc4, 0xa8, 0xad, 0x03, 0x0a, 0xa4, 0x0c, 0xf5, 0x4b, 0x50, 0x56, 0x76, 0xc6, 0xdd, 0x4b, 0xab, 0x0d, 0xa9, 0x6c, 0x98, 0xb0, 0x9a, 0x6c, 0xdb, 0x6a, 0x5d, 0x8d, 0x8c, 0x1d, 0x24, 0xb7, 0xc8, 0x77, 0x24, 0x9b, 0xd4, 0xdf, 0x91, 0x83, 0x03, 0x58, 0x6c, 0x30, 0x33, 0xb1, 0x28, 0x55, 0x6b, 0xbc, 0x20, 0xf1, 0xb5, 0x7d, 0xc8, 0x74, 0x90, 0x05, 0x1e, 0xb2, 0x70, 0x19, 0xff, 0x30, 0xc5, 0x24, 0xda, 0xd2, 0xa9, 0x92, 0x69, 0x1a, 0x5e, 0x58, 0x39, 0x31, 0x0e, 0x25, 0x94, 0x92, 0xbf, 0xf5, 0x63, 0x09, 0xc7, 0xbf, 0xf6, 0x15, 0x71, 0x4f, 0x9d, 0x09, 0x74, 0xe0, 0xeb, 0x64, 0x53, 0x94, 0x30, 0x1e, 0xcb, 0x37, 0x97, 0x29, 0x6d, 0x6a, 0x21, 0x4d, 0x72, 0x7c, 0xbf, 0x01, 0xd7, 0x1b, 0x05, 0x42, 0xf6, 0x29, 0xaa, 0x7d, 0x17, 0x72, 0x0b, 0xb1, 0x99, 0x77, 0x73, 0x5e, 0x43, 0x03, 0xf1, 0x21, 0x0f, 0xdf, 0xb7, 0x75, 0x73, 0x99, 0xe8, 0x7a, 0x97, 0x44, 0x2e, 0xc1, 0x9f, 0x3d, 0x23, 0x2f, 0xeb, 0xf6, 0x11, 0xa3, 0x45, 0x08, 0xb8, 0xbd, 0x54, 0x9a, 0x2c, 0x64, 0x7d, 0x6d, 0xc1, 0x61, 0xf3, 0xf4, 0x28, 0x12, 0xb3, 0x12, 0x16, 0xc3, 0xaf, 0x04, 0xb1, 0x92, 0x96, 0x4e, 0x80, 0x5b, 0x44, 0xb6, 0xd2, 0xf1, 0x74, 0x3e, 0x5b, 0xdb, 0x09
            };
            byte[] ref_exponent2 = new byte[]{
                0xf4, 0xda, 0xe9, 0x86, 0xe6, 0x21, 0xfa, 0xe5, 0x48, 0xce, 0xe1, 0x62, 0xa1, 0x79, 0xb4, 0x3e, 0xd0, 0xc9, 0x72, 0x85, 0x76, 0xc9, 0xfc, 0x8a, 0x03, 0xdf, 0x59, 0x51, 0x81, 0x91, 0x9f, 0x7e, 0x04, 0xf3, 0x32, 0x25, 0x87, 0x1e, 0x0d, 0x2b, 0x78, 0x6e, 0x8d, 0xe0, 0x74, 0xe9, 0x68, 0xe1, 0xb5, 0x66, 0x96, 0xac, 0xda, 0x9d, 0xd8, 0xfd, 0x1d, 0xcc, 0xd4, 0xa6, 0x2b, 0x33, 0x94, 0x21, 0xa8, 0x5e, 0xe9, 0x53, 0xa6, 0x9f, 0xcd, 0xb0, 0x25, 0xcb, 0xd8, 0x50, 0x89, 0x7f, 0x8b, 0x43, 0x7e, 0x1c, 0x8f, 0x17, 0xac, 0x0f, 0x63, 0xda, 0xe1, 0x10, 0x36, 0xfe, 0x6b, 0x07, 0xb7, 0x88, 0xdd, 0x4e, 0xbb, 0x35, 0x45, 0x79, 0x08, 0xfa, 0xa6, 0xa9, 0x67, 0xe5, 0xf2, 0x4f, 0xa5, 0x0e, 0x36, 0x3f, 0x8e, 0x5b, 0x3c, 0x86, 0x62, 0x5c, 0x61, 0x11, 0x40, 0xa0, 0x20, 0x38, 0x7a, 0xae, 0x85, 0xc8, 0x20, 0xb1, 0x11, 0x59, 0x69, 0x50, 0x19, 0xe7, 0xbd, 0x1c, 0xf0, 0x69, 0x24, 0xa6, 0x45, 0x38, 0xb2, 0x04, 0x84, 0xbb, 0x2b, 0xb6, 0xe7, 0xdc, 0x69, 0xb5, 0x73, 0xff, 0x14, 0x02, 0x11, 0x47, 0xfd, 0x43, 0x8a, 0x12, 0x2c, 0x91, 0xf8, 0xd1, 0x72, 0xb3, 0x33, 0x90, 0x40, 0x3f, 0x47, 0x99, 0x24, 0x0c, 0x94, 0x74, 0x9f, 0x94, 0xf2, 0xac, 0xe0, 0x35, 0x05, 0x81, 0x55, 0xd1
            };
            // BigInteger bre1 = new (ref_exponent1);
            // BigInteger bre2 = new (ref_exponent2);
            // Console.WriteLine("bdp:" + (bdq));
            // Console.WriteLine("bdq:" + (bdp));
            // Console.WriteLine("bre1:" + (bre1));
            // Console.WriteLine("bre2:" + (bre2));
            // Console.WriteLine("diff1:" + (bre1 - bdp));
            // Console.WriteLine("diff2:" + (bre2 - bdq));
            // BNssl bnre1 = new(ref_exponent1);
            // BNssl bnre2 = new(ref_exponent2);
            // BNssl bnp = new(rsa_p.SubArray());
            // BNssl bnq = new(rsa_q.SubArray());
            // BNssl bnd = new(rsa_d.SubArray());
   
            // BNssl bnp1 = BNssl.sub(bnp, BNssl.value_one());
            // BNssl bnq1 = BNssl.sub(bnq, BNssl.value_one());
	    Console.Write("refdmp1:");new ConsumableData(ref_exponent1).dump();
	    Console.Write("\nrefdmq1:");new ConsumableData(ref_exponent2).dump();
	    Console.Write("\ndmp1:");new ConsumableData(brsa_dp1.ToByteArray()).dump();
	    Console.Write("\ndmq1:");new ConsumableData(brsa_dq1.ToByteArray()).dump();
            // bnre1.print();
            // bnre2.print();
            // bnd.print();
            // bnp.print();
            // bnq.print();
            return new RSAParameters {
                Exponent = rsa_e.SubArray(),
                Modulus  = rsa_n.SubArray(),
                D        = rsa_d.SubArray(),
                P        = rsa_p.SubArray(),
                Q        = rsa_q.SubArray(),
                InverseQ = rsa_iqmp.SubArray(),
                DP       = ByteConverter.trim(brsa_dp1.ToByteArray()),
                DQ       = ByteConverter.trim(brsa_dq1.ToByteArray()),
            };
        }



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
                    uint    nkeys = data.U32;
                    ConsumableData pubkey = new(data.rawData);
                    uint encryptedLen = data.U32;
        
                    Console.WriteLine(magic);
                    Console.WriteLine(cipher_name);
                    Console.WriteLine(kdf_name);
                    // kdf.dump();
                    Console.WriteLine("kdf:" + kdf.Size);
                    Console.WriteLine("nkeys:" + nkeys);
                    Console.WriteLine("encryptedLen:" + encryptedLen);
                    Console.WriteLine("pubKey:" + pubkey.Size);
                    Console.WriteLine("pubKeyType:" + pubkey.StrData);
                    Console.Write("pubkey:");
                    pubkey.dump();
                    byte[] rsa_e = pubkey.trimmedRawData;
                    byte[] rsa_n = pubkey.trimmedRawData;
                    Console.Write("RSA_E:");
                    new ConsumableData(rsa_e).dump();
                    Console.Write("RSA_N:");
                    new ConsumableData(rsa_n).dump();
                    SshCipher cipher = SshCipher.ciphers[cipher_name];
                    int keyLen = cipher.keyLen;
                    int ivLen  = cipher.ivLen;
                    int authLen = cipher.authLen;
                    int blockSize = cipher.blockSize;
                    Console.WriteLine("keyLen:" + keyLen);
                    Console.WriteLine("ivLen:" + ivLen);
                    Console.WriteLine("authLen:" + authLen);
                    Console.WriteLine("blockSize:" + blockSize);
                    if( encryptedLen < blockSize || (encryptedLen % blockSize) != 0) {
                        throw new Exception("Invalid Key Format");
                    }
                    byte[] key = new byte[keyLen + ivLen];
                    Array.Fill<byte>(key, 1);
                    if(kdf_name == "bcrypt") {
                        Console.Write("kdf:"); kdf.dump();
                        byte[] salt = kdf.rawData;
                        uint round = kdf.U32;
                        string passphrase = "testtest";
                        Console.Write("salt:"); new ConsumableData(salt).dump();
                        // var sw = new System.Diagnostics.Stopwatch(); // 
                        // sw.Restart();				 // 
                        if(Bcrypt.pbkdf(passphrase, salt, ref key, (int)round) < 0) {
                            throw new Exception("Invalid format@pbkdf");
                        }
                        else {
                            // sw.Stop();	// 
                            // Console.WriteLine($"PBKDF elapsed: {sw.ElapsedMilliseconds} ms"); // 
                            ConsumableData cdkey = new(key);
                            Console.Write("key:");
                            cdkey.dump();
			
                        }
                    }

                    if(data.Remain < authLen || data.Remain - authLen < encryptedLen) {
                        throw new Exception("INVALID format@RemainCheck");
                    }
                    byte[] keyBody = Misc.BlockCopy(key, 0, keyLen);
                    byte[] ivBody = Misc.BlockCopy(key, keyLen, ivLen);
                    Console.Write("keyBody:"); new ConsumableData(keyBody).dump();
                    Console.Write("ivBody:"); new ConsumableData(ivBody).dump();
                    SshCipherCtx cipherCtx = new(cipher, keyBody, ivBody, false);
                    ConsumableData decrypted = new(cipherCtx.Crypt(0, data.Remains, (int)encryptedLen, 0, authLen));
                    Console.Write("Decrypted:");
                    decrypted.dump();
                    data.Consume((int)(encryptedLen + authLen));
                    if(data.Remain != 0) {
                        throw new Exception("INVALID FORMAT of data");
                    }
                    uint check1 = decrypted.U32;
                    uint check2 = decrypted.U32;
                    if(check1 != check2) {
                        throw new Exception("Wrong Pass pharase");
                    }
                    RSAParameters params0 = deserializeKey(decrypted);
                    using (var rsa = new RSACryptoServiceProvider()) {
                        rsa.ImportParameters(params0);

                        byte[] encrypted = new byte[]{0x1C, 0x9C, 0xF4, 0xB3, 0x02, 0x0C, 0x0B, 0x75, 0x86, 0x12, 0x6C, 0x4A, 0xFD, 0xEF, 0x29, 0x78, 0x94, 0x81, 0x9C, 0x9C, 0x77, 0x09, 0xD2, 0x31, 0x8B, 0xA6, 0x53, 0xED, 0x1A, 0xFD, 0xF6, 0x5F, 0xF5, 0xAE, 0xAB, 0x45, 0xBB, 0x6D, 0xA1, 0x47, 0x24, 0x09, 0x93, 0x22, 0x18, 0xC4, 0x5E, 0x02, 0xF6, 0xD4, 0xB1, 0x66, 0xDC, 0x97, 0x27, 0x34, 0x7D, 0xD9, 0x97, 0x71, 0x81, 0xB8, 0xD9, 0xC8, 0xBA, 0x5B, 0xBE, 0x83, 0xBD, 0x37, 0xA3, 0xEB, 0xCC, 0x3D, 0xE2, 0x64, 0x57, 0xAB, 0x37, 0x1F, 0x16, 0xE1, 0x41, 0xB1, 0xC6, 0xA7, 0x63, 0x8A, 0x78, 0xC1, 0x6C, 0x6F, 0x31, 0x16, 0x5B, 0x19, 0x03, 0xE1, 0xDB, 0x1B, 0xCF, 0x4E, 0xA5, 0x11, 0x09, 0x27, 0x42, 0x86, 0xBE, 0xAC, 0x8D, 0x68, 0xF5, 0x91, 0x83, 0x29, 0xE6, 0x9C, 0x9D, 0xAE, 0xAF, 0xD1, 0xAC, 0xBC, 0x0E, 0x9E, 0x6E, 0x4D, 0xDA, 0x8E, 0x0F, 0x69, 0x43, 0x3F, 0xC1, 0xB1, 0x81, 0xAB, 0x67, 0x44, 0x4A, 0xF6, 0x42, 0x6D, 0x78, 0x6E, 0x1A, 0x70, 0x90, 0x35, 0x36, 0x24, 0x73, 0xC7, 0x64, 0xF8, 0xB6, 0x38, 0x38, 0xC4, 0x88, 0xFD, 0x04, 0xC9, 0xE1, 0xF6, 0x94, 0xBC, 0x4A, 0x3F, 0xAD, 0x54, 0x39, 0xC7, 0x00, 0xC2, 0xC2, 0x4F, 0x27, 0xD7, 0x1A, 0xC5, 0xC5, 0x85, 0xCF, 0xD3, 0x63, 0x30, 0x43, 0xF7, 0x11, 0x4A, 0xC2, 0xC8, 0x8E, 0x5D, 0xC6, 0x67, 0xD6, 0x8C, 0x2B, 0x5B, 0x66, 0xD9, 0x28, 0xAF, 0x4F, 0x10, 0xCB, 0x12, 0x3A, 0xD8, 0x92, 0xA1, 0x0D, 0x1A, 0x09, 0x0A, 0xD4, 0x93, 0x58, 0x8C, 0xC6, 0x88, 0x45, 0x21, 0x7A, 0x86, 0x75, 0x55, 0xEA, 0x22, 0xF6, 0x6F, 0x63, 0x2D, 0x97, 0xAF, 0x19, 0x52, 0x1F, 0xDA, 0x07, 0x33, 0xD5, 0x4E, 0x32, 0x80, 0xDD, 0xCB, 0xDD, 0x15, 0xC8, 0xE4, 0xCB, 0x30, 0x32, 0x7B, 0x66, 0x4B, 0x0C, 0x3D, 0xD9, 0x41, 0x23, 0x12, 0x79, 0x69, 0x9A, 0x8A, 0xF1, 0x21, 0xDD, 0x1B, 0x10, 0xEF, 0x71, 0x3B, 0xF0, 0xD5, 0x3E, 0x88, 0x2D, 0x76, 0x76, 0x63, 0x1B, 0x98, 0xAC, 0xDE, 0xCB, 0x81, 0x51, 0x90, 0xAA, 0x1B, 0xB5, 0x35, 0x2A, 0x52, 0x89, 0xDD, 0x70, 0x93, 0x42, 0x3D, 0x52, 0xAF, 0x65, 0x9A, 0x37, 0xE0, 0xFF, 0xDD, 0x83, 0xE0, 0xF0, 0xD4, 0xD1, 0x0B, 0x3F, 0x22, 0xB4, 0xBF, 0xC1, 0xE2, 0xE5, 0x61, 0x8C, 0xB6, 0x3D, 0x97, 0x19, 0xCC, 0x8F, 0xAC, 0x74, 0x40, 0x20, 0xC4, 0x51, 0xCF, 0xCE, 0x2D, 0xB9, 0xA3, 0x44, 0x85, 0x59, 0x46, 0x27, 0xC2, 0x2C, 0x98, 0xE5, 0x86, 0xDD, 0x52, 0xAA, 0x33, 0x84, 0x58, 0x62, 0xE3, 0x41, 0x2E, 0xAD, 0x33, 0xD7, 0xF5, 0x0B, 0x74, 0x26, 0xB2, 0x0B, 0x4E, 0x1C, 0xCA, 0x57, 0xD2, 0xD4, 0x47, 0x88, 0x7E};
                        byte[] decryptedData = rsa.Decrypt(encrypted, RSAEncryptionPadding.Pkcs1);
                        Encoding enc = Encoding.GetEncoding("UTF-8");
                        Console.WriteLine(enc.GetString(decryptedData));
                        
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
