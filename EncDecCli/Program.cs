// See https://aka.ms/new-console-template for more information
using Utility;
using System.Security.Cryptography;
using System.Text;
Arguments arguments = new(args, new List<string>{
    "command",
    "input",
},
new List<string>
{
    "output",
    "path_to_key"
});
Mode_E command = Enum.Parse<Mode_E>(arguments["command"]);
string userprofile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
string input = arguments["input"];
string? dest = null;
string? keyPath = null;
if (command == Mode_E.encrypt)
{
    // encrypt
    dest = (arguments["output"].isNone) ? input + ".aes" : arguments["output"];
    if (!dest.EndsWith(".aes"))
    {
        dest += ".aes";
    }
    keyPath = (arguments["path_to_key"].isNone) ? System.IO.Path.Combine(userprofile, ".ssh", "id_rsa.pub") : arguments["path_to_key"];
    RSACryptoServiceProvider? provider = SSHKeyManager.ParseSSHPublicPrivateKeyForEncrypt(keyPath, passwordCb);
    if (provider == null)
    {
        throw new Exception("Invalid type key");
    }
    using (FileStream inputStream = File.Open(input, FileMode.Open))
    {
        using (FileStream outputStream = File.Open(dest, FileMode.Create))
        {
            using (BinaryWriter bw = new BinaryWriter(outputStream))
            {
                Span<byte> readBuffer = new Span<byte>(new byte[8192]);

                byte[] passKey = PassphraseGenerator.Generate(128);
                var cipherBytes = provider.Encrypt(passKey, RSAEncryptionPadding.Pkcs1);
                bw.Write(ByteConverter.convertToByte((UInt16)(cipherBytes.Length & 0xFFFF), Endian.LITTLE));
                bw.Write(cipherBytes);
                // generate salt
                byte[] magic = Encoding.UTF8.GetBytes("Salted__"); // magic
                byte[] salt = PassphraseGenerator.Generate(8); // PKCS5_SALT_LEN = 8
                bw.Write(magic);
                bw.Write(salt);
                // Console.Write("magic:"); new ConsumableData(magic).dump();
                // Console.Write("salt:"); new ConsumableData(salt).dump();
                Rfc2898DeriveBytes b = new(passKey, salt, 10000, HashAlgorithmName.SHA256);
                byte[] keyIv = b.GetBytes(48);
                byte[] key = Misc.BlockCopy(keyIv, 0, 32);
                byte[] iv = Misc.BlockCopy(keyIv, 32, 16);
                // Console.Write("key:"); new ConsumableData(key).dump();
                // Console.Write("iv:"); new ConsumableData(iv).dump();
                Aes encAlg = Aes.Create();
                encAlg.Key = key;
                encAlg.IV = iv;
                int readLen = 0;

                using (CryptoStream encrypt = new(outputStream, encAlg.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    while ((readLen = inputStream.Read(readBuffer)) > 0)
                    {
                        encrypt.Write(readBuffer.ToArray(), 0, readLen);
                    }
                    encrypt.FlushFinalBlock();
                    encrypt.Close();
                }
            }
        }
    }
}
else
{
    //decrypt
    if (!input.EndsWith("aes"))
    {
        throw new Exception("the file names " + input + " is not encrypted file");
    }
    dest = (arguments["output"].isNone) ? input.Replace(".aes", "") : arguments["output"];
    keyPath = (arguments["path_to_key"].isNone) ? System.IO.Path.Combine(userprofile, ".ssh", "id_rsa") : arguments["path_to_key"];
    RSA rsa = SSHKeyManager.ReadSSHPrivateKey(keyPath, passwordCb);
    using (FileStream inputStream = File.Open(input, FileMode.Open))
    {
        using (FileStream outputStream = File.Open(dest, FileMode.Create))
        {
            using (BinaryReader br = new(inputStream))
            {
                Span<byte> readBuffer = new Span<byte>(new byte[8192]);
                byte[] headerSizeB = new byte[2];
                br.Read(headerSizeB, 0, headerSizeB.Length);
                UInt16 headerSize = ByteConverter.convertToU16(headerSizeB, Endian.LITTLE);
                Console.WriteLine("headerSize:{0}", headerSize);
                byte[] cipherBytes = new byte[headerSize];
                br.Read(cipherBytes, 0, cipherBytes.Length);
                byte[] decrypted = rsa.Decrypt(cipherBytes, RSAEncryptionPadding.Pkcs1);

                byte[] magic = new byte[8];
                byte[] salt = new byte[8];
                br.Read(magic, 0, magic.Length);
                br.Read(salt, 0, salt.Length);
                // Console.Write("magic:"); new ConsumableData(magic).dump();
                // Console.Write("salt:"); new ConsumableData(salt).dump();
                var b = new Rfc2898DeriveBytes(decrypted, salt, 10000, HashAlgorithmName.SHA256);
                // Console.WriteLine("hashAlgorithm:{0}", b.HashAlgorithm);
                byte[] keyIv = b.GetBytes(48);
                byte[] key = Misc.BlockCopy(keyIv, 0, 32);
                byte[] iv = Misc.BlockCopy(keyIv, 32, 16);
                // Console.Write("keyIV:"); new ConsumableData(keyIv).dump();
                // Console.Write("key:"); new ConsumableData(key).dump();
                // Console.Write("iv:"); new ConsumableData(iv).dump();
                Aes encAlg = Aes.Create();
                encAlg.Key = key;
                encAlg.IV = iv;
                int readLen = 0;
                using (CryptoStream decrypt = new(outputStream, encAlg.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    while ((readLen = inputStream.Read(readBuffer)) > 0)
                    {
                        decrypt.Write(readBuffer.ToArray(), 0, readLen);
                    }
                    decrypt.FlushFinalBlock();
                    decrypt.Close();
                }
            }
        }
    }
}

string passwordCb()
{
    ConsoleKeyInfo key;
    String result = "";
    Console.Write("Input Passphrase:");
    do
    {
        key = Console.ReadKey(true);

        // Ignore any key out of range.
        if (key.Key != ConsoleKey.Enter)
        {
            // Append the character to the password.
            result += key.KeyChar;
            continue;
        }
        break;
        // Exit if Enter key is pressed.
    } while (true);
    return result;
}

//Console.WriteLine("Hello, World!");
Console.WriteLine("input: {0}", input);
Console.WriteLine("output: {0}", dest);
Console.WriteLine("key: {0}", keyPath);



enum Mode_E
{
    encrypt,
    decrypt,
}

