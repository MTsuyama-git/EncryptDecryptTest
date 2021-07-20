using System;
using System.Security.Cryptography;
using System.Reflection;
using System.IO;
using System.Text;

namespace Encrypt
{
    public enum sshkey_types {
	KEY_RSA,
	KEY_DSA,
	KEY_ECDSA,
	KEY_ED25519,
	KEY_RSA_CERT,
	KEY_DSA_CERT,
	KEY_ECDSA_CERT,
	KEY_ED25519_CERT,
	KEY_XMSS,
	KEY_XMSS_CERT,
	KEY_ECDSA_SK,
	KEY_ECDSA_SK_CERT,
	KEY_ED25519_SK,
	KEY_ED25519_SK_CERT,
	KEY_UNSPEC
    };
    public struct KeyType {
	public readonly string name;
	public readonly string shortname;
	public readonly string sigalg;
	public readonly sshkey_types type;
	public readonly int nid;
	public readonly int cert;
	public readonly int sigonly;

	public KeyType(string name, string shortname, string sigalg, sshkey_types type, int nid, int cert, int sigonly)
	{
	    this.name = name;
	    this.shortname = shortname;
	    this.sigalg = sigalg;
	    this.type = type;
	    this.nid = nid;
	    this.cert = cert;
	    this.sigonly = sigonly;
	}
    };
    
    class PointedData
    {

	byte[] data;
	int offset;

	public PointedData(byte[] data) {
	    this.data = data;
	    this.offset = 0;
	}

	public int Size
        {
            get
            {
                return data.Length;
            }
        }

	public int Remain
	{
	    get
	    {
		return data.Length - offset;
	    }
	      
	}
	
	public void Consume(int num) {
	    this.offset += num;
	    if(this.offset > data.Length) {
		this.offset = data.Length;
	    }
	    return;
	}

	public byte this[int idx] {
	    get {
		int trueIdx = offset + idx;
		if(trueIdx >= this.data.Length) {
		    trueIdx = this.data.Length - 1;
		}
		return this.data[trueIdx];
	    }
	}

	public byte[] SubArray(int num) {
	    int tail = offset + num;
	    if(tail > this.data.Length) {
		tail = this.data.Length;
	    }
	    byte[] result = new byte[tail - offset];
	    int typeSize = System.Runtime.InteropServices.Marshal.SizeOf(
		data.GetType().GetElementType());
	    Buffer.BlockCopy(data, offset, result, 0, result.Length * typeSize);
	    return result;
	}
    }


    class Program
    {
	private readonly char[] del = { '\t', ' ' };

	static readonly KeyType[] keytypes = new KeyType[] {
	    new KeyType("ssh-ed25519", "ED25519", null, sshkey_types.KEY_ED25519, 0, 0, 0),
	    new KeyType( "ssh-ed25519-cert-v01@openssh.com", "ED25519-CERT", null,
	      sshkey_types.KEY_ED25519_CERT, 0, 1, 0 ),
	    new KeyType( "sk-ssh-ed25519@openssh.com", "ED25519-SK", null,
	      sshkey_types.KEY_ED25519_SK, 0, 0, 0 ),
	    new KeyType( "sk-ssh-ed25519-cert-v01@openssh.com", "ED25519-SK-CERT", null,
	      sshkey_types.KEY_ED25519_SK_CERT, 0, 1, 0 ),
	    new KeyType( "ssh-xmss@openssh.com", "XMSS", null, sshkey_types.KEY_XMSS, 0, 0, 0 ),
	    new KeyType( "ssh-xmss-cert-v01@openssh.com", "XMSS-CERT", null,
	      sshkey_types.KEY_XMSS_CERT, 0, 1, 0 ),
	    new KeyType( "ssh-rsa", "RSA", null, sshkey_types.KEY_RSA, 0, 0, 0 ),
	    new KeyType( "rsa-sha2-256", "RSA", null, sshkey_types.KEY_RSA, 0, 0, 1 ),
	    new KeyType( "rsa-sha2-512", "RSA", null, sshkey_types.KEY_RSA, 0, 0, 1 ),
	    new KeyType( "ssh-dss", "DSA", null, sshkey_types.KEY_DSA, 0, 0, 0 ),
	    // new KeyType( "ecdsa-sha2-nistp256", "ECDSA", null,
	    //   sshkey_types.KEY_ECDSA, NID_X9_62_prime256v1, 0, 0 ),
	    // new KeyType( "ecdsa-sha2-nistp384", "ECDSA", null,
	    //   sshkey_types.KEY_ECDSA, NID_secp384r1, 0, 0 ),
	    // new KeyType( "ecdsa-sha2-nistp521", "ECDSA", null,
	    //   sshkey_types.KEY_ECDSA, NID_secp521r1, 0, 0 ),
	    // new KeyType( "sk-ecdsa-sha2-nistp256@openssh.com", "ECDSA-SK", null,
	    //   sshkey_types.KEY_ECDSA_SK, NID_X9_62_prime256v1, 0, 0 ),
	    // new KeyType( "webauthn-sk-ecdsa-sha2-nistp256@openssh.com", "ECDSA-SK", null,
	    //   sshkey_types.KEY_ECDSA_SK, NID_X9_62_prime256v1, 0, 1 ),
	    // new KeyType( "ssh-rsa-cert-v01@openssh.com", "RSA-CERT", null,
	    //   sshkey_types.KEY_RSA_CERT, 0, 1, 0 ),
	    // new KeyType( "rsa-sha2-256-cert-v01@openssh.com", "RSA-CERT",
	    //   "rsa-sha2-256", sshkey_types.KEY_RSA_CERT, 0, 1, 1 ),
	    // new KeyType( "rsa-sha2-512-cert-v01@openssh.com", "RSA-CERT",
	    //   "rsa-sha2-512", sshkey_types.KEY_RSA_CERT, 0, 1, 1 ),
	    // new KeyType( "ssh-dss-cert-v01@openssh.com", "DSA-CERT", null,
	    //   sshkey_types.KEY_DSA_CERT, 0, 1, 0 ),
	    // new KeyType( "ecdsa-sha2-nistp256-cert-v01@openssh.com", "ECDSA-CERT", null,
	    //   sshkey_types.KEY_ECDSA_CERT, NID_X9_62_prime256v1, 1, 0 ),
	    // new KeyType( "ecdsa-sha2-nistp384-cert-v01@openssh.com", "ECDSA-CERT", null,
	    //   sshkey_types.KEY_ECDSA_CERT, NID_secp384r1, 1, 0 ),
	    // new KeyType( "ecdsa-sha2-nistp521-cert-v01@openssh.com", "ECDSA-CERT", null,
	    //   sshkey_types.KEY_ECDSA_CERT, NID_secp521r1, 1, 0 ),
	    // new KeyType( "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", "ECDSA-SK-CERT", null,
	    //   sshkey_types.KEY_ECDSA_SK_CERT, NID_X9_62_prime256v1, 1, 0 ),
	    new KeyType( null, null, null, sshkey_types.KEY_UNSPEC, -1, 0, 0 )
	};

	private static sshkey_types key_type_from_name(string name)
	{
	    foreach(var keytype in keytypes) {
		if(keytype.name == name) {
		    return keytype.type;
		}
	    }
	    return sshkey_types.KEY_UNSPEC;
	}

	private static string getString(PointedData data)
	{
	    Encoding enc = Encoding.GetEncoding("UTF-8");
	    int length = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | (data[3]);
	    data.Consume(4);
	    string result = enc.GetString(data.SubArray(length));
	    data.Consume(length);
	    return result;
	    
	}

	private static byte[] readBinary(PointedData data, bool trim=true)
	{
	    Encoding enc = Encoding.GetEncoding("UTF-8");
	    int length = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | (data[3]);
	    data.Consume(4);
	    if(trim) {
		while(data[0] == 0x0 && length > 0) {
		    length -= 1;
		    data.Consume(1);
		}
	    }
	    return data.SubArray(length);
	    
	}

	private static void dump(byte[] b)
	{
	    foreach(byte e in b) {
		Console.Write(string.Format("{0,2:X2}", e)+ " ");
	    }
	    Console.WriteLine();
	}

	public void readSSHPublicKey(string contents)
	{
	    var items = contents.Split(del, StringSplitOptions.RemoveEmptyEntries);
	    sshkey_types keytype = key_type_from_name(items[0]);
	    PointedData data = 	new(Convert.FromBase64String(items[1]));
	    string name = getString(data);
	    sshkey_types keytype2 = key_type_from_name(name);
	    if(keytype != keytype2) {
		Console.Error.WriteLine("Invalid key");
		Environment.Exit(1);
	    }
	    byte[] rsa_e = readBinary(data); //exponent
	    byte[] rsa_n = readBinary(data); // modulus
	    dump(rsa_e);
	    dump(rsa_n);
	    using (var rsa = new RSACryptoServiceProvider())
	    {
		rsa.ImportParameters(new RSAParameters {
			Exponent = rsa_e,
			Modulus  = rsa_n
		    });
		var plainBytes = Encoding.UTF8.GetBytes("testtest");
		var cipherBytes = rsa.Encrypt(plainBytes, RSAEncryptionPadding.Pkcs1);
	    }
	    // RSA_set0_key(k->rsa, rsa_n_v, rsa_e_v, NULL)
	    
	}

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
            // string contents = System.IO.File.ReadAllText(keyPath);
            // readRSAPublicKey(contents);
	    string line;
	    using (StreamReader sr = new (keyPath)){
		while ((line = sr.ReadLine()) != null)
		{
		    var c = line.Substring(0, 1);
		    if(c == "#" || c == "\n" || c=="\0" )
			continue;
		    if(line.Substring(0, 10) == "-----BEGIN" || String.Compare(line, "SSH PRIVATE KEY FILE") == 0) {
			throw new Exception("Invalid format error");
		    }
		    var items = line.Split(del, StringSplitOptions.RemoveEmptyEntries);
		    if(items.Length >= 3) {
			this.readSSHPublicKey(line);
		    }
		}
	    }
        }

        static void Main(string[] args)
        {
            _ = new Program(args);
            // Console.WriteLine("Hello World!");
        }
    }
}
