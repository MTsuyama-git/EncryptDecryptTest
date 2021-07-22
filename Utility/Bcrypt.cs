using System;
using System.Text;

namespace Utility
{
    class Bcrypt
    {
        static readonly int SHA512_DIGEST_LENGTH = 64;
        static readonly int BCRYPT_WORDS = 8;
        static readonly int BCRYPT_HASHSIZE = BCRYPT_WORDS * 4;

        static byte[] hash(byte[] salt)
        {
            Blowfish state = new ();
            string ciphertext = "OxychromaticBlowfishSwatDynamite";
            UInt32[] cdata = new UInt32[BCRYPT_WORDS];
            byte[] result = new byte[salt.Length];
            UInt16 j;
            int shalen = SHA512_DIGEST_LENGTH;

            state.expandstate(salt, result);
            for(int i = 0; i < 64; ++i) {
                state.expandstate(salt);
                state.expandstate(result);
            }
            
            j = 0;

            for(int i = 0; i < BCRYPT_WORDS; ++i) 
                cdata[i] = Blowfish.stream2word(ciphertext, ref j);
            int sizeofCdata = System.Runtime.InteropServices.Marshal.SizeOf(
		    cdata.GetType().GetElementType())*cdata.Length;
            for(int i = 0; i < 64; ++i)
                state.enc(cdata, (UInt16)(sizeofCdata/sizeof(UInt64)));
            for(int i = 0; i < BCRYPT_WORDS; ++i) {
                result[4 * i + 3] = (byte)((cdata[i] >> 24) & 0xFF);
                result[4 * i + 2] = (byte)((cdata[i] >> 16) & 0xFF);
                result[4 * i + 1] = (byte)((cdata[i] >> 8) & 0xFF);
                result[4 * i + 0] = (byte)((cdata[i] >> 0) & 0xFF);
            }
            
            return result;
        }


        static int pbkdf(string password, byte[] salt, out byte[] key, int rounds)
        {
            byte[]  sha2salt  = new byte[SHA512_DIGEST_LENGTH];
            byte[]  output    = new byte[BCRYPT_HASHSIZE];
            byte[]  tmpoutput = new byte[BCRYPT_HASHSIZE];
            byte[]  countsalt = new byte[salt.Length + 4];
            int amt, stride;
            int count;
            int origkeylen = key.Length;

            Array.Fill<byte>(countsalt, 1);

            if(rounds < 1)
                throw new Exception("Rounds must be greater than 0.");
            if(password.Length == 0 || salt.Length == 0 || key.Length == 0 || key.Length > Math.Pow(output.Length, 2.0) || salt.Length > (1 << 20))
                throw new Exception("Invalid parameters.");
            stride = (key.Length + output.Length - 1) / output.Length;
            amt = (key.Length + stride - 1) / stride;
            int typeSize = System.Runtime.InteropServices.Marshal.SizeOf(salt.GetType().GetElementType());
            Buffer.BlockCopy(salt, 0, countsalt, 0, typeSize * salt.Length);
            
            byte[]  sha2pass  = hash_sha512(password);

        }
    }
}