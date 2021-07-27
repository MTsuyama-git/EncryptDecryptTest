using System;
using Utility;
namespace TestBigNumber
{
    class Program
    {
	// static void divShort(in UInt16 a, in UInt16 b, out UInt16 dv, ref UInt16 rem) {
	//     const ushort halfshortsize = sizeof(ushort)/2 * 8;
	//     const ushort halfshortmask =  (((ushort) 1 << halfshortsize) - 1);
	//     Console.WriteLine("{0:X}", halfshortmask);
	//     ushort al = (ushort)(a & halfshortmask);
	//     ushort bl = (ushort)(b & halfshortmask);
	//     ushort ah = (ushort)((a >> halfshortsize) & halfshortmask);
	//     ushort bh = (ushort)((b >> halfshortsize) & halfshortmask);

	//     Console.WriteLine("al:{0:X}\nbl:{1:X}\nah:{2:X}\nbh:{3:X}", al, bl, ah, bh);

	//     ushort dvh = (ushort)((bh != 0) ? ah / bh : 0);
	//     ushort dvl = (ushort)((bl != 0) ? al / bl : dvh);
	//     ushort rh = (ushort)((bh != 0) ? ah % bh : ah);
	//     ushort rl = (ushort)((bl != 0) ? al % bl : al);

	//     Console.WriteLine("{0}, {1} , {2}, {3}", dvh,dvl,rh,rl);
	//     if(bh == 0) {
	// 	dvh += (ushort)(rh / bl);
	// 	rh %= bl;
			
	//     }
	//     while(dvh > dvl) {
	// 	if(rh > 0) {
	// 	    rh -= 1;
	// 	}
	// 	else {
	// 	    dvh -= 1;
	// 	    rh += (ushort)(bh - 1);
	// 	}
	// 	rl += ((1 << halfshortsize) - 1);
	// 	dvl += (ushort)((bl > 0) ? (rl / bl) : 0);
	// 	rl %= (ushort)((bl > 0) ? bl : 1);
	//     }
	//     while((dvh < dvl)) {
	// 	dvl += 1;
	// 	rl += bl;
	//     }
	//     Console.WriteLine("{0}, {1} , {2}, {3}", dvh,dvl,rh,rl);

	//     if(dvh != dvl) {
	// 	throw new Exception("wrong result");
	//     }
	//     dv = (ushort)((dvh << halfshortsize) |  dvl);
	//     rem = (ushort)((rh << halfshortsize) |  rl);

	//     return;
	// }

        static void Main(string[] args)
	{
	    // BNssl p = new(
	    // 	BNPrivate.Constants.p_data
	    // );
	    // BNssl q = new (
	    // 	BNPrivate.Constants.q_data
	    // );
	    
	    // BNssl d = new (
	    // 	BNPrivate.Constants.d_data
	    // );

	    Org.BouncyCastle.Math.BigInteger d = new (1, 
		BNPrivate.Constants.d_data
	    );

	    Org.BouncyCastle.Math.BigInteger p = new (1, 
		BNPrivate.Constants.p_data
	    );

	    Org.BouncyCastle.Math.BigInteger q = new (1, 
		BNPrivate.Constants.q_data
	    );

            q = q.Subtract(new Org.BouncyCastle.Math.BigInteger("1"));
            p = p.Subtract(new Org.BouncyCastle.Math.BigInteger("1"));

            var dp1 = d.Mod(p);
            var dq1 = d.Mod(q);

	    var pdata = Misc.BlockCopy(BNPrivate.Constants.p_data);
	    var qdata = Misc.BlockCopy(BNPrivate.Constants.q_data);
	    var ddata = Misc.BlockCopy(BNPrivate.Constants.d_data);
	    Array.Reverse(pdata);
	    Array.Reverse(qdata);
	    Array.Reverse(ddata);
	    System.Numerics.BigInteger bid = new(
		ddata
	    );
	    System.Numerics.BigInteger bip = new(
		pdata
	    );
	    bip -= 1;
	    // Console.WriteLine(bip.ToString("X"));
	    // Console.WriteLine(p.ToString(16));

	    System.Numerics.BigInteger biq = new(
		qdata
	    );
	    biq -= 1;

	    Console.WriteLine("======");
	    Console.WriteLine(d);
	    Console.WriteLine(p);
	    Console.WriteLine(dp1.ToString(16));
	    Console.WriteLine("======");
	    Console.WriteLine(bid);
	    Console.WriteLine(bip);
	    Console.WriteLine((bid % bip).ToString("X"));
	    Console.WriteLine("======");
	    Console.WriteLine(bid);
	    Console.WriteLine(biq);
	    Console.WriteLine((bid % biq).ToString("X"));
	    Console.WriteLine("======");
	    Console.WriteLine(d);
	    Console.WriteLine(q);
	    Console.WriteLine(dq1.ToString(16));
	    Console.WriteLine("======");


	    // Console.WriteLine(biq.ToString("X"));
	    // Console.WriteLine(q.ToString(16));

	    // Console.WriteLine(bid < 0);
	    // Console.WriteLine(bip < 0);
	    // Console.WriteLine(biq < 0);

	    var bidmp = bid % bip;
	    var bidmq = bid % biq;
	    // Console.WriteLine(dp1);
	    // Console.WriteLine(bidmp.ToString("X"));
	    // Console.WriteLine(dq1);
	    // Console.WriteLine(bidmq.ToString("X"));
	    
	    var bidmpb = bidmp.ToByteArray();
	    var bidmqb = bidmq.ToByteArray();

	    Array.Reverse(bidmpb);
	    Array.Reverse(bidmqb);

	    new ConsumableData(bidmpb).dump();
	    new ConsumableData(bidmqb).dump();



	    // var l = BNssl.ValueZero - q128;
	    // l.Print();
	    // l += q128;
	    // l.Print();

	    // ulong num1 = 0xFFFF_0000_FFFF;
	    // ulong num2 = 0x00FE;
	    // Console.WriteLine("{0:X} / {1:X} = {2:X} ... {3:X}", num1, num2, num1/num2, num1%num2);
	    // ushort[] bnum1 = {0xFFFF, 0x0000, 0xFFFF};
	    // int bnum1Top = 3;
	    // ushort[] bnum2 = {0x00FE};
	    // int bnum2Top = 1;

	    // UInt16 dv = 0, rem = 0;
	    
	    // for(int i = bnum1Top - 1; i >= 0; --i) {
	    // 	ushort n0 = bnum1[i];
	    // 	ushort d0 = bnum2[0];
		
	    // 	divShort(n0, d0, out dv, ref rem);
	    // 	Console.WriteLine("{0:X} / {1:X} = {2:X} ... {3:X}", n0, d0, n0/d0, n0%d0);
	    // 	Console.WriteLine("{0:X} / {1:X} = {2:X} ... {3:X}", bnum1[i], bnum2[0], dv, rem);
	    // }
	}
    }
}
