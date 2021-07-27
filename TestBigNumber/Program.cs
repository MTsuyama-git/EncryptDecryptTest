using System;
using Utility;
namespace TestBigNumber
{
    class Program
    {
        static void Main(string[] args)
            {
                BNssl p = new(
                    BNPrivate.Constants.p_data
                );
                BNssl q = new (
                    BNPrivate.Constants.q_data
                );
	    
                BNssl dmp1 = new(
                    BNPrivate.Constants.dmp1_data
                );

                BNssl dmq1 = new(
                    BNPrivate.Constants.dmq1_data

                );
                
                p.Print();
                BNssl p1 = BNssl.Sub(p, BNssl.ValueOne);
                p1.Print();
                q.Print();
                BNssl q1 = BNssl.Sub(q, BNssl.ValueOne);
                q1.Print();
	    
                // dmp1.Print();
                // dmq1.Print();
            }
    }
}
