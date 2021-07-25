using System;

namespace Utility {
    public class BNsslCtx {
        public BNsslCtx() {
            // todo
        }

        public BNssl get() {
            return new BNssl();
        }
        
        public void end() {
        }
    }

    public class BNsslPair {
        public BNssl div;
        public BNssl rem;
        public BNsslPair(in BNssl div, in BNssl rem) {
            this.div = div;
            this.rem = rem;
        }
    }


    public class BNssl {
        ulong[] d;
        int top;
        int dmax;
        int neg;
        int flags;

        private static readonly int MALLOCED = 0x01;
        private static readonly int STATIC_DATA = 0x02;
        private static readonly int CONSTTIME = 0x04;
        private static readonly int BYTES = 8;
        private static readonly int BITS = 128;
        private static readonly int BITS2 = 64;
        private static readonly int BITS4 = 32;
        private static readonly int INT_MAX = 2147483647;
        private static readonly ulong MASK2 = 0xffffffffffffffffL;

        
        public BNssl() {
            flags = MALLOCED;
            top = 0;
            neg = 0;
            dmax = 0;
            d = null;
            check_top();
        }

        public BNssl(in byte[] arr) {
            int i, m;
            flags = MALLOCED;
            top = 0;
            neg = 0;
            dmax = 0;
            d = null;
            check_top();
            int arr_offset = 0;
            ulong l = 0;
            int n = arr.Length;
            if(n == 0) {
                top = 0;
                return;
            }
            i = (n - 1) / (BYTES) + 1;
            m = (n - 1) % (BYTES);
            wexpand(i);
            top = i;
            neg = 0;
            while((n--) > 0) {
                l = (l << 8) | arr[arr_offset++];
                if(m--  == 0) {
                    d[--i] = l;
                    l = 0;
                    m = BYTES - 1;
                }
            }
            correct_top();
        }


        public static ulong add_words(ref ulong[] r, in ulong[] a, in ulong[] b, int n)
            {
                ulong c, l, t;
                int a_offset, b_offset, r_offset;
                a_offset = b_offset = r_offset = 0;
                if(!(n >= 0)) {
                    throw new Exception("n is zero");
                }
                c = 0;

                while ((n & ~3) != 0)
                {
                    t = a[a_offset + 0];
                    t = (t+c)&MASK2;
                    c = (ulong)((t < c) ? 1 : 0);
                    l = (t + b[b_offset + 0])&MASK2;
                    c += (ulong)((l < t) ? 1 : 0);
                    r[r_offset + 0] = l;
                    t = a[a_offset + 1];
                    t = (t + c)&MASK2;
                    c = (ulong)((t < c) ? 1 : 0);
                    l = (t + b[b_offset + 1])&MASK2;
                    c += (ulong)((l < t) ? 1 : 0);
                    r[r_offset + 1] = l;
                    t = a[a_offset + 2];
                    t = (t + c)& MASK2;
                    c = (ulong)((t < c) ? 1 : 0);
                    l = (t + b[b_offset + 2]) & MASK2;
                    c += (ulong)((l < t) ? 1 : 0);
                    r[r_offset + 2] = l;
                    t = a[a_offset + 3];
                    t = (t +c) & MASK2;
                    c = (ulong)((t < c) ? 1 : 0);
                    l = (t + b[b_offset + 3]) & MASK2;
                    c += (ulong)((l < t ) ? 1 : 0);
                    r[r_offset + 3] = l;
                    a_offset++;
                    b_offset++;
                    r_offset++;
                }
                return c;
            }

        public static int ucmp(in BNssl a, in BNssl b) {
            int i;
            ulong t1, t2;
            ulong[] ap, bp;

            a.check_top();
            b.check_top();
            i = a.top - b.top;
            if(i != 0) return i;
            ap = a.d;
            bp = b.d;
            for(i = a.top - 1; i >= 0; --i)
            {
                t1 = ap[i];
                t2 = bp[i];
                if(t1 != t2)
                {
                    return ((t1 > t2) ? 1 : -1);
                }
            }
            return 0;
        }

        public static BNssl add(BNssl a, BNssl b) {
            BNssl r = new(); BNssl tmp;
            int a_neg = a.neg;

            a.check_top();
            b.check_top();

            if((a_neg ^ b.neg) != 0)
            {
                if(a_neg != 0)
                {
                    tmp = a;
                    a = b;
                    b = tmp;
                }
                if(ucmp(in a, in b) < 0) {
                    r = usub(b, a);
                    r.neg = 1;
                }

                else {
                    r = usub(a, b);
                    r.neg = 0;
                }
                return r;
            }
            r = uadd(a, b);
            r.neg = a_neg;
            r.check_top();
            return r;
        }
        
        public static BNssl uadd(BNssl a, BNssl b) {
            BNssl r = new();
            BNssl tmp;
            int max, min, dif;
            ulong t1, t2, carry;
            ulong[] ap, bp, rp;
            int i;
            int rp_offset = 0;
            int ap_offset = 0;
            int bp_offset = 0;
            a.check_top();
            b.check_top();
            
            if(a.top < b.top)
            {
                tmp = a;
                a = b;
                b = tmp;
            }

            max = a.top;
            min = b.top;
            dif = max - min;
            
            r.wexpand(max + 1);
            r.top = max;

            ap = a.d;
            bp = b.d;
            rp = r.d;
            
            carry = add_words(ref rp, in ap, in bp, min);
            rp_offset += min;
            ap_offset += min;
            bp_offset += min;

            if(carry!=0) {
                while(dif != 0) {
                    dif--;
                    t1 = ap[ap_offset++];
                    t2 = (t1 + 1) & MASK2;
                    rp[rp_offset++] = t2;
                    if(t2 != 0)
                    {
                        carry = 0;
                        break;
                    }
                }

                if(carry != 0)
                {
                    rp[rp_offset] = 1;
                    r.top++;
                }

            }
            if(dif != 0 && (rp != ap || rp_offset != ap_offset)) {
                while((dif--) != 0) {
                    rp[rp_offset++] = ap[ap_offset++];
                }
            }
            r.neg = 0;
            r.check_top();
                        
            return r;

        }



        public static BNssl usub(BNssl a, BNssl b) {
            BNssl r = new();
            int max, min, dif;
            ulong t1, t2;
            ulong[] ap, bp, rp;
            int i, carry;
            int rp_offset = 0;
            int ap_offset = 0;
            int bp_offset = 0;
            a.check_top();
            b.check_top();
            max = a.top;
            min = b.top;
            dif = max - min;
                

            if(dif < 0)
            {

                throw new Exception("BN usub error");
            }
            r.wexpand(max);
            ap = a.d;
            bp = b.d;
            rp = r.d;
            
            carry = 0;
            for (i = min; i != 0; --i)
            {
                t1 = ap[ap_offset++];
                t2 = bp[bp_offset++];
                if(carry != 0)
                {
                    carry=((t1 <= t2) ? 1  : 0);
                    t1 = (t1 - t2 - 1)&MASK2;

                }
                else {
                    carry=((t1 < t2) ? 1  : 0);
                    t1 = (t1 - t2)&MASK2;
                }
                rp[rp_offset++] = t1 & MASK2;
            }

            if(carry != 0)
            {
                if(dif==0)
                    return r;
                while(dif>0){
                    dif--;
                    t1 = ap[ap_offset++];
                    t2 = (t1-1)&MASK2;
                    rp[rp_offset++] = t2;
                    if(t1 != 0)
                        break;
                }
            }
            
            if(rp != ap || rp_offset != ap_offset)
            {
                for(;;) {
                    if((dif--) == 0) break;
                    rp[rp_offset] = ap[ap_offset];
                    if((dif--) == 0) break;
                    rp[rp_offset + 1] = ap[ap_offset+1];
                    if((dif--) == 0) break;
                    rp[rp_offset + 2] = ap[ap_offset+2];
                    if((dif--) == 0) break;
                    rp[rp_offset + 3] = ap[ap_offset+3];
                    rp_offset += 4;
                    ap_offset += 4;

                }
            }
            r.top = max;
            r.neg = 0;
            r.correct_top();
            return r;
        }


        public static int cmp(in BNssl a, in BNssl b)
            {
                int i;
                int gt, lt;
                ulong t1, t2;

                if(a == null || b == null) {
                    if(a != null)
                        return -1;
                    else if(b != null)
                        return 1;
                    return 0;
                }

                a.check_top();
                b.check_top();

                if(a.neg != b.neg)
                {
                    if(a.neg != 0)
                        return -1;
                    else {
                        return 1;
                    }
                }

                if (a.neg == 0)
                {
                    gt = 1; lt = -1;
                }
                else {
                    gt = -1; lt = 1;
                }

                if(a.top > b.top) return gt;
                if(b.top > a.top) return lt;

                for(i = a.top - 1; i >= 0; --i) {
                    t1 = a.d[i];
                    t2 = b.d[i];

                    if(t1 > t2) return gt;
                    if(t1 < t2) return lt;
                }

                return 0;
            }

        public static BNssl sub(BNssl a, BNssl b)
            {
             
                BNssl ret = new();
                BNssl tmp = new();
                int max;
                int _add = 0;
                int _neg = 0;
                a.check_top();
                b.check_top();
                if(a.neg != 0)
                {
                    if(b.neg != 0)
                    {
                        tmp = a;
                        a = b;
                        b = tmp;
                    }
                    else {
                        _add = 1; _neg = 1;
                    }
                }
                else {
                    if(b.neg != 0) {
                        _add = 1; _neg = 0;
                    }
                }

                if(_add != 0)
                {
                    ret = uadd(a, b);
                    ret.neg = _neg;
                }
                

                max = (a.top > b.top)? a.top : b.top;

                ret.wexpand(max);
                if(ucmp(a, b) < 0)
                {
                    ret = usub(b, a);
                    ret.neg = 1;
                }
                else {
                    ret = usub(a, b);
                    ret.neg = 1;
                }

                ret.check_top();
                return ret;
            }

        public void print() {
            int i, j, v, z=0;
            string Hex="0123456789ABCDEF";
            for(i = top - 1; i >= 0; --i)
            {
                for(j = BITS2 - 4; j >= 0; j-= 4)
                {
                    v = (((int)(d[i]>>(int)j))&0x0f);
                    if(z != 0 || (v != 0))
                    {
                        Console.Write(Hex.Substring(v, 1));
                    }
                }
            }
            Console.WriteLine();
        }

        public static BNssl value_one() {
            BNssl a = new();
            a.set_word(1);

            return a;
        }

        public BNsslPair div(in BNssl num, in BNssl divisor, ref BNsslCtx ctx) {
            BNssl dv = new();
            BNssl rm = new();
            int norm_shift, i, loop;
            BNssl tmp, wnum, snum, sdiv, res;
            ulong[] resp, wnump;
            ulong d0, d1;
            int num_n, div_n;
            int no_branch = 0;

            if(num.top > 0 && num.d[num.top - 1] == 0) {
                throw new Exception("Divisor not initialized");
            }
            
            num.check_top();

            if(((num.flags & CONSTTIME) != 0) || ((divisor.flags & CONSTTIME) != 0))
            {
                no_branch = 1;
            }

            dv.check_top();
            rm.check_top();

            divisor.check_top();

            if(divisor.is_zero) {
                throw new Exception("divisor is zero");
            }
            
            if(no_branch == 0 && ucmp(num, divisor) < 0)
            {
                rm.copy(num);
                dv.set_word(0);
                return new BNsslPair(dv, rm);
            }
            
            ctx = new BNsslCtx();
            tmp=ctx.get();
            snum=ctx.get();
            sdiv=ctx.get();
            if(sdiv == null || dv == null || tmp == null | snum == null) {
                throw new Exception("null.");
            }
            norm_shift = (BITS2 - ((divisor.num_bits) % BITS2));
            sdiv.lshift(divisor, norm_shift);
            sdiv.neg = 0;
            snum.lshift(num, norm_shift);
            snum.neg = 0;
            
            if(no_branch!=0)
            {
                if(snum.top <= sdiv.top + 1)
                {
                    snum.wexpand(sdiv.top + 2);
                    for(i = snum.top; i < sdiv.top + 2; ++i) snum.d[i] = 0;
                    snum.top = sdiv.top + 2;
                }
            }
            else {
                snum.wexpand(snum.top + 1);
                snum.d[snum.top] = 0;
                snum.top++;
            }

            div_n = sdiv.top;
            num_n = snum.top;
            loop = num_n - div_n;
            wnum = new();
            wnum.neg = 0;
            wnum.top = div_n;
            wnum.d = new ulong[snum.d.Length - loop];
            wnum.dmax = snum.dmax - loop;
            
            d0 = sdiv.d[div_n-1];
            d1 = (div_n == 1) ? 0 : sdiv.d[div_n - 2];

            wnump = snum.d;
            int wnump_offset = num_n - 1;
            Misc.BlockCopy(ref wnum.d, in snum.d, in loop);
            dv.neg = (num.neg^divisor.neg);
            dv.wexpand(loop+1);
            dv.top = loop-no_branch;
            resp = snum.d;
            int resp_offset = loop - 1;


            tmp.wexpand(div_n+1);
            if(no_branch == 0)
            {
                if(ucmp(wnum, sdiv) >= 0) {
                    wnum.clear_top2max();
                    sub_words(wnum.d, wnum.d, sdiv.d, div_n);
                    resp[resp_offset] = 1;
                    
                }
                else {
                    dv.top--;
                }
            }
            if(dv.top == 0)
                dv.neg = 0;
            else
                resp_offset--;

            for(i = 0; i < loop-1; ++i, wnump_offset--, resp_offset--)
            {
                ulong q, l0;
                ulong n0, n1, rem = 0;
                n0 = wnump[wnump_offset + 0];
                n1 = wnump[wnump_offset - 1];
                if(n0 == d0)
                    q = MASK2;
                else {
                    ulong t2;

                    q = (ulong)(((((ulong)n0) << BITS2) | n1)/d0);
                    rem = (n1-q*d0)&MASK2;
                    t2 = (ulong)d1*q;
                    for(;;)
                    {
                        if(t2 <= ((((ulong)rem) << BITS2) | wnump[wnump_offset-2]))
                            break;
                        q--;
                        rem += d0;
                        if(rem < d0) break;
                        t2 -= d1;
                    }

                }
                l0=mul_words(tmp.d, sdiv.d, div_n, q);
                tmp.d[div_n] = 0;
                wnump_offset --;
                if(sub_words(wnum.d, wnum.d, tmp.d, div_n+1) != 0) {
                    q--;
                    if (add_words(ref wnum.d, in wnum.d, in sdiv.d, div_n) != 0) {
                        wnump_offset ++;
                    }
                }
                resp[resp_offset] = q;
            }
            snum.correct_top();
            int neg = num.neg;
            rm.rshift(snum, norm_shift);
            if(!rm.is_zero) {
                rm.neg = neg;
            }
            rm.check_top();
            if(no_branch!=0)
                dv.correct_top();
            ctx.end();
            return new BNsslPair(dv, rm);
        }

        public ulong mul_words(ulong[] a, ulong[] b, int div_n, ulong q) {
            return 0;
        }

        void clear_top2max() {
            
        }

        public static int sub_words(ulong[] a, ulong[] b, ulong[] c, int n) {
            return 0;
        }


        public void rshift(BNssl num, int shift) {
        }

        public void lshift(BNssl num, int shift) {
        }


        public BNssl copy(BNssl b)
            {
                int i ;
                ulong[] A;
                ulong[] B;
                int a_offset, b_offset;
                a_offset = b_offset = 0;

                b.check_top();

                if(this==b) return this;
                this.wexpand(b.top);
                A = this.d;
                B = b.d;
                for(i = (b.top>>2); i > 0; i--, a_offset+=4, b_offset+=4) {
                    ulong a0, a1, a2, a3;
                    a0 = B[b_offset + 0];
                    a1 = B[b_offset + 1];
                    a2 = B[b_offset + 2];
                    a3 = B[b_offset + 3];
                    A[a_offset + 0] = a0;
                    A[a_offset + 1] = a1;
                    A[a_offset + 2] = a2;
                    A[a_offset + 3] = a3;
                }

                switch(b.top&3) {
                case 3:
                    A[a_offset + 2] = B[b_offset+2];
                    A[a_offset + 1] = B[b_offset+1];
                    A[a_offset + 0] = B[b_offset+0];
                    break;
                case 2:
                    A[a_offset + 1] = B[b_offset+1];
                    A[a_offset + 0] = B[b_offset+0];
                    break;
                case 1:
                    A[a_offset + 0] = B[b_offset+0];
                    break;
                case 0:
                    break;
                }

                this.top = b.top;
                this.neg = b.neg;
                this.check_top();
                return this;
            }


        public BNssl mod(in BNssl a, in BNssl b, ref BNsslCtx ctx) {
            // todo
            BNsslPair result = div(in a, in b, ref ctx);
            return result.rem;
        }

        private void set_word(ulong w) {
            check_top();
            expand(sizeof(ulong)*8);
            neg = 0;
            d[0] = w;
            top = (w != 0) ? 1 : 0;
            check_top();
            return;
        }
        
        public byte[] toBytes() {
            ulong l;
            int n, i, idx;
            check_top();
            n = i = num_bytes;
            byte[] to = new byte[i];
            idx = 0;
            while((i--) != 0)
            {
                l = d[i/BYTES];
                to[idx++] = (byte)((l >> (8*(i%BYTES)))&0xFF);
            }
            return to;
        }
        
        int num_bytes {
            get {
                return (num_bits + 7) / 8;
            }
        }

        int num_bits_word(ulong l) {
            byte[] bits= new byte[]{
                0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,
                5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
                6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
                6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
                7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
                8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
            };

// #if defined(SIXTY_FOUR_BIT_LONG)
            if ((l & 0xffffffff00000000L) != 0)
            {
                if ((l & 0xffff000000000000L) != 0)
                {
                    if ((l & 0xff00000000000000L) != 0)
                    {
                        return(bits[(int)(l>>56)]+56);
                    }
                    else    return(bits[(int)(l>>48)]+48);
                }
                else
                {
                    if ((l & 0x0000ff0000000000L) != 0)
                    {
                        return(bits[(int)(l>>40)]+40);
                    }
                    else    return(bits[(int)(l>>32)]+32);
                }
            }
            else
                // #else
                // #ifdef SIXTY_FOUR_BIT
                //     if (l & 0xffffffff00000000LL)
                //         {
                //         if (l & 0xffff000000000000LL)
                //             {
                //             if (l & 0xff00000000000000LL)
                //                 {
                //                 return(bits[(int)(l>>56)]+56);
                //                 }
                //             else    return(bits[(int)(l>>48)]+48);
                //             }
                //         else
                //             {
                //             if (l & 0x0000ff0000000000LL)
                //                 {
                //                 return(bits[(int)(l>>40)]+40);
                //                 }
                //             else    return(bits[(int)(l>>32)]+32);
                //             }
                //         }
                //     else
                // #endif
                // #endif
            {
                // #if defined(THIRTY_TWO_BIT) || defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
                if ((l & 0xffff0000L) != 0)
                {
                    if ((l & 0xff000000L) != 0)
                        return(bits[(int)(l>>24)]+24);
                    else    return(bits[(int)(l>>16)]+16);
                }
                else
                    // #endif
                {
                    // #if defined(THIRTY_TWO_BIT) || defined(SIXTY_FOUR_BIT) || defined(SIXTY_FOUR_BIT_LONG)
                    if ((l & 0xff00L) != 0)
                        return(bits[(int)(l>>8)]+8);
                    else    
                        // #endif
                        return(bits[(int)(l   )]  );
                }
            }
        }


        int num_bits {
            get {
                int i = top - 1;
                check_top();
                if(is_zero) return 0;
                return ((i*BITS2) + num_bits_word(d[i]));
            }
        }

        bool is_zero {
            get {
                return (top == 0);
            }
        }

        private void correct_top() {
            int tmp_top = top;
            int offset = tmp_top - 1;
            if(tmp_top > 0) {
                for(offset = tmp_top - 1; tmp_top > 0; tmp_top--)
                    if(d[offset--] != 0) break;
                top = tmp_top;
            }
            pollute();
        }

        private void wexpand(in int i) {
            if (i <= this.dmax) {
                return;
            }
            expand2(i);
        }

        private void pollute() {
            if(top < dmax) {
                Random rnd = new Random();
                ulong c = (ulong)rnd.Next();
                Array.Fill<ulong>(d, c, top, (dmax-top));
            }
        }
        
        private void check_top() {
            if(!(top == 0 || d[top - 1] != 0)) {
                throw new Exception("invalid top");
            }
            pollute();
        }

        private void expand(in int bits) {
            if(!(((((bits+BITS2-1))/BITS2)) <= dmax)) {
                expand2((bits + BITS2-1)/BITS2);
            }
        }


        private void expand2(in int words) {
            if(words > dmax) {
                ulong[] a = expand_internal(in words) ;
                d = a;
                dmax = words;
            }
            check_top();
        }

        private ulong[] expand_internal(in int words) {
            ulong[] a, A = null;
            ulong[] B = d;
            int i;

            if(words > (INT_MAX/(4*BITS2))) {
                throw new Exception("Bignum too long");
            }
            get_flags(STATIC_DATA);
            a = A = new ulong[words];
            int offset_a = 0, offset_b = 0;
            if(B != null) {
                for(i = top >> 2 ; i > 0; i--, offset_a += 4, offset_b += 4) {
                    ulong a0, a1, a2, a3;
                    a0 = B[offset_b + 0];
                    a1 = B[offset_b + 1];
                    a2 = B[offset_b + 2];
                    a3 = B[offset_b + 3];
                    A[offset_a + 0] = a0;
                    A[offset_a + 1] = a1;
                    A[offset_a + 2] = a2;
                    A[offset_a + 3] = a3;
                }
            }
            return (a);

        }

        private void get_flags(int flag) {
            
        }

        // private checkTop() {
        //     BNssl b = this;
            
        // }

    }
}
