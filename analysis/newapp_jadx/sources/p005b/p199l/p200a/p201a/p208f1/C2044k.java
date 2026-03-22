package p005b.p199l.p200a.p201a.p208f1;

import com.alibaba.fastjson.asm.Opcodes;
import p005b.p199l.p200a.p201a.p250p1.C2353m;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.k */
/* loaded from: classes.dex */
public final class C2044k {

    /* renamed from: b.l.a.a.f1.k$a */
    public static final class a {

        /* renamed from: a */
        public long f4166a;
    }

    /* renamed from: a */
    public static boolean m1626a(C2360t c2360t, C2353m c2353m, boolean z, a aVar) {
        try {
            long m2591w = c2360t.m2591w();
            if (!z) {
                m2591w *= c2353m.f6074b;
            }
            aVar.f4166a = m2591w;
            return true;
        } catch (NumberFormatException unused) {
            return false;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:36:0x008e, code lost:
    
        if (r7 == r18.f6078f) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x009b, code lost:
    
        if ((r17.m2585q() * 1000) == r3) goto L61;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x00aa, code lost:
    
        if (r4 == r3) goto L61;
     */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00b1  */
    /* JADX WARN: Removed duplicated region for block: B:49:? A[RETURN, SYNTHETIC] */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static boolean m1627b(p005b.p199l.p200a.p201a.p250p1.C2360t r17, p005b.p199l.p200a.p201a.p250p1.C2353m r18, int r19, p005b.p199l.p200a.p201a.p208f1.C2044k.a r20) {
        /*
            Method dump skipped, instructions count: 212
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.C2044k.m1627b(b.l.a.a.p1.t, b.l.a.a.p1.m, int, b.l.a.a.f1.k$a):boolean");
    }

    /* renamed from: c */
    public static int m1628c(C2360t c2360t, int i2) {
        switch (i2) {
            case 1:
                return Opcodes.CHECKCAST;
            case 2:
            case 3:
            case 4:
            case 5:
                return 576 << (i2 - 2);
            case 6:
                return c2360t.m2585q() + 1;
            case 7:
                return c2360t.m2590v() + 1;
            case 8:
            case 9:
            case 10:
            case 11:
            case 12:
            case 13:
            case 14:
            case 15:
                return 256 << (i2 - 8);
            default:
                return -1;
        }
    }
}
