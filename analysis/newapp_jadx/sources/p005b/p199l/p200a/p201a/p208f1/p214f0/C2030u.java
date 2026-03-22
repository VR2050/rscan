package p005b.p199l.p200a.p201a.p208f1.p214f0;

import android.util.SparseArray;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2359s;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.f0.u */
/* loaded from: classes.dex */
public final class C2030u implements InterfaceC2041h {

    /* renamed from: e */
    public boolean f4097e;

    /* renamed from: f */
    public boolean f4098f;

    /* renamed from: g */
    public boolean f4099g;

    /* renamed from: h */
    public long f4100h;

    /* renamed from: i */
    public C2028s f4101i;

    /* renamed from: j */
    public InterfaceC2042i f4102j;

    /* renamed from: k */
    public boolean f4103k;

    /* renamed from: a */
    public final C2342c0 f4093a = new C2342c0(0);

    /* renamed from: c */
    public final C2360t f4095c = new C2360t(4096);

    /* renamed from: b */
    public final SparseArray<a> f4094b = new SparseArray<>();

    /* renamed from: d */
    public final C2029t f4096d = new C2029t();

    /* renamed from: b.l.a.a.f1.f0.u$a */
    public static final class a {

        /* renamed from: a */
        public final InterfaceC2019j f4104a;

        /* renamed from: b */
        public final C2342c0 f4105b;

        /* renamed from: c */
        public final C2359s f4106c = new C2359s(new byte[64]);

        /* renamed from: d */
        public boolean f4107d;

        /* renamed from: e */
        public boolean f4108e;

        /* renamed from: f */
        public boolean f4109f;

        /* renamed from: g */
        public int f4110g;

        /* renamed from: h */
        public long f4111h;

        public a(InterfaceC2019j interfaceC2019j, C2342c0 c2342c0) {
            this.f4104a = interfaceC2019j;
            this.f4105b = c2342c0;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:105:0x01f2  */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int mo1479d(p005b.p199l.p200a.p201a.p208f1.C2003e r17, p005b.p199l.p200a.p201a.p208f1.C2049p r18) {
        /*
            Method dump skipped, instructions count: 810
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p214f0.C2030u.mo1479d(b.l.a.a.f1.e, b.l.a.a.f1.p):int");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: e */
    public void mo1480e(InterfaceC2042i interfaceC2042i) {
        this.f4102j = interfaceC2042i;
    }

    /* JADX WARN: Code restructure failed: missing block: B:8:0x0021, code lost:
    
        if (r7 != r9) goto L11;
     */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0030  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x003c A[LOOP:0: B:13:0x0034->B:15:0x003c, LOOP_END] */
    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: f */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo1481f(long r7, long r9) {
        /*
            r6 = this;
            b.l.a.a.p1.c0 r7 = r6.f4093a
            long r7 = r7.m2307c()
            r0 = 0
            r1 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            int r3 = (r7 > r1 ? 1 : (r7 == r1 ? 0 : -1))
            if (r3 != 0) goto L12
            r7 = 1
            goto L13
        L12:
            r7 = 0
        L13:
            if (r7 != 0) goto L23
            b.l.a.a.p1.c0 r7 = r6.f4093a
            long r7 = r7.f6031a
            r3 = 0
            int r5 = (r7 > r3 ? 1 : (r7 == r3 ? 0 : -1))
            if (r5 == 0) goto L2c
            int r3 = (r7 > r9 ? 1 : (r7 == r9 ? 0 : -1))
            if (r3 == 0) goto L2c
        L23:
            b.l.a.a.p1.c0 r7 = r6.f4093a
            r7.f6033c = r1
            b.l.a.a.p1.c0 r7 = r6.f4093a
            r7.m2308d(r9)
        L2c:
            b.l.a.a.f1.f0.s r7 = r6.f4101i
            if (r7 == 0) goto L33
            r7.m1460e(r9)
        L33:
            r7 = 0
        L34:
            android.util.SparseArray<b.l.a.a.f1.f0.u$a> r8 = r6.f4094b
            int r8 = r8.size()
            if (r7 >= r8) goto L4e
            android.util.SparseArray<b.l.a.a.f1.f0.u$a> r8 = r6.f4094b
            java.lang.Object r8 = r8.valueAt(r7)
            b.l.a.a.f1.f0.u$a r8 = (p005b.p199l.p200a.p201a.p208f1.p214f0.C2030u.a) r8
            r8.f4109f = r0
            b.l.a.a.f1.f0.j r8 = r8.f4104a
            r8.mo1574c()
            int r7 = r7 + 1
            goto L34
        L4e:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p214f0.C2030u.mo1481f(long, long):void");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    /* renamed from: h */
    public boolean mo1483h(C2003e c2003e) {
        byte[] bArr = new byte[14];
        c2003e.m1565e(bArr, 0, 14, false);
        if (442 != (((bArr[0] & 255) << 24) | ((bArr[1] & 255) << 16) | ((bArr[2] & 255) << 8) | (bArr[3] & 255)) || (bArr[4] & 196) != 68 || (bArr[6] & 4) != 4 || (bArr[8] & 4) != 4 || (bArr[9] & 1) != 1 || (bArr[12] & 3) != 3) {
            return false;
        }
        c2003e.m1561a(bArr[13] & 7, false);
        c2003e.m1565e(bArr, 0, 3, false);
        return 1 == ((((bArr[0] & 255) << 16) | ((bArr[1] & 255) << 8)) | (bArr[2] & 255));
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h
    public void release() {
    }
}
