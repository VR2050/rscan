package p005b.p199l.p200a.p201a.p227k1.p232m0;

import android.net.Uri;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import java.io.IOException;
import java.math.BigInteger;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import org.checkerframework.checker.nullness.qual.RequiresNonNull;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p220h1.p223i.C2088b;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.k1.m0.l */
/* loaded from: classes.dex */
public final class C2169l extends AbstractC2130l {

    /* renamed from: j */
    public static final C2049p f4893j = new C2049p();

    /* renamed from: k */
    public static final AtomicInteger f4894k = new AtomicInteger();

    /* renamed from: A */
    public final boolean f4895A;

    /* renamed from: B */
    public final boolean f4896B;

    /* renamed from: C */
    public InterfaceC2041h f4897C;

    /* renamed from: D */
    public boolean f4898D;

    /* renamed from: E */
    public C2172o f4899E;

    /* renamed from: F */
    public int f4900F;

    /* renamed from: G */
    public boolean f4901G;

    /* renamed from: H */
    public volatile boolean f4902H;

    /* renamed from: I */
    public boolean f4903I;

    /* renamed from: l */
    public final int f4904l;

    /* renamed from: m */
    public final int f4905m;

    /* renamed from: n */
    public final Uri f4906n;

    /* renamed from: o */
    @Nullable
    public final InterfaceC2321m f4907o;

    /* renamed from: p */
    @Nullable
    public final C2324p f4908p;

    /* renamed from: q */
    @Nullable
    public final InterfaceC2041h f4909q;

    /* renamed from: r */
    public final boolean f4910r;

    /* renamed from: s */
    public final boolean f4911s;

    /* renamed from: t */
    public final C2342c0 f4912t;

    /* renamed from: u */
    public final boolean f4913u;

    /* renamed from: v */
    public final InterfaceC2167j f4914v;

    /* renamed from: w */
    @Nullable
    public final List<Format> f4915w;

    /* renamed from: x */
    @Nullable
    public final DrmInitData f4916x;

    /* renamed from: y */
    public final C2088b f4917y;

    /* renamed from: z */
    public final C2360t f4918z;

    public C2169l(InterfaceC2167j interfaceC2167j, InterfaceC2321m interfaceC2321m, C2324p c2324p, Format format, boolean z, @Nullable InterfaceC2321m interfaceC2321m2, @Nullable C2324p c2324p2, boolean z2, Uri uri, @Nullable List<Format> list, int i2, @Nullable Object obj, long j2, long j3, long j4, int i3, boolean z3, boolean z4, C2342c0 c2342c0, @Nullable DrmInitData drmInitData, @Nullable InterfaceC2041h interfaceC2041h, C2088b c2088b, C2360t c2360t, boolean z5) {
        super(interfaceC2321m, c2324p, format, i2, obj, j2, j3, j4);
        this.f4895A = z;
        this.f4905m = i3;
        this.f4908p = c2324p2;
        this.f4907o = interfaceC2321m2;
        this.f4901G = c2324p2 != null;
        this.f4896B = z2;
        this.f4906n = uri;
        this.f4910r = z4;
        this.f4912t = c2342c0;
        this.f4911s = z3;
        this.f4914v = interfaceC2167j;
        this.f4915w = list;
        this.f4916x = drmInitData;
        this.f4909q = interfaceC2041h;
        this.f4917y = c2088b;
        this.f4918z = c2360t;
        this.f4913u = z5;
        this.f4904l = f4894k.getAndIncrement();
    }

    /* renamed from: f */
    public static byte[] m1945f(String str) {
        if (C2344d0.m2320L(str).startsWith("0x")) {
            str = str.substring(2);
        }
        byte[] byteArray = new BigInteger(str, 16).toByteArray();
        byte[] bArr = new byte[16];
        int length = byteArray.length > 16 ? byteArray.length - 16 : 0;
        System.arraycopy(byteArray, length, bArr, (16 - byteArray.length) + length, byteArray.length - length);
        return bArr;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
    /* renamed from: a */
    public void mo1782a() {
        InterfaceC2041h interfaceC2041h;
        Objects.requireNonNull(this.f4899E);
        if (this.f4897C == null && (interfaceC2041h = this.f4909q) != null) {
            this.f4897C = interfaceC2041h;
            this.f4898D = true;
            this.f4901G = false;
        }
        if (this.f4901G) {
            Objects.requireNonNull(this.f4907o);
            Objects.requireNonNull(this.f4908p);
            m1946e(this.f4907o, this.f4908p, this.f4896B);
            this.f4900F = 0;
            this.f4901G = false;
        }
        if (this.f4902H) {
            return;
        }
        if (!this.f4911s) {
            if (this.f4910r) {
                C2342c0 c2342c0 = this.f4912t;
                if (c2342c0.f6031a == Long.MAX_VALUE) {
                    c2342c0.m2308d(this.f4628f);
                }
            } else {
                C2342c0 c2342c02 = this.f4912t;
                synchronized (c2342c02) {
                    while (c2342c02.f6033c == -9223372036854775807L) {
                        c2342c02.wait();
                    }
                }
            }
            m1946e(this.f4630h, this.f4623a, this.f4895A);
        }
        this.f4903I = true;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
    /* renamed from: b */
    public void mo1783b() {
        this.f4902H = true;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l
    /* renamed from: d */
    public boolean mo1861d() {
        return this.f4903I;
    }

    @RequiresNonNull({"output"})
    /* renamed from: e */
    public final void m1946e(InterfaceC2321m interfaceC2321m, C2324p c2324p, boolean z) {
        C2324p m2268c;
        boolean z2;
        int i2 = 0;
        if (z) {
            z2 = this.f4900F != 0;
            m2268c = c2324p;
        } else {
            m2268c = c2324p.m2268c(this.f4900F);
            z2 = false;
        }
        try {
            C2003e m1947g = m1947g(interfaceC2321m, m2268c);
            if (z2) {
                m1947g.m1569i(this.f4900F);
            }
            while (i2 == 0) {
                try {
                    if (this.f4902H) {
                        break;
                    } else {
                        i2 = this.f4897C.mo1479d(m1947g, f4893j);
                    }
                } finally {
                    this.f4900F = (int) (m1947g.f3789d - c2324p.f5937e);
                }
            }
            try {
                interfaceC2321m.close();
            } catch (IOException unused) {
            }
        } catch (Throwable th) {
            if (interfaceC2321m != null) {
                try {
                    interfaceC2321m.close();
                } catch (IOException unused2) {
                }
            }
            throw th;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:32:0x028b  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x029e  */
    @org.checkerframework.checker.nullness.qual.EnsuresNonNull({"extractor"})
    @org.checkerframework.checker.nullness.qual.RequiresNonNull({"output"})
    /* renamed from: g */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final p005b.p199l.p200a.p201a.p208f1.C2003e m1947g(p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m r14, p005b.p199l.p200a.p201a.p248o1.C2324p r15) {
        /*
            Method dump skipped, instructions count: 725
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.p232m0.C2169l.m1947g(b.l.a.a.o1.m, b.l.a.a.o1.p):b.l.a.a.f1.e");
    }
}
