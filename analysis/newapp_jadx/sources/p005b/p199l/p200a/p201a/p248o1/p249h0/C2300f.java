package p005b.p199l.p200a.p201a.p248o1.p249h0;

import android.net.Uri;
import androidx.annotation.Nullable;
import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p248o1.C2289e0;
import p005b.p199l.p200a.p201a.p248o1.C2322n;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2319k;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c;

/* renamed from: b.l.a.a.o1.h0.f */
/* loaded from: classes.dex */
public final class C2300f implements InterfaceC2321m {

    /* renamed from: a */
    public final InterfaceC2297c f5832a;

    /* renamed from: b */
    public final InterfaceC2321m f5833b;

    /* renamed from: c */
    @Nullable
    public final InterfaceC2321m f5834c;

    /* renamed from: d */
    public final InterfaceC2321m f5835d;

    /* renamed from: e */
    public final InterfaceC2304j f5836e;

    /* renamed from: f */
    @Nullable
    public final a f5837f;

    /* renamed from: g */
    public final boolean f5838g;

    /* renamed from: h */
    public final boolean f5839h;

    /* renamed from: i */
    public final boolean f5840i;

    /* renamed from: j */
    @Nullable
    public InterfaceC2321m f5841j;

    /* renamed from: k */
    public boolean f5842k;

    /* renamed from: l */
    @Nullable
    public Uri f5843l;

    /* renamed from: m */
    @Nullable
    public Uri f5844m;

    /* renamed from: n */
    public int f5845n;

    /* renamed from: o */
    @Nullable
    public byte[] f5846o;

    /* renamed from: p */
    public Map<String, String> f5847p = Collections.emptyMap();

    /* renamed from: q */
    public int f5848q;

    /* renamed from: r */
    @Nullable
    public String f5849r;

    /* renamed from: s */
    public long f5850s;

    /* renamed from: t */
    public long f5851t;

    /* renamed from: u */
    @Nullable
    public C2305k f5852u;

    /* renamed from: v */
    public boolean f5853v;

    /* renamed from: w */
    public boolean f5854w;

    /* renamed from: x */
    public long f5855x;

    /* renamed from: y */
    public long f5856y;

    /* renamed from: b.l.a.a.o1.h0.f$a */
    public interface a {
        /* renamed from: a */
        void m2223a(int i2);

        /* renamed from: b */
        void m2224b(long j2, long j3);
    }

    public C2300f(InterfaceC2297c interfaceC2297c, InterfaceC2321m interfaceC2321m, InterfaceC2321m interfaceC2321m2, @Nullable InterfaceC2319k interfaceC2319k, int i2, @Nullable a aVar, @Nullable InterfaceC2304j interfaceC2304j) {
        this.f5832a = interfaceC2297c;
        this.f5833b = interfaceC2321m2;
        int i3 = C2306l.f5869a;
        this.f5836e = C2295a.f5819a;
        this.f5838g = (i2 & 1) != 0;
        this.f5839h = (i2 & 2) != 0;
        this.f5840i = (i2 & 4) != 0;
        this.f5835d = interfaceC2321m;
        if (interfaceC2319k != null) {
            this.f5834c = new C2289e0(interfaceC2321m, interfaceC2319k);
        } else {
            this.f5834c = null;
        }
        this.f5837f = null;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* renamed from: a */
    public final void m2218a() {
        InterfaceC2321m interfaceC2321m = this.f5841j;
        if (interfaceC2321m == null) {
            return;
        }
        try {
            interfaceC2321m.close();
        } finally {
            this.f5841j = null;
            this.f5842k = false;
            C2305k c2305k = this.f5852u;
            if (c2305k != null) {
                this.f5832a.mo2209j(c2305k);
                this.f5852u = null;
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void addTransferListener(InterfaceC2291f0 interfaceC2291f0) {
        this.f5833b.addTransferListener(interfaceC2291f0);
        this.f5835d.addTransferListener(interfaceC2291f0);
    }

    /* renamed from: b */
    public final void m2219b(Throwable th) {
        if (m2220c() || (th instanceof InterfaceC2297c.a)) {
            this.f5853v = true;
        }
    }

    /* renamed from: c */
    public final boolean m2220c() {
        return this.f5841j == this.f5833b;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public void close() {
        this.f5843l = null;
        this.f5844m = null;
        this.f5845n = 1;
        this.f5846o = null;
        this.f5847p = Collections.emptyMap();
        this.f5848q = 0;
        this.f5850s = 0L;
        this.f5849r = null;
        a aVar = this.f5837f;
        if (aVar != null && this.f5855x > 0) {
            aVar.m2224b(this.f5832a.mo2207h(), this.f5855x);
            this.f5855x = 0L;
        }
        try {
            m2218a();
        } catch (Throwable th) {
            m2219b(th);
            throw th;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x00e8  */
    /* JADX WARN: Removed duplicated region for block: B:38:0x011b  */
    /* JADX WARN: Removed duplicated region for block: B:46:0x0140  */
    /* JADX WARN: Removed duplicated region for block: B:56:0x017b  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0180  */
    /* JADX WARN: Removed duplicated region for block: B:60:? A[RETURN, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:61:0x017d  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x011d  */
    /* renamed from: d */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m2221d(boolean r23) {
        /*
            Method dump skipped, instructions count: 392
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p248o1.p249h0.C2300f.m2221d(boolean):void");
    }

    /* renamed from: e */
    public final void m2222e() {
        this.f5851t = 0L;
        if (this.f5841j == this.f5834c) {
            C2311q c2311q = new C2311q();
            C2311q.m2249a(c2311q, this.f5850s);
            this.f5832a.mo2202c(this.f5849r, c2311q);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public Map<String, List<String>> getResponseHeaders() {
        return m2220c() ^ true ? this.f5835d.getResponseHeaders() : Collections.emptyMap();
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    @Nullable
    public Uri getUri() {
        return this.f5844m;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public long open(C2324p c2324p) {
        a aVar;
        try {
            Objects.requireNonNull((C2295a) this.f5836e);
            int i2 = C2306l.f5869a;
            String str = c2324p.f5940h;
            if (str == null) {
                str = c2324p.f5933a.toString();
            }
            this.f5849r = str;
            Uri uri = c2324p.f5933a;
            this.f5843l = uri;
            C2312r c2312r = (C2312r) this.f5832a.mo2201b(str);
            Uri uri2 = null;
            String str2 = c2312r.f5897c.containsKey("exo_redir") ? new String(c2312r.f5897c.get("exo_redir"), Charset.forName("UTF-8")) : null;
            if (str2 != null) {
                uri2 = Uri.parse(str2);
            }
            if (uri2 != null) {
                uri = uri2;
            }
            this.f5844m = uri;
            this.f5845n = c2324p.f5934b;
            this.f5846o = c2324p.f5935c;
            this.f5847p = c2324p.f5936d;
            this.f5848q = c2324p.f5941i;
            this.f5850s = c2324p.f5938f;
            boolean z = true;
            int i3 = (this.f5839h && this.f5853v) ? 0 : (this.f5840i && c2324p.f5939g == -1) ? 1 : -1;
            if (i3 == -1) {
                z = false;
            }
            this.f5854w = z;
            if (z && (aVar = this.f5837f) != null) {
                aVar.m2223a(i3);
            }
            long j2 = c2324p.f5939g;
            if (j2 == -1 && !this.f5854w) {
                long m2248a = C2309o.m2248a(this.f5832a.mo2201b(this.f5849r));
                this.f5851t = m2248a;
                if (m2248a != -1) {
                    long j3 = m2248a - c2324p.f5938f;
                    this.f5851t = j3;
                    if (j3 <= 0) {
                        throw new C2322n(0);
                    }
                }
                m2221d(false);
                return this.f5851t;
            }
            this.f5851t = j2;
            m2221d(false);
            return this.f5851t;
        } catch (Throwable th) {
            m2219b(th);
            throw th;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m
    public int read(byte[] bArr, int i2, int i3) {
        boolean z = false;
        if (i3 == 0) {
            return 0;
        }
        if (this.f5851t == 0) {
            return -1;
        }
        try {
            if (this.f5850s >= this.f5856y) {
                m2221d(true);
            }
            int read = this.f5841j.read(bArr, i2, i3);
            if (read != -1) {
                if (m2220c()) {
                    this.f5855x += read;
                }
                long j2 = read;
                this.f5850s += j2;
                long j3 = this.f5851t;
                if (j3 != -1) {
                    this.f5851t = j3 - j2;
                }
            } else {
                if (!this.f5842k) {
                    long j4 = this.f5851t;
                    if (j4 <= 0) {
                        if (j4 == -1) {
                        }
                    }
                    m2218a();
                    m2221d(false);
                    return read(bArr, i2, i3);
                }
                m2222e();
            }
            return read;
        } catch (IOException e2) {
            if (this.f5842k) {
                int i4 = C2306l.f5869a;
                Throwable th = e2;
                while (true) {
                    if (th != null) {
                        if ((th instanceof C2322n) && ((C2322n) th).f5926c == 0) {
                            z = true;
                            break;
                        }
                        th = th.getCause();
                    } else {
                        break;
                    }
                }
                if (z) {
                    m2222e();
                    return -1;
                }
            }
            m2219b(e2);
            throw e2;
        } catch (Throwable th2) {
            m2219b(th2);
            throw th2;
        }
    }
}
