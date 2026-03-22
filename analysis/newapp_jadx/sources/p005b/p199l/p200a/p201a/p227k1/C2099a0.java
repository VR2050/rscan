package p005b.p199l.p200a.p201a.p227k1;

import android.net.Uri;
import android.os.Handler;
import androidx.annotation.Nullable;
import androidx.work.WorkRequest;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.icy.IcyHeaders;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.io.EOFException;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.C1964f0;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.C2400v0;
import p005b.p199l.p200a.p201a.p204c1.C1945e;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p208f1.C2003e;
import p005b.p199l.p200a.p201a.p208f1.C2049p;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2041h;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2050q;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p210b0.C1976d;
import p005b.p199l.p200a.p201a.p227k1.C2099a0;
import p005b.p199l.p200a.p201a.p227k1.C2105d0;
import p005b.p199l.p200a.p201a.p227k1.C2199v;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p248o1.C2281a0;
import p005b.p199l.p200a.p201a.p248o1.C2287d0;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.C2331w;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2334z;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2349i;
import p005b.p199l.p200a.p201a.p250p1.C2357q;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.k1.a0 */
/* loaded from: classes.dex */
public final class C2099a0 implements InterfaceC2201x, InterfaceC2042i, C2281a0.b<a>, C2281a0.f, C2105d0.b {

    /* renamed from: c */
    public static final Map<String, String> f4437c;

    /* renamed from: e */
    public static final Format f4438e;

    /* renamed from: A */
    public boolean f4439A;

    /* renamed from: B */
    @Nullable
    public d f4440B;

    /* renamed from: C */
    public boolean f4441C;

    /* renamed from: E */
    public boolean f4443E;

    /* renamed from: F */
    public boolean f4444F;

    /* renamed from: G */
    public boolean f4445G;

    /* renamed from: H */
    public int f4446H;

    /* renamed from: K */
    public boolean f4449K;

    /* renamed from: L */
    public long f4450L;

    /* renamed from: N */
    public boolean f4452N;

    /* renamed from: O */
    public int f4453O;

    /* renamed from: P */
    public boolean f4454P;

    /* renamed from: Q */
    public boolean f4455Q;

    /* renamed from: f */
    public final Uri f4456f;

    /* renamed from: g */
    public final InterfaceC2321m f4457g;

    /* renamed from: h */
    public final InterfaceC1954e<?> f4458h;

    /* renamed from: i */
    public final InterfaceC2334z f4459i;

    /* renamed from: j */
    public final InterfaceC2203z.a f4460j;

    /* renamed from: k */
    public final c f4461k;

    /* renamed from: l */
    public final InterfaceC2288e f4462l;

    /* renamed from: m */
    @Nullable
    public final String f4463m;

    /* renamed from: n */
    public final long f4464n;

    /* renamed from: p */
    public final b f4466p;

    /* renamed from: u */
    @Nullable
    public InterfaceC2201x.a f4471u;

    /* renamed from: v */
    @Nullable
    public InterfaceC2050q f4472v;

    /* renamed from: w */
    @Nullable
    public IcyHeaders f4473w;

    /* renamed from: z */
    public boolean f4476z;

    /* renamed from: o */
    public final C2281a0 f4465o = new C2281a0("Loader:ProgressiveMediaPeriod");

    /* renamed from: q */
    public final C2349i f4467q = new C2349i();

    /* renamed from: r */
    public final Runnable f4468r = new Runnable() { // from class: b.l.a.a.k1.k
        @Override // java.lang.Runnable
        public final void run() {
            boolean[] zArr;
            Format format;
            Metadata m4053b;
            int i2;
            C2099a0 c2099a0 = C2099a0.this;
            InterfaceC2050q interfaceC2050q = c2099a0.f4472v;
            if (c2099a0.f4455Q || c2099a0.f4439A || !c2099a0.f4476z || interfaceC2050q == null) {
                return;
            }
            char c2 = 0;
            for (C2105d0 c2105d0 : c2099a0.f4474x) {
                if (c2105d0.m1822r() == null) {
                    return;
                }
            }
            C2349i c2349i = c2099a0.f4467q;
            synchronized (c2349i) {
                c2349i.f6061a = false;
            }
            int length = c2099a0.f4474x.length;
            TrackGroup[] trackGroupArr = new TrackGroup[length];
            boolean[] zArr2 = new boolean[length];
            c2099a0.f4447I = interfaceC2050q.mo1464i();
            int i3 = 0;
            while (i3 < length) {
                Format m1822r = c2099a0.f4474x[i3].m1822r();
                String str = m1822r.f9245l;
                boolean m2545h = C2357q.m2545h(str);
                boolean z = m2545h || C2357q.m2547j(str);
                zArr2[i3] = z;
                c2099a0.f4441C = z | c2099a0.f4441C;
                IcyHeaders icyHeaders = c2099a0.f4473w;
                if (icyHeaders != null) {
                    if (m2545h || c2099a0.f4475y[i3].f4501b) {
                        Metadata metadata = m1822r.f9243j;
                        if (metadata == null) {
                            Metadata.Entry[] entryArr = new Metadata.Entry[1];
                            entryArr[c2] = icyHeaders;
                            m4053b = new Metadata(entryArr);
                        } else {
                            Metadata.Entry[] entryArr2 = new Metadata.Entry[1];
                            entryArr2[c2] = icyHeaders;
                            m4053b = metadata.m4053b(entryArr2);
                        }
                        m1822r = m1822r.m4042b(m1822r.f9248o, m4053b);
                    }
                    if (m2545h && m1822r.f9241h == -1 && (i2 = icyHeaders.f9292c) != -1) {
                        zArr = zArr2;
                        format = new Format(m1822r.f9237c, m1822r.f9238e, m1822r.f9239f, m1822r.f9240g, i2, m1822r.f9242i, m1822r.f9243j, m1822r.f9244k, m1822r.f9245l, m1822r.f9246m, m1822r.f9247n, m1822r.f9248o, m1822r.f9249p, m1822r.f9250q, m1822r.f9251r, m1822r.f9252s, m1822r.f9253t, m1822r.f9254u, m1822r.f9256w, m1822r.f9255v, m1822r.f9257x, m1822r.f9258y, m1822r.f9259z, m1822r.f9230A, m1822r.f9231B, m1822r.f9232C, m1822r.f9233D, m1822r.f9234E, m1822r.f9235F);
                        trackGroupArr[i3] = new TrackGroup(format);
                        i3++;
                        zArr2 = zArr;
                        c2 = 0;
                    }
                }
                zArr = zArr2;
                format = m1822r;
                trackGroupArr[i3] = new TrackGroup(format);
                i3++;
                zArr2 = zArr;
                c2 = 0;
            }
            boolean[] zArr3 = zArr2;
            boolean z2 = c2099a0.f4448J == -1 && interfaceC2050q.mo1464i() == -9223372036854775807L;
            c2099a0.f4449K = z2;
            c2099a0.f4442D = z2 ? 7 : 1;
            c2099a0.f4440B = new C2099a0.d(interfaceC2050q, new TrackGroupArray(trackGroupArr), zArr3);
            c2099a0.f4439A = true;
            ((C2101b0) c2099a0.f4461k).m1795t(c2099a0.f4447I, interfaceC2050q.mo1462c(), c2099a0.f4449K);
            InterfaceC2201x.a aVar = c2099a0.f4471u;
            Objects.requireNonNull(aVar);
            aVar.mo1423k(c2099a0);
        }
    };

    /* renamed from: s */
    public final Runnable f4469s = new Runnable() { // from class: b.l.a.a.k1.l
        @Override // java.lang.Runnable
        public final void run() {
            C2099a0 c2099a0 = C2099a0.this;
            if (c2099a0.f4455Q) {
                return;
            }
            InterfaceC2201x.a aVar = c2099a0.f4471u;
            Objects.requireNonNull(aVar);
            aVar.mo1421i(c2099a0);
        }
    };

    /* renamed from: t */
    public final Handler f4470t = new Handler();

    /* renamed from: y */
    public f[] f4475y = new f[0];

    /* renamed from: x */
    public C2105d0[] f4474x = new C2105d0[0];

    /* renamed from: M */
    public long f4451M = -9223372036854775807L;

    /* renamed from: J */
    public long f4448J = -1;

    /* renamed from: I */
    public long f4447I = -9223372036854775807L;

    /* renamed from: D */
    public int f4442D = 1;

    /* renamed from: b.l.a.a.k1.a0$a */
    public final class a implements C2281a0.e, C2199v.a {

        /* renamed from: a */
        public final Uri f4477a;

        /* renamed from: b */
        public final C2287d0 f4478b;

        /* renamed from: c */
        public final b f4479c;

        /* renamed from: d */
        public final InterfaceC2042i f4480d;

        /* renamed from: e */
        public final C2349i f4481e;

        /* renamed from: g */
        public volatile boolean f4483g;

        /* renamed from: i */
        public long f4485i;

        /* renamed from: l */
        @Nullable
        public InterfaceC2052s f4488l;

        /* renamed from: m */
        public boolean f4489m;

        /* renamed from: f */
        public final C2049p f4482f = new C2049p();

        /* renamed from: h */
        public boolean f4484h = true;

        /* renamed from: k */
        public long f4487k = -1;

        /* renamed from: j */
        public C2324p f4486j = m1784c(0);

        public a(Uri uri, InterfaceC2321m interfaceC2321m, b bVar, InterfaceC2042i interfaceC2042i, C2349i c2349i) {
            this.f4477a = uri;
            this.f4478b = new C2287d0(interfaceC2321m);
            this.f4479c = bVar;
            this.f4480d = interfaceC2042i;
            this.f4481e = c2349i;
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
        /* renamed from: a */
        public void mo1782a() {
            long j2;
            Uri uri;
            InterfaceC2321m interfaceC2321m;
            C2003e c2003e;
            int i2;
            int i3 = 0;
            while (i3 == 0 && !this.f4483g) {
                C2003e c2003e2 = null;
                try {
                    j2 = this.f4482f.f4187a;
                    C2324p m1784c = m1784c(j2);
                    this.f4486j = m1784c;
                    long open = this.f4478b.open(m1784c);
                    this.f4487k = open;
                    if (open != -1) {
                        this.f4487k = open + j2;
                    }
                    uri = this.f4478b.getUri();
                    Objects.requireNonNull(uri);
                    C2099a0.this.f4473w = IcyHeaders.m4055b(this.f4478b.getResponseHeaders());
                    InterfaceC2321m interfaceC2321m2 = this.f4478b;
                    IcyHeaders icyHeaders = C2099a0.this.f4473w;
                    if (icyHeaders == null || (i2 = icyHeaders.f9297i) == -1) {
                        interfaceC2321m = interfaceC2321m2;
                    } else {
                        InterfaceC2321m c2199v = new C2199v(interfaceC2321m2, i2, this);
                        InterfaceC2052s m1756A = C2099a0.this.m1756A(new f(0, true));
                        this.f4488l = m1756A;
                        ((C2105d0) m1756A).mo1615d(C2099a0.f4438e);
                        interfaceC2321m = c2199v;
                    }
                    c2003e = new C2003e(interfaceC2321m, j2, this.f4487k);
                } catch (Throwable th) {
                    th = th;
                }
                try {
                    InterfaceC2041h m1785a = this.f4479c.m1785a(c2003e, this.f4480d, uri);
                    if (C2099a0.this.f4473w != null && (m1785a instanceof C1976d)) {
                        ((C1976d) m1785a).f3563m = true;
                    }
                    if (this.f4484h) {
                        m1785a.mo1481f(j2, this.f4485i);
                        this.f4484h = false;
                    }
                    while (i3 == 0 && !this.f4483g) {
                        C2349i c2349i = this.f4481e;
                        synchronized (c2349i) {
                            while (!c2349i.f6061a) {
                                c2349i.wait();
                            }
                        }
                        i3 = m1785a.mo1479d(c2003e, this.f4482f);
                        long j3 = c2003e.f3789d;
                        if (j3 > C2099a0.this.f4464n + j2) {
                            C2349i c2349i2 = this.f4481e;
                            synchronized (c2349i2) {
                                c2349i2.f6061a = false;
                            }
                            C2099a0 c2099a0 = C2099a0.this;
                            c2099a0.f4470t.post(c2099a0.f4469s);
                            j2 = j3;
                        }
                    }
                    if (i3 == 1) {
                        i3 = 0;
                    } else {
                        this.f4482f.f4187a = c2003e.f3789d;
                    }
                    C2287d0 c2287d0 = this.f4478b;
                    if (c2287d0 != null) {
                        try {
                            c2287d0.f5796a.close();
                        } catch (IOException unused) {
                        }
                    }
                } catch (Throwable th2) {
                    th = th2;
                    c2003e2 = c2003e;
                    if (i3 != 1 && c2003e2 != null) {
                        this.f4482f.f4187a = c2003e2.f3789d;
                    }
                    C2287d0 c2287d02 = this.f4478b;
                    int i4 = C2344d0.f6035a;
                    if (c2287d02 != null) {
                        try {
                            c2287d02.f5796a.close();
                        } catch (IOException unused2) {
                        }
                    }
                    throw th;
                }
            }
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.e
        /* renamed from: b */
        public void mo1783b() {
            this.f4483g = true;
        }

        /* renamed from: c */
        public final C2324p m1784c(long j2) {
            return new C2324p(this.f4477a, 1, null, j2, j2, -1L, C2099a0.this.f4463m, 6, C2099a0.f4437c);
        }
    }

    /* renamed from: b.l.a.a.k1.a0$b */
    public static final class b {

        /* renamed from: a */
        public final InterfaceC2041h[] f4491a;

        /* renamed from: b */
        @Nullable
        public InterfaceC2041h f4492b;

        public b(InterfaceC2041h[] interfaceC2041hArr) {
            this.f4491a = interfaceC2041hArr;
        }

        /* renamed from: a */
        public InterfaceC2041h m1785a(C2003e c2003e, InterfaceC2042i interfaceC2042i, Uri uri) {
            InterfaceC2041h interfaceC2041h = this.f4492b;
            if (interfaceC2041h != null) {
                return interfaceC2041h;
            }
            InterfaceC2041h[] interfaceC2041hArr = this.f4491a;
            if (interfaceC2041hArr.length == 1) {
                this.f4492b = interfaceC2041hArr[0];
            } else {
                int length = interfaceC2041hArr.length;
                int i2 = 0;
                while (true) {
                    if (i2 >= length) {
                        break;
                    }
                    InterfaceC2041h interfaceC2041h2 = interfaceC2041hArr[i2];
                    try {
                    } catch (EOFException unused) {
                    } catch (Throwable th) {
                        c2003e.f3791f = 0;
                        throw th;
                    }
                    if (interfaceC2041h2.mo1483h(c2003e)) {
                        this.f4492b = interfaceC2041h2;
                        c2003e.f3791f = 0;
                        break;
                    }
                    continue;
                    c2003e.f3791f = 0;
                    i2++;
                }
                if (this.f4492b == null) {
                    StringBuilder m586H = C1499a.m586H("None of the available extractors (");
                    InterfaceC2041h[] interfaceC2041hArr2 = this.f4491a;
                    int i3 = C2344d0.f6035a;
                    StringBuilder sb = new StringBuilder();
                    for (int i4 = 0; i4 < interfaceC2041hArr2.length; i4++) {
                        sb.append(interfaceC2041hArr2[i4].getClass().getSimpleName());
                        if (i4 < interfaceC2041hArr2.length - 1) {
                            sb.append(", ");
                        }
                    }
                    m586H.append(sb.toString());
                    m586H.append(") could read the stream.");
                    throw new C2115i0(m586H.toString(), uri);
                }
            }
            this.f4492b.mo1480e(interfaceC2042i);
            return this.f4492b;
        }
    }

    /* renamed from: b.l.a.a.k1.a0$c */
    public interface c {
    }

    /* renamed from: b.l.a.a.k1.a0$d */
    public static final class d {

        /* renamed from: a */
        public final InterfaceC2050q f4493a;

        /* renamed from: b */
        public final TrackGroupArray f4494b;

        /* renamed from: c */
        public final boolean[] f4495c;

        /* renamed from: d */
        public final boolean[] f4496d;

        /* renamed from: e */
        public final boolean[] f4497e;

        public d(InterfaceC2050q interfaceC2050q, TrackGroupArray trackGroupArray, boolean[] zArr) {
            this.f4493a = interfaceC2050q;
            this.f4494b = trackGroupArray;
            this.f4495c = zArr;
            int i2 = trackGroupArray.f9397e;
            this.f4496d = new boolean[i2];
            this.f4497e = new boolean[i2];
        }
    }

    /* renamed from: b.l.a.a.k1.a0$e */
    public final class e implements InterfaceC2107e0 {

        /* renamed from: c */
        public final int f4498c;

        public e(int i2) {
            this.f4498c = i2;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
        /* renamed from: a */
        public void mo1786a() {
            C2099a0 c2099a0 = C2099a0.this;
            c2099a0.f4474x[this.f4498c].m1827w();
            c2099a0.f4465o.m2184f(((C2331w) c2099a0.f4459i).m2280b(c2099a0.f4442D));
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
        /* renamed from: i */
        public int mo1787i(C1964f0 c1964f0, C1945e c1945e, boolean z) {
            C2099a0 c2099a0 = C2099a0.this;
            int i2 = this.f4498c;
            if (c2099a0.m1758C()) {
                return -3;
            }
            c2099a0.m1780y(i2);
            int m1803A = c2099a0.f4474x[i2].m1803A(c1964f0, c1945e, z, c2099a0.f4454P, c2099a0.f4450L);
            if (m1803A == -3) {
                c2099a0.m1781z(i2);
            }
            return m1803A;
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
        public boolean isReady() {
            C2099a0 c2099a0 = C2099a0.this;
            return !c2099a0.m1758C() && c2099a0.f4474x[this.f4498c].m1825u(c2099a0.f4454P);
        }

        @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0
        /* renamed from: o */
        public int mo1788o(long j2) {
            C2099a0 c2099a0 = C2099a0.this;
            int i2 = this.f4498c;
            if (c2099a0.m1758C()) {
                return 0;
            }
            c2099a0.m1780y(i2);
            C2105d0 c2105d0 = c2099a0.f4474x[i2];
            int m1809e = (!c2099a0.f4454P || j2 <= c2105d0.m1818n()) ? c2105d0.m1809e(j2) : c2105d0.m1810f();
            if (m1809e != 0) {
                return m1809e;
            }
            c2099a0.m1781z(i2);
            return m1809e;
        }
    }

    /* renamed from: b.l.a.a.k1.a0$f */
    public static final class f {

        /* renamed from: a */
        public final int f4500a;

        /* renamed from: b */
        public final boolean f4501b;

        public f(int i2, boolean z) {
            this.f4500a = i2;
            this.f4501b = z;
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || f.class != obj.getClass()) {
                return false;
            }
            f fVar = (f) obj;
            return this.f4500a == fVar.f4500a && this.f4501b == fVar.f4501b;
        }

        public int hashCode() {
            return (this.f4500a * 31) + (this.f4501b ? 1 : 0);
        }
    }

    static {
        HashMap hashMap = new HashMap();
        hashMap.put("Icy-MetaData", "1");
        f4437c = Collections.unmodifiableMap(hashMap);
        f4438e = Format.m4027D("icy", "application/x-icy", Long.MAX_VALUE);
    }

    public C2099a0(Uri uri, InterfaceC2321m interfaceC2321m, InterfaceC2041h[] interfaceC2041hArr, InterfaceC1954e<?> interfaceC1954e, InterfaceC2334z interfaceC2334z, InterfaceC2203z.a aVar, c cVar, InterfaceC2288e interfaceC2288e, @Nullable String str, int i2) {
        this.f4456f = uri;
        this.f4457g = interfaceC2321m;
        this.f4458h = interfaceC1954e;
        this.f4459i = interfaceC2334z;
        this.f4460j = aVar;
        this.f4461k = cVar;
        this.f4462l = interfaceC2288e;
        this.f4463m = str;
        this.f4464n = i2;
        this.f4466p = new b(interfaceC2041hArr);
        aVar.m2040p();
    }

    /* renamed from: A */
    public final InterfaceC2052s m1756A(f fVar) {
        int length = this.f4474x.length;
        for (int i2 = 0; i2 < length; i2++) {
            if (fVar.equals(this.f4475y[i2])) {
                return this.f4474x[i2];
            }
        }
        C2105d0 c2105d0 = new C2105d0(this.f4462l, this.f4458h);
        c2105d0.f4547d = this;
        int i3 = length + 1;
        f[] fVarArr = (f[]) Arrays.copyOf(this.f4475y, i3);
        fVarArr[length] = fVar;
        int i4 = C2344d0.f6035a;
        this.f4475y = fVarArr;
        C2105d0[] c2105d0Arr = (C2105d0[]) Arrays.copyOf(this.f4474x, i3);
        c2105d0Arr[length] = c2105d0;
        this.f4474x = c2105d0Arr;
        return c2105d0;
    }

    /* renamed from: B */
    public final void m1757B() {
        a aVar = new a(this.f4456f, this.f4457g, this.f4466p, this, this.f4467q);
        if (this.f4439A) {
            d dVar = this.f4440B;
            Objects.requireNonNull(dVar);
            InterfaceC2050q interfaceC2050q = dVar.f4493a;
            C4195m.m4771I(m1779x());
            long j2 = this.f4447I;
            if (j2 != -9223372036854775807L && this.f4451M > j2) {
                this.f4454P = true;
                this.f4451M = -9223372036854775807L;
                return;
            }
            long j3 = interfaceC2050q.mo1463g(this.f4451M).f4188a.f4194c;
            long j4 = this.f4451M;
            aVar.f4482f.f4187a = j3;
            aVar.f4485i = j4;
            aVar.f4484h = true;
            aVar.f4489m = false;
            this.f4451M = -9223372036854775807L;
        }
        this.f4453O = m1777v();
        this.f4460j.m2038n(aVar.f4486j, 1, -1, null, 0, null, aVar.f4485i, this.f4447I, this.f4465o.m2186h(aVar, this, ((C2331w) this.f4459i).m2280b(this.f4442D)));
    }

    /* renamed from: C */
    public final boolean m1758C() {
        return this.f4444F || m1779x();
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i
    /* renamed from: a */
    public void mo1623a(InterfaceC2050q interfaceC2050q) {
        if (this.f4473w != null) {
            interfaceC2050q = new InterfaceC2050q.b(-9223372036854775807L, 0L);
        }
        this.f4472v = interfaceC2050q;
        this.f4470t.post(this.f4468r);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: b */
    public long mo1759b() {
        if (this.f4446H == 0) {
            return Long.MIN_VALUE;
        }
        return mo1763f();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: c */
    public boolean mo1760c(long j2) {
        if (this.f4454P || this.f4465o.m2182d() || this.f4452N) {
            return false;
        }
        if (this.f4439A && this.f4446H == 0) {
            return false;
        }
        boolean m2361a = this.f4467q.m2361a();
        if (this.f4465o.m2183e()) {
            return m2361a;
        }
        m1757B();
        return true;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: d */
    public boolean mo1761d() {
        boolean z;
        if (this.f4465o.m2183e()) {
            C2349i c2349i = this.f4467q;
            synchronized (c2349i) {
                z = c2349i.f6061a;
            }
            if (z) {
                return true;
            }
        }
        return false;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: e */
    public long mo1762e(long j2, C2400v0 c2400v0) {
        d dVar = this.f4440B;
        Objects.requireNonNull(dVar);
        InterfaceC2050q interfaceC2050q = dVar.f4493a;
        if (!interfaceC2050q.mo1462c()) {
            return 0L;
        }
        InterfaceC2050q.a mo1463g = interfaceC2050q.mo1463g(j2);
        return C2344d0.m2313E(j2, c2400v0, mo1463g.f4188a.f4193b, mo1463g.f4189b.f4193b);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: f */
    public long mo1763f() {
        long j2;
        boolean z;
        d dVar = this.f4440B;
        Objects.requireNonNull(dVar);
        boolean[] zArr = dVar.f4495c;
        if (this.f4454P) {
            return Long.MIN_VALUE;
        }
        if (m1779x()) {
            return this.f4451M;
        }
        if (this.f4441C) {
            int length = this.f4474x.length;
            j2 = Long.MAX_VALUE;
            for (int i2 = 0; i2 < length; i2++) {
                if (zArr[i2]) {
                    C2105d0 c2105d0 = this.f4474x[i2];
                    synchronized (c2105d0) {
                        z = c2105d0.f4564u;
                    }
                    if (!z) {
                        j2 = Math.min(j2, this.f4474x[i2].m1818n());
                    }
                }
            }
        } else {
            j2 = Long.MAX_VALUE;
        }
        if (j2 == Long.MAX_VALUE) {
            j2 = m1778w();
        }
        return j2 == Long.MIN_VALUE ? this.f4450L : j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: g */
    public void mo1764g(long j2) {
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.f
    /* renamed from: h */
    public void mo1765h() {
        for (C2105d0 c2105d0 : this.f4474x) {
            c2105d0.m1804B();
        }
        b bVar = this.f4466p;
        InterfaceC2041h interfaceC2041h = bVar.f4492b;
        if (interfaceC2041h != null) {
            interfaceC2041h.release();
            bVar.f4492b = null;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.C2105d0.b
    /* renamed from: i */
    public void mo1766i(Format format) {
        this.f4470t.post(this.f4468r);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: j */
    public long mo1767j(InterfaceC2257f[] interfaceC2257fArr, boolean[] zArr, InterfaceC2107e0[] interfaceC2107e0Arr, boolean[] zArr2, long j2) {
        d dVar = this.f4440B;
        Objects.requireNonNull(dVar);
        TrackGroupArray trackGroupArray = dVar.f4494b;
        boolean[] zArr3 = dVar.f4496d;
        int i2 = this.f4446H;
        int i3 = 0;
        for (int i4 = 0; i4 < interfaceC2257fArr.length; i4++) {
            if (interfaceC2107e0Arr[i4] != null && (interfaceC2257fArr[i4] == null || !zArr[i4])) {
                int i5 = ((e) interfaceC2107e0Arr[i4]).f4498c;
                C4195m.m4771I(zArr3[i5]);
                this.f4446H--;
                zArr3[i5] = false;
                interfaceC2107e0Arr[i4] = null;
            }
        }
        boolean z = !this.f4443E ? j2 == 0 : i2 != 0;
        for (int i6 = 0; i6 < interfaceC2257fArr.length; i6++) {
            if (interfaceC2107e0Arr[i6] == null && interfaceC2257fArr[i6] != null) {
                InterfaceC2257f interfaceC2257f = interfaceC2257fArr[i6];
                C4195m.m4771I(interfaceC2257f.length() == 1);
                C4195m.m4771I(interfaceC2257f.mo2153g(0) == 0);
                int m4060b = trackGroupArray.m4060b(interfaceC2257f.mo2149a());
                C4195m.m4771I(!zArr3[m4060b]);
                this.f4446H++;
                zArr3[m4060b] = true;
                interfaceC2107e0Arr[i6] = new e(m4060b);
                zArr2[i6] = true;
                if (!z) {
                    C2105d0 c2105d0 = this.f4474x[m4060b];
                    z = (c2105d0.m1807E(j2, true) || c2105d0.m1820p() == 0) ? false : true;
                }
            }
        }
        if (this.f4446H == 0) {
            this.f4452N = false;
            this.f4444F = false;
            if (this.f4465o.m2183e()) {
                C2105d0[] c2105d0Arr = this.f4474x;
                int length = c2105d0Arr.length;
                while (i3 < length) {
                    c2105d0Arr[i3].m1813i();
                    i3++;
                }
                this.f4465o.m2181b();
            } else {
                for (C2105d0 c2105d02 : this.f4474x) {
                    c2105d02.m1805C(false);
                }
            }
        } else if (z) {
            j2 = mo1771n(j2);
            while (i3 < interfaceC2107e0Arr.length) {
                if (interfaceC2107e0Arr[i3] != null) {
                    zArr2[i3] = true;
                }
                i3++;
            }
        }
        this.f4443E = true;
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: k */
    public void mo1768k(a aVar, long j2, long j3, boolean z) {
        a aVar2 = aVar;
        InterfaceC2203z.a aVar3 = this.f4460j;
        C2324p c2324p = aVar2.f4486j;
        C2287d0 c2287d0 = aVar2.f4478b;
        aVar3.m2029e(c2324p, c2287d0.f5798c, c2287d0.f5799d, 1, -1, null, 0, null, aVar2.f4485i, this.f4447I, j2, j3, c2287d0.f5797b);
        if (z) {
            return;
        }
        if (this.f4448J == -1) {
            this.f4448J = aVar2.f4487k;
        }
        for (C2105d0 c2105d0 : this.f4474x) {
            c2105d0.m1805C(false);
        }
        if (this.f4446H > 0) {
            InterfaceC2201x.a aVar4 = this.f4471u;
            Objects.requireNonNull(aVar4);
            aVar4.mo1421i(this);
        }
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: l */
    public void mo1769l(a aVar, long j2, long j3) {
        InterfaceC2050q interfaceC2050q;
        a aVar2 = aVar;
        if (this.f4447I == -9223372036854775807L && (interfaceC2050q = this.f4472v) != null) {
            boolean mo1462c = interfaceC2050q.mo1462c();
            long m1778w = m1778w();
            long j4 = m1778w == Long.MIN_VALUE ? 0L : m1778w + WorkRequest.MIN_BACKOFF_MILLIS;
            this.f4447I = j4;
            ((C2101b0) this.f4461k).m1795t(j4, mo1462c, this.f4449K);
        }
        InterfaceC2203z.a aVar3 = this.f4460j;
        C2324p c2324p = aVar2.f4486j;
        C2287d0 c2287d0 = aVar2.f4478b;
        aVar3.m2032h(c2324p, c2287d0.f5798c, c2287d0.f5799d, 1, -1, null, 0, null, aVar2.f4485i, this.f4447I, j2, j3, c2287d0.f5797b);
        if (this.f4448J == -1) {
            this.f4448J = aVar2.f4487k;
        }
        this.f4454P = true;
        InterfaceC2201x.a aVar4 = this.f4471u;
        Objects.requireNonNull(aVar4);
        aVar4.mo1421i(this);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: m */
    public void mo1770m() {
        this.f4465o.m2184f(((C2331w) this.f4459i).m2280b(this.f4442D));
        if (this.f4454P && !this.f4439A) {
            throw new C2205l0("Loading finished before preparation is complete.");
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: n */
    public long mo1771n(long j2) {
        boolean z;
        d dVar = this.f4440B;
        Objects.requireNonNull(dVar);
        InterfaceC2050q interfaceC2050q = dVar.f4493a;
        boolean[] zArr = dVar.f4495c;
        if (!interfaceC2050q.mo1462c()) {
            j2 = 0;
        }
        this.f4444F = false;
        this.f4450L = j2;
        if (m1779x()) {
            this.f4451M = j2;
            return j2;
        }
        if (this.f4442D != 7) {
            int length = this.f4474x.length;
            for (int i2 = 0; i2 < length; i2++) {
                if (!this.f4474x[i2].m1807E(j2, false) && (zArr[i2] || !this.f4441C)) {
                    z = false;
                    break;
                }
            }
            z = true;
            if (z) {
                return j2;
            }
        }
        this.f4452N = false;
        this.f4451M = j2;
        this.f4454P = false;
        if (this.f4465o.m2183e()) {
            this.f4465o.m2181b();
        } else {
            this.f4465o.f5771e = null;
            for (C2105d0 c2105d0 : this.f4474x) {
                c2105d0.m1805C(false);
            }
        }
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i
    /* renamed from: o */
    public void mo1624o() {
        this.f4476z = true;
        this.f4470t.post(this.f4468r);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: p */
    public long mo1772p() {
        if (!this.f4445G) {
            this.f4460j.m2043s();
            this.f4445G = true;
        }
        if (!this.f4444F) {
            return -9223372036854775807L;
        }
        if (!this.f4454P && m1777v() <= this.f4453O) {
            return -9223372036854775807L;
        }
        this.f4444F = false;
        return this.f4450L;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: q */
    public void mo1773q(InterfaceC2201x.a aVar, long j2) {
        this.f4471u = aVar;
        this.f4467q.m2361a();
        m1757B();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: r */
    public TrackGroupArray mo1774r() {
        d dVar = this.f4440B;
        Objects.requireNonNull(dVar);
        return dVar.f4494b;
    }

    /* JADX WARN: Removed duplicated region for block: B:25:0x0084  */
    /* JADX WARN: Removed duplicated region for block: B:26:0x0089  */
    @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
    /* renamed from: s */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p005b.p199l.p200a.p201a.p248o1.C2281a0.c mo1775s(p005b.p199l.p200a.p201a.p227k1.C2099a0.a r31, long r32, long r34, java.io.IOException r36, int r37) {
        /*
            r30 = this;
            r0 = r30
            r1 = r31
            b.l.a.a.k1.a0$a r1 = (p005b.p199l.p200a.p201a.p227k1.C2099a0.a) r1
            long r2 = r0.f4448J
            r4 = -1
            int r6 = (r2 > r4 ? 1 : (r2 == r4 ? 0 : -1))
            if (r6 != 0) goto L12
            long r2 = r1.f4487k
            r0.f4448J = r2
        L12:
            b.l.a.a.o1.z r2 = r0.f4459i
            int r7 = r0.f4442D
            r6 = r2
            b.l.a.a.o1.w r6 = (p005b.p199l.p200a.p201a.p248o1.C2331w) r6
            r8 = r34
            r10 = r36
            r11 = r37
            long r2 = r6.m2281c(r7, r8, r10, r11)
            r6 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            r8 = 1
            int r9 = (r2 > r6 ? 1 : (r2 == r6 ? 0 : -1))
            if (r9 != 0) goto L30
            b.l.a.a.o1.a0$c r2 = p005b.p199l.p200a.p201a.p248o1.C2281a0.f5768b
            goto L8b
        L30:
            int r9 = r30.m1777v()
            int r10 = r0.f4453O
            r11 = 0
            if (r9 <= r10) goto L3b
            r10 = 1
            goto L3c
        L3b:
            r10 = 0
        L3c:
            long r12 = r0.f4448J
            int r14 = (r12 > r4 ? 1 : (r12 == r4 ? 0 : -1))
            if (r14 != 0) goto L7f
            b.l.a.a.f1.q r4 = r0.f4472v
            if (r4 == 0) goto L4f
            long r4 = r4.mo1464i()
            int r12 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r12 == 0) goto L4f
            goto L7f
        L4f:
            boolean r4 = r0.f4439A
            if (r4 == 0) goto L5c
            boolean r4 = r30.m1758C()
            if (r4 != 0) goto L5c
            r0.f4452N = r8
            goto L82
        L5c:
            boolean r4 = r0.f4439A
            r0.f4444F = r4
            r4 = 0
            r0.f4450L = r4
            r0.f4453O = r11
            b.l.a.a.k1.d0[] r6 = r0.f4474x
            int r7 = r6.length
            r9 = 0
        L6a:
            if (r9 >= r7) goto L74
            r12 = r6[r9]
            r12.m1805C(r11)
            int r9 = r9 + 1
            goto L6a
        L74:
            b.l.a.a.f1.p r6 = r1.f4482f
            r6.f4187a = r4
            r1.f4485i = r4
            r1.f4484h = r8
            r1.f4489m = r11
            goto L81
        L7f:
            r0.f4453O = r9
        L81:
            r11 = 1
        L82:
            if (r11 == 0) goto L89
            b.l.a.a.o1.a0$c r2 = p005b.p199l.p200a.p201a.p248o1.C2281a0.m2179c(r10, r2)
            goto L8b
        L89:
            b.l.a.a.o1.a0$c r2 = p005b.p199l.p200a.p201a.p248o1.C2281a0.f5767a
        L8b:
            b.l.a.a.k1.z$a r9 = r0.f4460j
            b.l.a.a.o1.p r10 = r1.f4486j
            b.l.a.a.o1.d0 r3 = r1.f4478b
            android.net.Uri r11 = r3.f5798c
            java.util.Map<java.lang.String, java.util.List<java.lang.String>> r12 = r3.f5799d
            r13 = 1
            r16 = 0
            r17 = 0
            long r4 = r1.f4485i
            r18 = r4
            long r4 = r0.f4447I
            r20 = r4
            long r3 = r3.f5797b
            r26 = r3
            boolean r1 = r2.m2187a()
            r29 = r1 ^ 1
            r14 = -1
            r15 = 0
            r22 = r32
            r24 = r34
            r28 = r36
            r9.m2035k(r10, r11, r12, r13, r14, r15, r16, r17, r18, r20, r22, r24, r26, r28, r29)
            return r2
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.C2099a0.mo1775s(b.l.a.a.o1.a0$e, long, long, java.io.IOException, int):b.l.a.a.o1.a0$c");
    }

    @Override // p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i
    /* renamed from: t */
    public InterfaceC2052s mo1625t(int i2, int i3) {
        return m1756A(new f(i2, false));
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: u */
    public void mo1776u(long j2, boolean z) {
        if (m1779x()) {
            return;
        }
        d dVar = this.f4440B;
        Objects.requireNonNull(dVar);
        boolean[] zArr = dVar.f4496d;
        int length = this.f4474x.length;
        for (int i2 = 0; i2 < length; i2++) {
            this.f4474x[i2].m1812h(j2, z, zArr[i2]);
        }
    }

    /* renamed from: v */
    public final int m1777v() {
        int i2 = 0;
        for (C2105d0 c2105d0 : this.f4474x) {
            i2 += c2105d0.m1823s();
        }
        return i2;
    }

    /* renamed from: w */
    public final long m1778w() {
        long j2 = Long.MIN_VALUE;
        for (C2105d0 c2105d0 : this.f4474x) {
            j2 = Math.max(j2, c2105d0.m1818n());
        }
        return j2;
    }

    /* renamed from: x */
    public final boolean m1779x() {
        return this.f4451M != -9223372036854775807L;
    }

    /* renamed from: y */
    public final void m1780y(int i2) {
        d dVar = this.f4440B;
        Objects.requireNonNull(dVar);
        boolean[] zArr = dVar.f4497e;
        if (zArr[i2]) {
            return;
        }
        Format format = dVar.f4494b.f9398f[i2].f9394e[0];
        this.f4460j.m2026b(C2357q.m2543f(format.f9245l), format, 0, null, this.f4450L);
        zArr[i2] = true;
    }

    /* renamed from: z */
    public final void m1781z(int i2) {
        d dVar = this.f4440B;
        Objects.requireNonNull(dVar);
        boolean[] zArr = dVar.f4495c;
        if (this.f4452N && zArr[i2] && !this.f4474x[i2].m1825u(false)) {
            this.f4451M = 0L;
            this.f4452N = false;
            this.f4444F = true;
            this.f4450L = 0L;
            this.f4453O = 0;
            for (C2105d0 c2105d0 : this.f4474x) {
                c2105d0.m1805C(false);
            }
            InterfaceC2201x.a aVar = this.f4471u;
            Objects.requireNonNull(aVar);
            aVar.mo1421i(this);
        }
    }
}
