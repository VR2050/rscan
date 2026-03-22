package com.google.android.exoplayer2.source.dash;

import android.net.Uri;
import android.os.Handler;
import android.os.SystemClock;
import android.text.TextUtils;
import android.util.SparseArray;
import androidx.annotation.Nullable;
import androidx.work.WorkRequest;
import com.google.android.exoplayer2.source.dash.DashMediaSource;
import com.google.android.material.badge.BadgeDrawable;
import com.google.android.material.datepicker.UtcDates;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.C1960e0;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.C2399v;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p227k1.AbstractC2185n;
import p005b.p199l.p200a.p201a.p227k1.C2196s;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p227k1.p228j0.C2117a;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2125g;
import p005b.p199l.p200a.p201a.p227k1.p230l0.C2138e;
import p005b.p199l.p200a.p201a.p227k1.p230l0.C2141h;
import p005b.p199l.p200a.p201a.p227k1.p230l0.C2142i;
import p005b.p199l.p200a.p201a.p227k1.p230l0.C2143j;
import p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2136c;
import p005b.p199l.p200a.p201a.p227k1.p230l0.InterfaceC2139f;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2144a;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2145b;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2148e;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2149f;
import p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2156m;
import p005b.p199l.p200a.p201a.p248o1.C2281a0;
import p005b.p199l.p200a.p201a.p248o1.C2285c0;
import p005b.p199l.p200a.p201a.p248o1.C2287d0;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.C2331w;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2283b0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2334z;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* loaded from: classes.dex */
public final class DashMediaSource extends AbstractC2185n {

    /* renamed from: A */
    public InterfaceC2321m f9400A;

    /* renamed from: B */
    public C2281a0 f9401B;

    /* renamed from: C */
    @Nullable
    public InterfaceC2291f0 f9402C;

    /* renamed from: D */
    public IOException f9403D;

    /* renamed from: E */
    public Handler f9404E;

    /* renamed from: F */
    public Uri f9405F;

    /* renamed from: G */
    public Uri f9406G;

    /* renamed from: I */
    public boolean f9408I;

    /* renamed from: J */
    public long f9409J;

    /* renamed from: K */
    public long f9410K;

    /* renamed from: L */
    public long f9411L;

    /* renamed from: M */
    public int f9412M;

    /* renamed from: O */
    public int f9414O;

    /* renamed from: j */
    public final InterfaceC2321m.a f9416j;

    /* renamed from: k */
    public final InterfaceC2136c.a f9417k;

    /* renamed from: l */
    public final C2196s f9418l;

    /* renamed from: m */
    public final InterfaceC1954e<?> f9419m;

    /* renamed from: n */
    public final InterfaceC2334z f9420n;

    /* renamed from: o */
    public final long f9421o;

    /* renamed from: p */
    public final boolean f9422p;

    /* renamed from: r */
    public final C2285c0.a<? extends C2145b> f9424r;

    /* renamed from: H */
    public C2145b f9407H = null;

    /* renamed from: z */
    @Nullable
    public final Object f9432z = null;

    /* renamed from: i */
    public final boolean f9415i = false;

    /* renamed from: q */
    public final InterfaceC2203z.a f9423q = m1998j(null);

    /* renamed from: t */
    public final Object f9426t = new Object();

    /* renamed from: u */
    public final SparseArray<C2138e> f9427u = new SparseArray<>();

    /* renamed from: x */
    public final C2143j.b f9430x = new C3296c(null);

    /* renamed from: N */
    public long f9413N = -9223372036854775807L;

    /* renamed from: s */
    public final C3298e f9425s = new C3298e(null);

    /* renamed from: y */
    public final InterfaceC2283b0 f9431y = new C3299f();

    /* renamed from: v */
    public final Runnable f9428v = new Runnable() { // from class: b.l.a.a.k1.l0.a
        @Override // java.lang.Runnable
        public final void run() {
            DashMediaSource.this.m4064v();
        }
    };

    /* renamed from: w */
    public final Runnable f9429w = new Runnable() { // from class: b.l.a.a.k1.l0.b
        @Override // java.lang.Runnable
        public final void run() {
            DashMediaSource.this.m4062t(false);
        }
    };

    public static final class Factory {

        /* renamed from: a */
        public final InterfaceC2136c.a f9433a;

        /* renamed from: b */
        @Nullable
        public final InterfaceC2321m.a f9434b;

        /* renamed from: c */
        public InterfaceC1954e<?> f9435c;

        /* renamed from: d */
        @Nullable
        public C2285c0.a<? extends C2145b> f9436d;

        /* renamed from: e */
        public C2196s f9437e;

        /* renamed from: f */
        public InterfaceC2334z f9438f;

        /* renamed from: g */
        public long f9439g;

        public Factory(InterfaceC2321m.a aVar) {
            this(new C2141h.a(aVar), aVar);
        }

        public Factory(InterfaceC2136c.a aVar, @Nullable InterfaceC2321m.a aVar2) {
            this.f9433a = aVar;
            this.f9434b = aVar2;
            this.f9435c = InterfaceC1954e.f3383a;
            this.f9438f = new C2331w();
            this.f9439g = WorkRequest.DEFAULT_BACKOFF_DELAY_MILLIS;
            this.f9437e = new C2196s();
        }
    }

    /* renamed from: com.google.android.exoplayer2.source.dash.DashMediaSource$b */
    public static final class C3295b extends AbstractC2404x0 {

        /* renamed from: b */
        public final long f9440b;

        /* renamed from: c */
        public final long f9441c;

        /* renamed from: d */
        public final int f9442d;

        /* renamed from: e */
        public final long f9443e;

        /* renamed from: f */
        public final long f9444f;

        /* renamed from: g */
        public final long f9445g;

        /* renamed from: h */
        public final C2145b f9446h;

        /* renamed from: i */
        @Nullable
        public final Object f9447i;

        public C3295b(long j2, long j3, int i2, long j4, long j5, long j6, C2145b c2145b, @Nullable Object obj) {
            this.f9440b = j2;
            this.f9441c = j3;
            this.f9442d = i2;
            this.f9443e = j4;
            this.f9444f = j5;
            this.f9445g = j6;
            this.f9446h = c2145b;
            this.f9447i = obj;
        }

        /* renamed from: r */
        public static boolean m4065r(C2145b c2145b) {
            return c2145b.f4783d && c2145b.f4784e != -9223372036854775807L && c2145b.f4781b == -9223372036854775807L;
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: b */
        public int mo1831b(Object obj) {
            int intValue;
            if ((obj instanceof Integer) && (intValue = ((Integer) obj).intValue() - this.f9442d) >= 0 && intValue < mo1833i()) {
                return intValue;
            }
            return -1;
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: g */
        public AbstractC2404x0.b mo1832g(int i2, AbstractC2404x0.b bVar, boolean z) {
            C4195m.m4767G(i2, 0, mo1833i());
            if (z) {
                String str = this.f9446h.f4791l.get(i2).f4810a;
            }
            Integer valueOf = z ? Integer.valueOf(this.f9442d + i2) : null;
            long m2668a = C2399v.m2668a(this.f9446h.m1889c(i2));
            long m2668a2 = C2399v.m2668a(this.f9446h.f4791l.get(i2).f4811b - this.f9446h.m1887a(0).f4811b) - this.f9443e;
            Objects.requireNonNull(bVar);
            C2117a c2117a = C2117a.f4606a;
            bVar.f6367a = valueOf;
            bVar.f6368b = 0;
            bVar.f6369c = m2668a;
            bVar.f6370d = m2668a2;
            bVar.f6371e = c2117a;
            return bVar;
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: i */
        public int mo1833i() {
            return this.f9446h.m1888b();
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: m */
        public Object mo1834m(int i2) {
            C4195m.m4767G(i2, 0, mo1833i());
            return Integer.valueOf(this.f9442d + i2);
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: o */
        public AbstractC2404x0.c mo1835o(int i2, AbstractC2404x0.c cVar, long j2) {
            InterfaceC2139f mo1918i;
            C4195m.m4767G(i2, 0, 1);
            long j3 = this.f9445g;
            if (m4065r(this.f9446h)) {
                if (j2 > 0) {
                    j3 += j2;
                    if (j3 > this.f9444f) {
                        j3 = -9223372036854775807L;
                    }
                }
                long j4 = this.f9443e + j3;
                long m1890d = this.f9446h.m1890d(0);
                int i3 = 0;
                while (i3 < this.f9446h.m1888b() - 1 && j4 >= m1890d) {
                    j4 -= m1890d;
                    i3++;
                    m1890d = this.f9446h.m1890d(i3);
                }
                C2149f m1887a = this.f9446h.m1887a(i3);
                int size = m1887a.f4812c.size();
                int i4 = 0;
                while (true) {
                    if (i4 >= size) {
                        i4 = -1;
                        break;
                    }
                    if (m1887a.f4812c.get(i4).f4776b == 2) {
                        break;
                    }
                    i4++;
                }
                if (i4 != -1 && (mo1918i = m1887a.f4812c.get(i4).f4777c.get(0).mo1918i()) != null && mo1918i.mo1873g(m1890d) != 0) {
                    j3 = (mo1918i.mo1867a(mo1918i.mo1870d(j4, m1890d)) + j3) - j4;
                }
            }
            long j5 = j3;
            Object obj = AbstractC2404x0.c.f6372a;
            Object obj2 = this.f9447i;
            C2145b c2145b = this.f9446h;
            cVar.m2699b(obj, obj2, c2145b, this.f9440b, this.f9441c, true, m4065r(c2145b), this.f9446h.f4783d, j5, this.f9444f, 0, mo1833i() - 1, this.f9443e);
            return cVar;
        }

        @Override // p005b.p199l.p200a.p201a.AbstractC2404x0
        /* renamed from: p */
        public int mo1836p() {
            return 1;
        }
    }

    /* renamed from: com.google.android.exoplayer2.source.dash.DashMediaSource$c */
    public final class C3296c implements C2143j.b {
        public C3296c(C3294a c3294a) {
        }
    }

    /* renamed from: com.google.android.exoplayer2.source.dash.DashMediaSource$d */
    public static final class C3297d implements C2285c0.a<Long> {

        /* renamed from: a */
        public static final Pattern f9449a = Pattern.compile("(.+?)(Z|((\\+|-|−)(\\d\\d)(:?(\\d\\d))?))");

        @Override // p005b.p199l.p200a.p201a.p248o1.C2285c0.a
        /* renamed from: a */
        public Long mo1900a(Uri uri, InputStream inputStream) {
            String readLine = new BufferedReader(new InputStreamReader(inputStream, Charset.forName("UTF-8"))).readLine();
            try {
                Matcher matcher = f9449a.matcher(readLine);
                if (!matcher.matches()) {
                    throw new C2205l0("Couldn't parse timestamp: " + readLine);
                }
                String group = matcher.group(1);
                SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US);
                simpleDateFormat.setTimeZone(TimeZone.getTimeZone(UtcDates.UTC));
                long time = simpleDateFormat.parse(group).getTime();
                if (!"Z".equals(matcher.group(2))) {
                    long j2 = BadgeDrawable.DEFAULT_EXCEED_MAX_BADGE_NUMBER_SUFFIX.equals(matcher.group(4)) ? 1L : -1L;
                    long parseLong = Long.parseLong(matcher.group(5));
                    String group2 = matcher.group(7);
                    time -= ((((parseLong * 60) + (TextUtils.isEmpty(group2) ? 0L : Long.parseLong(group2))) * 60) * 1000) * j2;
                }
                return Long.valueOf(time);
            } catch (ParseException e2) {
                throw new C2205l0(e2);
            }
        }
    }

    /* renamed from: com.google.android.exoplayer2.source.dash.DashMediaSource$e */
    public final class C3298e implements C2281a0.b<C2285c0<C2145b>> {
        public C3298e(C3294a c3294a) {
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
        /* renamed from: k */
        public void mo1768k(C2285c0<C2145b> c2285c0, long j2, long j3, boolean z) {
            DashMediaSource.this.m4061r(c2285c0, j2, j3);
        }

        /* JADX WARN: Removed duplicated region for block: B:20:0x0071  */
        /* JADX WARN: Removed duplicated region for block: B:27:0x00a2  */
        @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
        /* renamed from: l */
        /*
            Code decompiled incorrectly, please refer to instructions dump.
            To view partially-correct add '--show-bad-code' argument
        */
        public void mo1769l(p005b.p199l.p200a.p201a.p248o1.C2285c0<p005b.p199l.p200a.p201a.p227k1.p230l0.p231k.C2145b> r19, long r20, long r22) {
            /*
                Method dump skipped, instructions count: 335
                To view this dump add '--comments-level debug' option
            */
            throw new UnsupportedOperationException("Method not decompiled: com.google.android.exoplayer2.source.dash.DashMediaSource.C3298e.mo1769l(b.l.a.a.o1.a0$e, long, long):void");
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
        /* renamed from: s */
        public C2281a0.c mo1775s(C2285c0<C2145b> c2285c0, long j2, long j3, IOException iOException, int i2) {
            C2285c0<C2145b> c2285c02 = c2285c0;
            DashMediaSource dashMediaSource = DashMediaSource.this;
            long m2281c = ((C2331w) dashMediaSource.f9420n).m2281c(4, j3, iOException, i2);
            C2281a0.c m2179c = m2281c == -9223372036854775807L ? C2281a0.f5768b : C2281a0.m2179c(false, m2281c);
            InterfaceC2203z.a aVar = dashMediaSource.f9423q;
            C2324p c2324p = c2285c02.f5789a;
            C2287d0 c2287d0 = c2285c02.f5791c;
            aVar.m2036l(c2324p, c2287d0.f5798c, c2287d0.f5799d, c2285c02.f5790b, j2, j3, c2287d0.f5797b, iOException, !m2179c.m2187a());
            return m2179c;
        }
    }

    /* renamed from: com.google.android.exoplayer2.source.dash.DashMediaSource$f */
    public final class C3299f implements InterfaceC2283b0 {
        public C3299f() {
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.InterfaceC2283b0
        /* renamed from: a */
        public void mo2180a() {
            DashMediaSource.this.f9401B.m2184f(Integer.MIN_VALUE);
            IOException iOException = DashMediaSource.this.f9403D;
            if (iOException != null) {
                throw iOException;
            }
        }
    }

    /* renamed from: com.google.android.exoplayer2.source.dash.DashMediaSource$g */
    public static final class C3300g {

        /* renamed from: a */
        public final boolean f9452a;

        /* renamed from: b */
        public final long f9453b;

        /* renamed from: c */
        public final long f9454c;

        public C3300g(boolean z, long j2, long j3) {
            this.f9452a = z;
            this.f9453b = j2;
            this.f9454c = j3;
        }

        /* renamed from: a */
        public static C3300g m4066a(C2149f c2149f, long j2) {
            boolean z;
            boolean z2;
            int i2;
            int size = c2149f.f4812c.size();
            int i3 = 0;
            for (int i4 = 0; i4 < size; i4++) {
                int i5 = c2149f.f4812c.get(i4).f4776b;
                if (i5 == 1 || i5 == 2) {
                    z = true;
                    break;
                }
            }
            z = false;
            long j3 = Long.MAX_VALUE;
            int i6 = 0;
            boolean z3 = false;
            long j4 = 0;
            boolean z4 = false;
            while (i6 < size) {
                C2144a c2144a = c2149f.f4812c.get(i6);
                if (!z || c2144a.f4776b != 3) {
                    InterfaceC2139f mo1918i = c2144a.f4777c.get(i3).mo1918i();
                    if (mo1918i == null) {
                        return new C3300g(true, 0L, j2);
                    }
                    z3 |= mo1918i.mo1871e();
                    int mo1873g = mo1918i.mo1873g(j2);
                    if (mo1873g == 0) {
                        z2 = z;
                        i2 = i6;
                        j3 = 0;
                        j4 = 0;
                        z4 = true;
                    } else if (!z4) {
                        z2 = z;
                        long mo1872f = mo1918i.mo1872f();
                        i2 = i6;
                        j4 = Math.max(j4, mo1918i.mo1867a(mo1872f));
                        if (mo1873g != -1) {
                            long j5 = (mo1872f + mo1873g) - 1;
                            j3 = Math.min(j3, mo1918i.mo1868b(j5, j2) + mo1918i.mo1867a(j5));
                        }
                    }
                    i6 = i2 + 1;
                    z = z2;
                    i3 = 0;
                }
                z2 = z;
                i2 = i6;
                i6 = i2 + 1;
                z = z2;
                i3 = 0;
            }
            return new C3300g(z3, j4, j3);
        }
    }

    /* renamed from: com.google.android.exoplayer2.source.dash.DashMediaSource$h */
    public final class C3301h implements C2281a0.b<C2285c0<Long>> {
        public C3301h(C3294a c3294a) {
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
        /* renamed from: k */
        public void mo1768k(C2285c0<Long> c2285c0, long j2, long j3, boolean z) {
            DashMediaSource.this.m4061r(c2285c0, j2, j3);
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
        /* renamed from: l */
        public void mo1769l(C2285c0<Long> c2285c0, long j2, long j3) {
            C2285c0<Long> c2285c02 = c2285c0;
            DashMediaSource dashMediaSource = DashMediaSource.this;
            InterfaceC2203z.a aVar = dashMediaSource.f9423q;
            C2324p c2324p = c2285c02.f5789a;
            C2287d0 c2287d0 = c2285c02.f5791c;
            aVar.m2033i(c2324p, c2287d0.f5798c, c2287d0.f5799d, c2285c02.f5790b, j2, j3, c2287d0.f5797b);
            dashMediaSource.f9411L = c2285c02.f5793e.longValue() - j2;
            dashMediaSource.m4062t(true);
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.C2281a0.b
        /* renamed from: s */
        public C2281a0.c mo1775s(C2285c0<Long> c2285c0, long j2, long j3, IOException iOException, int i2) {
            C2285c0<Long> c2285c02 = c2285c0;
            DashMediaSource dashMediaSource = DashMediaSource.this;
            InterfaceC2203z.a aVar = dashMediaSource.f9423q;
            C2324p c2324p = c2285c02.f5789a;
            C2287d0 c2287d0 = c2285c02.f5791c;
            aVar.m2036l(c2324p, c2287d0.f5798c, c2287d0.f5799d, c2285c02.f5790b, j2, j3, c2287d0.f5797b, iOException, true);
            dashMediaSource.m4062t(true);
            return C2281a0.f5767a;
        }
    }

    /* renamed from: com.google.android.exoplayer2.source.dash.DashMediaSource$i */
    public static final class C3302i implements C2285c0.a<Long> {
        public C3302i(C3294a c3294a) {
        }

        @Override // p005b.p199l.p200a.p201a.p248o1.C2285c0.a
        /* renamed from: a */
        public Long mo1900a(Uri uri, InputStream inputStream) {
            return Long.valueOf(C2344d0.m2311C(new BufferedReader(new InputStreamReader(inputStream)).readLine()));
        }
    }

    static {
        C1960e0.m1454a("goog.exo.dash");
    }

    public DashMediaSource(C2145b c2145b, Uri uri, InterfaceC2321m.a aVar, C2285c0.a aVar2, InterfaceC2136c.a aVar3, C2196s c2196s, InterfaceC1954e interfaceC1954e, InterfaceC2334z interfaceC2334z, long j2, boolean z, Object obj, C3294a c3294a) {
        this.f9405F = uri;
        this.f9406G = uri;
        this.f9416j = aVar;
        this.f9424r = aVar2;
        this.f9417k = aVar3;
        this.f9419m = interfaceC1954e;
        this.f9420n = interfaceC2334z;
        this.f9421o = j2;
        this.f9422p = z;
        this.f9418l = c2196s;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: a */
    public InterfaceC2201x mo1789a(InterfaceC2202y.a aVar, InterfaceC2288e interfaceC2288e, long j2) {
        int intValue = ((Integer) aVar.f5247a).intValue() - this.f9414O;
        long j3 = this.f9407H.m1887a(intValue).f4811b;
        C4195m.m4765F(true);
        InterfaceC2203z.a m2045u = this.f5128f.m2045u(0, aVar, j3);
        int i2 = this.f9414O + intValue;
        C2138e c2138e = new C2138e(i2, this.f9407H, intValue, this.f9417k, this.f9402C, this.f9419m, this.f9420n, m2045u, this.f9411L, this.f9431y, interfaceC2288e, this.f9418l, this.f9430x);
        this.f9427u.put(i2, c2138e);
        return c2138e;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: f */
    public void mo1790f() {
        this.f9431y.mo2180a();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: g */
    public void mo1791g(InterfaceC2201x interfaceC2201x) {
        C2138e c2138e = (C2138e) interfaceC2201x;
        C2143j c2143j = c2138e.f4711p;
        c2143j.f4768n = true;
        c2143j.f4761g.removeCallbacksAndMessages(null);
        for (C2125g<InterfaceC2136c> c2125g : c2138e.f4715t) {
            c2125g.m1843A(c2138e);
        }
        c2138e.f4714s = null;
        c2138e.f4713r.m2041q();
        this.f9427u.remove(c2138e.f4700e);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.AbstractC2185n
    /* renamed from: o */
    public void mo1792o(@Nullable InterfaceC2291f0 interfaceC2291f0) {
        this.f9402C = interfaceC2291f0;
        this.f9419m.mo1443b();
        if (this.f9415i) {
            m4062t(false);
            return;
        }
        this.f9400A = this.f9416j.createDataSource();
        this.f9401B = new C2281a0("Loader:DashMediaSource");
        this.f9404E = new Handler();
        m4064v();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.AbstractC2185n
    /* renamed from: q */
    public void mo1793q() {
        this.f9408I = false;
        this.f9400A = null;
        C2281a0 c2281a0 = this.f9401B;
        if (c2281a0 != null) {
            c2281a0.m2185g(null);
            this.f9401B = null;
        }
        this.f9409J = 0L;
        this.f9410K = 0L;
        this.f9407H = this.f9415i ? this.f9407H : null;
        this.f9406G = this.f9405F;
        this.f9403D = null;
        Handler handler = this.f9404E;
        if (handler != null) {
            handler.removeCallbacksAndMessages(null);
            this.f9404E = null;
        }
        this.f9411L = 0L;
        this.f9412M = 0;
        this.f9413N = -9223372036854775807L;
        this.f9414O = 0;
        this.f9427u.clear();
        this.f9419m.release();
    }

    /* renamed from: r */
    public void m4061r(C2285c0<?> c2285c0, long j2, long j3) {
        InterfaceC2203z.a aVar = this.f9423q;
        C2324p c2324p = c2285c0.f5789a;
        C2287d0 c2287d0 = c2285c0.f5791c;
        aVar.m2030f(c2324p, c2287d0.f5798c, c2287d0.f5799d, c2285c0.f5790b, j2, j3, c2287d0.f5797b);
    }

    /* renamed from: t */
    public final void m4062t(boolean z) {
        long j2;
        boolean z2;
        long j3;
        for (int i2 = 0; i2 < this.f9427u.size(); i2++) {
            int keyAt = this.f9427u.keyAt(i2);
            if (keyAt >= this.f9414O) {
                C2138e valueAt = this.f9427u.valueAt(i2);
                C2145b c2145b = this.f9407H;
                int i3 = keyAt - this.f9414O;
                valueAt.f4718w = c2145b;
                valueAt.f4719x = i3;
                C2143j c2143j = valueAt.f4711p;
                c2143j.f4767m = false;
                c2143j.f4764j = -9223372036854775807L;
                c2143j.f4763i = c2145b;
                Iterator<Map.Entry<Long, Long>> it = c2143j.f4762h.entrySet().iterator();
                while (it.hasNext()) {
                    if (it.next().getKey().longValue() < c2143j.f4763i.f4787h) {
                        it.remove();
                    }
                }
                C2125g<InterfaceC2136c>[] c2125gArr = valueAt.f4715t;
                if (c2125gArr != null) {
                    for (C2125g<InterfaceC2136c> c2125g : c2125gArr) {
                        c2125g.f4653h.mo1863f(c2145b, i3);
                    }
                    valueAt.f4714s.mo1421i(valueAt);
                }
                valueAt.f4720y = c2145b.f4791l.get(i3).f4813d;
                for (C2142i c2142i : valueAt.f4716u) {
                    Iterator<C2148e> it2 = valueAt.f4720y.iterator();
                    while (true) {
                        if (it2.hasNext()) {
                            C2148e next = it2.next();
                            if (next.m1914a().equals(c2142i.f4754h.m1914a())) {
                                c2142i.m1885c(next, c2145b.f4783d && i3 == c2145b.m1888b() - 1);
                            }
                        }
                    }
                }
            }
        }
        int m1888b = this.f9407H.m1888b() - 1;
        C3300g m4066a = C3300g.m4066a(this.f9407H.m1887a(0), this.f9407H.m1890d(0));
        C3300g m4066a2 = C3300g.m4066a(this.f9407H.m1887a(m1888b), this.f9407H.m1890d(m1888b));
        long j4 = m4066a.f9453b;
        long j5 = m4066a2.f9454c;
        if (!this.f9407H.f4783d || m4066a2.f9452a) {
            j2 = j4;
            z2 = false;
        } else {
            j5 = Math.min(((this.f9411L != 0 ? C2399v.m2668a(SystemClock.elapsedRealtime() + this.f9411L) : C2399v.m2668a(System.currentTimeMillis())) - C2399v.m2668a(this.f9407H.f4780a)) - C2399v.m2668a(this.f9407H.m1887a(m1888b).f4811b), j5);
            long j6 = this.f9407H.f4785f;
            if (j6 != -9223372036854775807L) {
                long m2668a = j5 - C2399v.m2668a(j6);
                while (m2668a < 0 && m1888b > 0) {
                    m1888b--;
                    m2668a += this.f9407H.m1890d(m1888b);
                }
                j4 = m1888b == 0 ? Math.max(j4, m2668a) : this.f9407H.m1890d(0);
            }
            j2 = j4;
            z2 = true;
        }
        long j7 = j5 - j2;
        for (int i4 = 0; i4 < this.f9407H.m1888b() - 1; i4++) {
            j7 = this.f9407H.m1890d(i4) + j7;
        }
        C2145b c2145b2 = this.f9407H;
        if (c2145b2.f4783d) {
            long j8 = this.f9421o;
            if (!this.f9422p) {
                long j9 = c2145b2.f4786g;
                if (j9 != -9223372036854775807L) {
                    j8 = j9;
                }
            }
            long m2668a2 = j7 - C2399v.m2668a(j8);
            if (m2668a2 < 5000000) {
                m2668a2 = Math.min(5000000L, j7 / 2);
            }
            j3 = m2668a2;
        } else {
            j3 = 0;
        }
        C2145b c2145b3 = this.f9407H;
        long j10 = c2145b3.f4780a;
        long m2669b = j10 != -9223372036854775807L ? C2399v.m2669b(j2) + j10 + c2145b3.m1887a(0).f4811b : -9223372036854775807L;
        C2145b c2145b4 = this.f9407H;
        m2001p(new C3295b(c2145b4.f4780a, m2669b, this.f9414O, j2, j7, j3, c2145b4, this.f9432z));
        if (this.f9415i) {
            return;
        }
        this.f9404E.removeCallbacks(this.f9429w);
        if (z2) {
            this.f9404E.postDelayed(this.f9429w, 5000L);
        }
        if (this.f9408I) {
            m4064v();
            return;
        }
        if (z) {
            C2145b c2145b5 = this.f9407H;
            if (c2145b5.f4783d) {
                long j11 = c2145b5.f4784e;
                if (j11 != -9223372036854775807L) {
                    this.f9404E.postDelayed(this.f9428v, Math.max(0L, (this.f9409J + (j11 != 0 ? j11 : 5000L)) - SystemClock.elapsedRealtime()));
                }
            }
        }
    }

    /* renamed from: u */
    public final void m4063u(C2156m c2156m, C2285c0.a<Long> aVar) {
        C2285c0 c2285c0 = new C2285c0(this.f9400A, Uri.parse(c2156m.f4852b), 5, aVar);
        this.f9423q.m2039o(c2285c0.f5789a, c2285c0.f5790b, this.f9401B.m2186h(c2285c0, new C3301h(null), 1));
    }

    /* renamed from: v */
    public final void m4064v() {
        Uri uri;
        this.f9404E.removeCallbacks(this.f9428v);
        if (this.f9401B.m2182d()) {
            return;
        }
        if (this.f9401B.m2183e()) {
            this.f9408I = true;
            return;
        }
        synchronized (this.f9426t) {
            uri = this.f9406G;
        }
        this.f9408I = false;
        C2285c0 c2285c0 = new C2285c0(this.f9400A, uri, 4, this.f9424r);
        this.f9423q.m2039o(c2285c0.f5789a, c2285c0.f5790b, this.f9401B.m2186h(c2285c0, this.f9425s, ((C2331w) this.f9420n).m2280b(4)));
    }
}
