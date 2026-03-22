package p005b.p199l.p200a.p201a.p227k1.p232m0;

import android.net.Uri;
import android.os.SystemClock;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.source.TrackGroup;
import java.io.IOException;
import java.util.List;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2120b;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2122d;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2128j;
import p005b.p199l.p200a.p201a.p227k1.p229k0.AbstractC2130l;
import p005b.p199l.p200a.p201a.p227k1.p229k0.InterfaceC2131m;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2178c;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.C2180e;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.InterfaceC2184i;
import p005b.p199l.p200a.p201a.p245m1.AbstractC2253b;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p248o1.C2324p;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.k1.m0.h */
/* loaded from: classes.dex */
public class C2165h {

    /* renamed from: a */
    public final InterfaceC2167j f4866a;

    /* renamed from: b */
    public final InterfaceC2321m f4867b;

    /* renamed from: c */
    public final InterfaceC2321m f4868c;

    /* renamed from: d */
    public final C2174q f4869d;

    /* renamed from: e */
    public final Uri[] f4870e;

    /* renamed from: f */
    public final Format[] f4871f;

    /* renamed from: g */
    public final InterfaceC2184i f4872g;

    /* renamed from: h */
    public final TrackGroup f4873h;

    /* renamed from: i */
    @Nullable
    public final List<Format> f4874i;

    /* renamed from: k */
    public boolean f4876k;

    /* renamed from: m */
    @Nullable
    public IOException f4878m;

    /* renamed from: n */
    @Nullable
    public Uri f4879n;

    /* renamed from: o */
    public boolean f4880o;

    /* renamed from: p */
    public InterfaceC2257f f4881p;

    /* renamed from: r */
    public boolean f4883r;

    /* renamed from: j */
    public final C2164g f4875j = new C2164g(4);

    /* renamed from: l */
    public byte[] f4877l = C2344d0.f6040f;

    /* renamed from: q */
    public long f4882q = -9223372036854775807L;

    /* renamed from: b.l.a.a.k1.m0.h$a */
    public static final class a extends AbstractC2128j {

        /* renamed from: k */
        public byte[] f4884k;

        public a(InterfaceC2321m interfaceC2321m, C2324p c2324p, Format format, int i2, @Nullable Object obj, byte[] bArr) {
            super(interfaceC2321m, c2324p, 3, format, i2, obj, bArr);
        }
    }

    /* renamed from: b.l.a.a.k1.m0.h$b */
    public static final class b {

        /* renamed from: a */
        @Nullable
        public AbstractC2122d f4885a = null;

        /* renamed from: b */
        public boolean f4886b = false;

        /* renamed from: c */
        @Nullable
        public Uri f4887c = null;
    }

    /* renamed from: b.l.a.a.k1.m0.h$c */
    public static final class c extends AbstractC2120b {
        public c(C2180e c2180e, long j2, int i2) {
            super(i2, c2180e.f5070o.size() - 1);
        }
    }

    /* renamed from: b.l.a.a.k1.m0.h$d */
    public static final class d extends AbstractC2253b {

        /* renamed from: g */
        public int f4888g;

        public d(TrackGroup trackGroup, int[] iArr) {
            super(trackGroup, iArr);
            this.f4888g = mo2154i(trackGroup.f9394e[0]);
        }

        @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
        /* renamed from: b */
        public int mo1941b() {
            return this.f4888g;
        }

        @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
        /* renamed from: j */
        public void mo1942j(long j2, long j3, long j4, List<? extends AbstractC2130l> list, InterfaceC2131m[] interfaceC2131mArr) {
            long elapsedRealtime = SystemClock.elapsedRealtime();
            if (m2159r(this.f4888g, elapsedRealtime)) {
                for (int i2 = this.f5640b - 1; i2 >= 0; i2--) {
                    if (!m2159r(i2, elapsedRealtime)) {
                        this.f4888g = i2;
                        return;
                    }
                }
                throw new IllegalStateException();
            }
        }

        @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
        /* renamed from: m */
        public int mo1943m() {
            return 0;
        }

        @Override // p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f
        @Nullable
        /* renamed from: o */
        public Object mo1944o() {
            return null;
        }
    }

    public C2165h(InterfaceC2167j interfaceC2167j, InterfaceC2184i interfaceC2184i, Uri[] uriArr, Format[] formatArr, InterfaceC2166i interfaceC2166i, @Nullable InterfaceC2291f0 interfaceC2291f0, C2174q c2174q, @Nullable List<Format> list) {
        this.f4866a = interfaceC2167j;
        this.f4872g = interfaceC2184i;
        this.f4870e = uriArr;
        this.f4871f = formatArr;
        this.f4869d = c2174q;
        this.f4874i = list;
        InterfaceC2321m mo1933a = interfaceC2166i.mo1933a(1);
        this.f4867b = mo1933a;
        if (interfaceC2291f0 != null) {
            mo1933a.addTransferListener(interfaceC2291f0);
        }
        this.f4868c = interfaceC2166i.mo1933a(3);
        this.f4873h = new TrackGroup(formatArr);
        int[] iArr = new int[uriArr.length];
        for (int i2 = 0; i2 < uriArr.length; i2++) {
            iArr[i2] = i2;
        }
        this.f4881p = new d(this.f4873h, iArr);
    }

    /* renamed from: a */
    public InterfaceC2131m[] m1938a(@Nullable C2169l c2169l, long j2) {
        int m4059b = c2169l == null ? -1 : this.f4873h.m4059b(c2169l.f4625c);
        int length = this.f4881p.length();
        InterfaceC2131m[] interfaceC2131mArr = new InterfaceC2131m[length];
        for (int i2 = 0; i2 < length; i2++) {
            int mo2153g = this.f4881p.mo2153g(i2);
            Uri uri = this.f4870e[mo2153g];
            if (((C2178c) this.f4872g).m1971d(uri)) {
                C2180e m1970c = ((C2178c) this.f4872g).m1970c(uri, false);
                Objects.requireNonNull(m1970c);
                long j3 = m1970c.f5061f - ((C2178c) this.f4872g).f5027t;
                long m1939b = m1939b(c2169l, mo2153g != m4059b, m1970c, j3, j2);
                long j4 = m1970c.f5064i;
                if (m1939b < j4) {
                    interfaceC2131mArr[i2] = InterfaceC2131m.f4691a;
                } else {
                    interfaceC2131mArr[i2] = new c(m1970c, j3, (int) (m1939b - j4));
                }
            } else {
                interfaceC2131mArr[i2] = InterfaceC2131m.f4691a;
            }
        }
        return interfaceC2131mArr;
    }

    /* renamed from: b */
    public final long m1939b(@Nullable C2169l c2169l, boolean z, C2180e c2180e, long j2, long j3) {
        long m2325c;
        long j4;
        if (c2169l != null && !z) {
            return c2169l.mo1860c();
        }
        long j5 = c2180e.f5071p + j2;
        if (c2169l != null && !this.f4880o) {
            j3 = c2169l.f4628f;
        }
        if (c2180e.f5067l || j3 < j5) {
            m2325c = C2344d0.m2325c(c2180e.f5070o, Long.valueOf(j3 - j2), true, !((C2178c) this.f4872g).f5026s || c2169l == null);
            j4 = c2180e.f5064i;
        } else {
            m2325c = c2180e.f5064i;
            j4 = c2180e.f5070o.size();
        }
        return m2325c + j4;
    }

    @Nullable
    /* renamed from: c */
    public final AbstractC2122d m1940c(@Nullable Uri uri, int i2) {
        if (uri == null) {
            return null;
        }
        byte[] remove = this.f4875j.f4864a.remove(uri);
        if (remove != null) {
            this.f4875j.f4864a.put(uri, remove);
            return null;
        }
        return new a(this.f4868c, new C2324p(uri, 0L, 0L, -1L, null, 1), this.f4871f[i2], this.f4881p.mo1943m(), this.f4881p.mo1944o(), this.f4877l);
    }
}
