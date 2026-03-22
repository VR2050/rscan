package p005b.p199l.p200a.p201a.p227k1.p232m0;

import android.net.Uri;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import p005b.p199l.p200a.p201a.C2205l0;
import p005b.p199l.p200a.p201a.C2400v0;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p227k1.C2195r;
import p005b.p199l.p200a.p201a.p227k1.C2196s;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p227k1.p232m0.C2172o;
import p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.InterfaceC2184i;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2334z;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2357q;

/* renamed from: b.l.a.a.k1.m0.m */
/* loaded from: classes.dex */
public final class C2170m implements InterfaceC2201x, C2172o.a, InterfaceC2184i.b {

    /* renamed from: c */
    public final InterfaceC2167j f4919c;

    /* renamed from: e */
    public final InterfaceC2184i f4920e;

    /* renamed from: f */
    public final InterfaceC2166i f4921f;

    /* renamed from: g */
    @Nullable
    public final InterfaceC2291f0 f4922g;

    /* renamed from: h */
    public final InterfaceC1954e<?> f4923h;

    /* renamed from: i */
    public final InterfaceC2334z f4924i;

    /* renamed from: j */
    public final InterfaceC2203z.a f4925j;

    /* renamed from: k */
    public final InterfaceC2288e f4926k;

    /* renamed from: l */
    public final IdentityHashMap<InterfaceC2107e0, Integer> f4927l;

    /* renamed from: m */
    public final C2174q f4928m;

    /* renamed from: n */
    public final C2196s f4929n;

    /* renamed from: o */
    public final boolean f4930o;

    /* renamed from: p */
    public final int f4931p;

    /* renamed from: q */
    public final boolean f4932q;

    /* renamed from: r */
    @Nullable
    public InterfaceC2201x.a f4933r;

    /* renamed from: s */
    public int f4934s;

    /* renamed from: t */
    public TrackGroupArray f4935t;

    /* renamed from: u */
    public C2172o[] f4936u;

    /* renamed from: v */
    public C2172o[] f4937v;

    /* renamed from: w */
    public InterfaceC2109f0 f4938w;

    /* renamed from: x */
    public boolean f4939x;

    public C2170m(InterfaceC2167j interfaceC2167j, InterfaceC2184i interfaceC2184i, InterfaceC2166i interfaceC2166i, @Nullable InterfaceC2291f0 interfaceC2291f0, InterfaceC1954e<?> interfaceC1954e, InterfaceC2334z interfaceC2334z, InterfaceC2203z.a aVar, InterfaceC2288e interfaceC2288e, C2196s c2196s, boolean z, int i2, boolean z2) {
        this.f4919c = interfaceC2167j;
        this.f4920e = interfaceC2184i;
        this.f4921f = interfaceC2166i;
        this.f4922g = interfaceC2291f0;
        this.f4923h = interfaceC1954e;
        this.f4924i = interfaceC2334z;
        this.f4925j = aVar;
        this.f4926k = interfaceC2288e;
        this.f4929n = c2196s;
        this.f4930o = z;
        this.f4931p = i2;
        this.f4932q = z2;
        Objects.requireNonNull(c2196s);
        this.f4938w = new C2195r(new InterfaceC2109f0[0]);
        this.f4927l = new IdentityHashMap<>();
        this.f4928m = new C2174q();
        this.f4936u = new C2172o[0];
        this.f4937v = new C2172o[0];
        aVar.m2040p();
    }

    /* renamed from: o */
    public static Format m1948o(Format format, @Nullable Format format2, boolean z) {
        String str;
        String str2;
        String str3;
        Metadata metadata;
        int i2;
        int i3;
        int i4;
        if (format2 != null) {
            String str4 = format2.f9242i;
            Metadata metadata2 = format2.f9243j;
            int i5 = format2.f9258y;
            int i6 = format2.f9239f;
            int i7 = format2.f9240g;
            String str5 = format2.f9233D;
            str2 = format2.f9238e;
            str = str4;
            metadata = metadata2;
            i2 = i5;
            i3 = i6;
            i4 = i7;
            str3 = str5;
        } else {
            String m2334l = C2344d0.m2334l(format.f9242i, 1);
            Metadata metadata3 = format.f9243j;
            if (z) {
                int i8 = format.f9258y;
                str = m2334l;
                i2 = i8;
                i3 = format.f9239f;
                metadata = metadata3;
                i4 = format.f9240g;
                str3 = format.f9233D;
                str2 = format.f9238e;
            } else {
                str = m2334l;
                str2 = null;
                str3 = null;
                metadata = metadata3;
                i2 = -1;
                i3 = 0;
                i4 = 0;
            }
        }
        return Format.m4037x(format.f9237c, str2, format.f9244k, C2357q.m2540c(str), str, metadata, z ? format.f9241h : -1, i2, -1, null, i3, i4, str3);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.InterfaceC2184i.b
    /* renamed from: a */
    public void mo1949a() {
        this.f4933r.mo1421i(this);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: b */
    public long mo1759b() {
        return this.f4938w.mo1759b();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: c */
    public boolean mo1760c(long j2) {
        if (this.f4935t != null) {
            return this.f4938w.mo1760c(j2);
        }
        for (C2172o c2172o : this.f4936u) {
            if (!c2172o.f4948E) {
                c2172o.mo1760c(c2172o.f4960Q);
            }
        }
        return false;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: d */
    public boolean mo1761d() {
        return this.f4938w.mo1761d();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: e */
    public long mo1762e(long j2, C2400v0 c2400v0) {
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: f */
    public long mo1763f() {
        return this.f4938w.mo1763f();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: g */
    public void mo1764g(long j2) {
        this.f4938w.mo1764g(j2);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.p232m0.p233s.InterfaceC2184i.b
    /* renamed from: h */
    public boolean mo1950h(Uri uri, long j2) {
        boolean z;
        int mo2158q;
        boolean z2 = true;
        for (C2172o c2172o : this.f4936u) {
            C2165h c2165h = c2172o.f4971g;
            int i2 = 0;
            while (true) {
                Uri[] uriArr = c2165h.f4870e;
                if (i2 >= uriArr.length) {
                    i2 = -1;
                    break;
                }
                if (uriArr[i2].equals(uri)) {
                    break;
                }
                i2++;
            }
            if (i2 != -1 && (mo2158q = c2165h.f4881p.mo2158q(i2)) != -1) {
                c2165h.f4883r |= uri.equals(c2165h.f4879n);
                if (j2 != -9223372036854775807L && !c2165h.f4881p.mo2150c(mo2158q, j2)) {
                    z = false;
                    z2 &= z;
                }
            }
            z = true;
            z2 &= z;
        }
        this.f4933r.mo1421i(this);
        return z2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0.a
    /* renamed from: i */
    public void mo1421i(C2172o c2172o) {
        this.f4933r.mo1421i(this);
    }

    /* JADX WARN: Removed duplicated region for block: B:163:0x023e  */
    /* JADX WARN: Removed duplicated region for block: B:165:0x025f  */
    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: j */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long mo1767j(p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f[] r36, boolean[] r37, p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0[] r38, boolean[] r39, long r40) {
        /*
            Method dump skipped, instructions count: 821
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.p232m0.C2170m.mo1767j(b.l.a.a.m1.f[], boolean[], b.l.a.a.k1.e0[], boolean[], long):long");
    }

    /* renamed from: l */
    public final C2172o m1951l(int i2, Uri[] uriArr, Format[] formatArr, @Nullable Format format, @Nullable List<Format> list, Map<String, DrmInitData> map, long j2) {
        return new C2172o(i2, this, new C2165h(this.f4919c, this.f4920e, uriArr, formatArr, this.f4921f, this.f4922g, this.f4928m, list), map, this.f4926k, j2, format, this.f4923h, this.f4924i, this.f4925j, this.f4931p);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: m */
    public void mo1770m() {
        for (C2172o c2172o : this.f4936u) {
            c2172o.m1959C();
            if (c2172o.f4964U && !c2172o.f4948E) {
                throw new C2205l0("Loading finished before preparation is complete.");
            }
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: n */
    public long mo1771n(long j2) {
        C2172o[] c2172oArr = this.f4937v;
        if (c2172oArr.length > 0) {
            boolean m1962F = c2172oArr[0].m1962F(j2, false);
            int i2 = 1;
            while (true) {
                C2172o[] c2172oArr2 = this.f4937v;
                if (i2 >= c2172oArr2.length) {
                    break;
                }
                c2172oArr2[i2].m1962F(j2, m1962F);
                i2++;
            }
            if (m1962F) {
                this.f4928m.f5001a.clear();
            }
        }
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: p */
    public long mo1772p() {
        if (this.f4939x) {
            return -9223372036854775807L;
        }
        this.f4925j.m2043s();
        this.f4939x = true;
        return -9223372036854775807L;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:104:0x02d0  */
    /* JADX WARN: Removed duplicated region for block: B:134:0x0397 A[LOOP:8: B:132:0x0391->B:134:0x0397, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:138:0x040d  */
    /* JADX WARN: Removed duplicated region for block: B:58:0x0113  */
    /* JADX WARN: Type inference failed for: r4v0, types: [java.util.Map] */
    /* JADX WARN: Type inference failed for: r4v1 */
    /* JADX WARN: Type inference failed for: r4v25, types: [java.util.HashMap] */
    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: q */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo1773q(p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x.a r36, long r37) {
        /*
            Method dump skipped, instructions count: 1056
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p227k1.p232m0.C2170m.mo1773q(b.l.a.a.k1.x$a, long):void");
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: r */
    public TrackGroupArray mo1774r() {
        TrackGroupArray trackGroupArray = this.f4935t;
        Objects.requireNonNull(trackGroupArray);
        return trackGroupArray;
    }

    /* renamed from: s */
    public void m1952s() {
        int i2 = this.f4934s - 1;
        this.f4934s = i2;
        if (i2 > 0) {
            return;
        }
        int i3 = 0;
        for (C2172o c2172o : this.f4936u) {
            c2172o.m1964v();
            i3 += c2172o.f4953J.f9397e;
        }
        TrackGroup[] trackGroupArr = new TrackGroup[i3];
        int i4 = 0;
        for (C2172o c2172o2 : this.f4936u) {
            c2172o2.m1964v();
            int i5 = c2172o2.f4953J.f9397e;
            int i6 = 0;
            while (i6 < i5) {
                c2172o2.m1964v();
                trackGroupArr[i4] = c2172o2.f4953J.f9398f[i6];
                i6++;
                i4++;
            }
        }
        this.f4935t = new TrackGroupArray(trackGroupArr);
        this.f4933r.mo1423k(this);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: u */
    public void mo1776u(long j2, boolean z) {
        for (C2172o c2172o : this.f4937v) {
            if (c2172o.f4947D && !c2172o.m1957A()) {
                int length = c2172o.f4987w.length;
                for (int i2 = 0; i2 < length; i2++) {
                    c2172o.f4987w[i2].m1812h(j2, z, c2172o.f4958O[i2]);
                }
            }
        }
    }
}
