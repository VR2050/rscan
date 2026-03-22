package p005b.p199l.p200a.p201a.p227k1.p234n0;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import com.google.android.exoplayer2.drm.DrmInitData;
import com.google.android.exoplayer2.source.TrackGroup;
import com.google.android.exoplayer2.source.TrackGroupArray;
import java.util.ArrayList;
import java.util.Objects;
import p005b.p199l.p200a.p201a.C2400v0;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p227k1.C2195r;
import p005b.p199l.p200a.p201a.p227k1.C2196s;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2107e0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2203z;
import p005b.p199l.p200a.p201a.p227k1.p229k0.C2125g;
import p005b.p199l.p200a.p201a.p227k1.p234n0.InterfaceC2188c;
import p005b.p199l.p200a.p201a.p227k1.p234n0.p235e.C2190a;
import p005b.p199l.p200a.p201a.p245m1.InterfaceC2257f;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2283b0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2334z;

/* renamed from: b.l.a.a.k1.n0.d */
/* loaded from: classes.dex */
public final class C2189d implements InterfaceC2201x, InterfaceC2109f0.a<C2125g<InterfaceC2188c>> {

    /* renamed from: c */
    public final InterfaceC2188c.a f5141c;

    /* renamed from: e */
    @Nullable
    public final InterfaceC2291f0 f5142e;

    /* renamed from: f */
    public final InterfaceC2283b0 f5143f;

    /* renamed from: g */
    public final InterfaceC1954e<?> f5144g;

    /* renamed from: h */
    public final InterfaceC2334z f5145h;

    /* renamed from: i */
    public final InterfaceC2203z.a f5146i;

    /* renamed from: j */
    public final InterfaceC2288e f5147j;

    /* renamed from: k */
    public final TrackGroupArray f5148k;

    /* renamed from: l */
    public final C2196s f5149l;

    /* renamed from: m */
    @Nullable
    public InterfaceC2201x.a f5150m;

    /* renamed from: n */
    public C2190a f5151n;

    /* renamed from: o */
    public C2125g<InterfaceC2188c>[] f5152o;

    /* renamed from: p */
    public InterfaceC2109f0 f5153p;

    /* renamed from: q */
    public boolean f5154q;

    public C2189d(C2190a c2190a, InterfaceC2188c.a aVar, @Nullable InterfaceC2291f0 interfaceC2291f0, C2196s c2196s, InterfaceC1954e<?> interfaceC1954e, InterfaceC2334z interfaceC2334z, InterfaceC2203z.a aVar2, InterfaceC2283b0 interfaceC2283b0, InterfaceC2288e interfaceC2288e) {
        this.f5151n = c2190a;
        this.f5141c = aVar;
        this.f5142e = interfaceC2291f0;
        this.f5143f = interfaceC2283b0;
        this.f5144g = interfaceC1954e;
        this.f5145h = interfaceC2334z;
        this.f5146i = aVar2;
        this.f5147j = interfaceC2288e;
        this.f5149l = c2196s;
        TrackGroup[] trackGroupArr = new TrackGroup[c2190a.f5160f.length];
        int i2 = 0;
        while (true) {
            C2190a.b[] bVarArr = c2190a.f5160f;
            if (i2 >= bVarArr.length) {
                this.f5148k = new TrackGroupArray(trackGroupArr);
                C2125g<InterfaceC2188c>[] c2125gArr = new C2125g[0];
                this.f5152o = c2125gArr;
                Objects.requireNonNull(c2196s);
                this.f5153p = new C2195r(c2125gArr);
                aVar2.m2040p();
                return;
            }
            Format[] formatArr = bVarArr[i2].f5175j;
            Format[] formatArr2 = new Format[formatArr.length];
            for (int i3 = 0; i3 < formatArr.length; i3++) {
                Format format = formatArr[i3];
                DrmInitData drmInitData = format.f9248o;
                if (drmInitData != null) {
                    format = format.m4043e(interfaceC1954e.mo1442a(drmInitData));
                }
                formatArr2[i3] = format;
            }
            trackGroupArr[i2] = new TrackGroup(formatArr2);
            i2++;
        }
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: b */
    public long mo1759b() {
        return this.f5153p.mo1759b();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: c */
    public boolean mo1760c(long j2) {
        return this.f5153p.mo1760c(j2);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: d */
    public boolean mo1761d() {
        return this.f5153p.mo1761d();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: e */
    public long mo1762e(long j2, C2400v0 c2400v0) {
        for (C2125g<InterfaceC2188c> c2125g : this.f5152o) {
            if (c2125g.f4649c == 2) {
                return c2125g.f4653h.mo1856e(j2, c2400v0);
            }
        }
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: f */
    public long mo1763f() {
        return this.f5153p.mo1763f();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x, p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0
    /* renamed from: g */
    public void mo1764g(long j2) {
        this.f5153p.mo1764g(j2);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2109f0.a
    /* renamed from: i */
    public void mo1421i(C2125g<InterfaceC2188c> c2125g) {
        this.f5150m.mo1421i(this);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: j */
    public long mo1767j(InterfaceC2257f[] interfaceC2257fArr, boolean[] zArr, InterfaceC2107e0[] interfaceC2107e0Arr, boolean[] zArr2, long j2) {
        InterfaceC2257f[] interfaceC2257fArr2 = interfaceC2257fArr;
        ArrayList arrayList = new ArrayList();
        int i2 = 0;
        while (i2 < interfaceC2257fArr2.length) {
            if (interfaceC2107e0Arr[i2] != null) {
                C2125g c2125g = (C2125g) interfaceC2107e0Arr[i2];
                if (interfaceC2257fArr2[i2] == null || !zArr[i2]) {
                    c2125g.m1843A(null);
                    interfaceC2107e0Arr[i2] = null;
                } else {
                    ((InterfaceC2188c) c2125g.f4653h).mo2002b(interfaceC2257fArr2[i2]);
                    arrayList.add(c2125g);
                }
            }
            if (interfaceC2107e0Arr[i2] == null && interfaceC2257fArr2[i2] != null) {
                InterfaceC2257f interfaceC2257f = interfaceC2257fArr2[i2];
                int m4060b = this.f5148k.m4060b(interfaceC2257f.mo2149a());
                C2125g c2125g2 = new C2125g(this.f5151n.f5160f[m4060b].f5166a, null, null, this.f5141c.mo2004a(this.f5143f, this.f5151n, m4060b, interfaceC2257f, this.f5142e), this, this.f5147j, j2, this.f5144g, this.f5145h, this.f5146i);
                arrayList.add(c2125g2);
                interfaceC2107e0Arr[i2] = c2125g2;
                zArr2[i2] = true;
            }
            i2++;
            interfaceC2257fArr2 = interfaceC2257fArr;
        }
        C2125g<InterfaceC2188c>[] c2125gArr = new C2125g[arrayList.size()];
        this.f5152o = c2125gArr;
        arrayList.toArray(c2125gArr);
        C2196s c2196s = this.f5149l;
        C2125g<InterfaceC2188c>[] c2125gArr2 = this.f5152o;
        Objects.requireNonNull(c2196s);
        this.f5153p = new C2195r(c2125gArr2);
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: m */
    public void mo1770m() {
        this.f5143f.mo2180a();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: n */
    public long mo1771n(long j2) {
        for (C2125g<InterfaceC2188c> c2125g : this.f5152o) {
            c2125g.m1844B(j2);
        }
        return j2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: p */
    public long mo1772p() {
        if (this.f5154q) {
            return -9223372036854775807L;
        }
        this.f5146i.m2043s();
        this.f5154q = true;
        return -9223372036854775807L;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: q */
    public void mo1773q(InterfaceC2201x.a aVar, long j2) {
        this.f5150m = aVar;
        aVar.mo1423k(this);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: r */
    public TrackGroupArray mo1774r() {
        return this.f5148k;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2201x
    /* renamed from: u */
    public void mo1776u(long j2, boolean z) {
        for (C2125g<InterfaceC2188c> c2125g : this.f5152o) {
            c2125g.m1846u(j2, z);
        }
    }
}
