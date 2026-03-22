package p005b.p199l.p200a.p201a;

import androidx.annotation.CheckResult;
import androidx.annotation.Nullable;
import com.google.android.exoplayer2.source.TrackGroupArray;
import p005b.p199l.p200a.p201a.AbstractC2404x0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p245m1.C2260i;

/* renamed from: b.l.a.a.m0 */
/* loaded from: classes.dex */
public final class C2251m0 {

    /* renamed from: a */
    public static final InterfaceC2202y.a f5609a = new InterfaceC2202y.a(new Object());

    /* renamed from: b */
    public final AbstractC2404x0 f5610b;

    /* renamed from: c */
    public final InterfaceC2202y.a f5611c;

    /* renamed from: d */
    public final long f5612d;

    /* renamed from: e */
    public final long f5613e;

    /* renamed from: f */
    public final int f5614f;

    /* renamed from: g */
    @Nullable
    public final C1936b0 f5615g;

    /* renamed from: h */
    public final boolean f5616h;

    /* renamed from: i */
    public final TrackGroupArray f5617i;

    /* renamed from: j */
    public final C2260i f5618j;

    /* renamed from: k */
    public final InterfaceC2202y.a f5619k;

    /* renamed from: l */
    public volatile long f5620l;

    /* renamed from: m */
    public volatile long f5621m;

    /* renamed from: n */
    public volatile long f5622n;

    public C2251m0(AbstractC2404x0 abstractC2404x0, InterfaceC2202y.a aVar, long j2, long j3, int i2, @Nullable C1936b0 c1936b0, boolean z, TrackGroupArray trackGroupArray, C2260i c2260i, InterfaceC2202y.a aVar2, long j4, long j5, long j6) {
        this.f5610b = abstractC2404x0;
        this.f5611c = aVar;
        this.f5612d = j2;
        this.f5613e = j3;
        this.f5614f = i2;
        this.f5615g = c1936b0;
        this.f5616h = z;
        this.f5617i = trackGroupArray;
        this.f5618j = c2260i;
        this.f5619k = aVar2;
        this.f5620l = j4;
        this.f5621m = j5;
        this.f5622n = j6;
    }

    /* renamed from: d */
    public static C2251m0 m2139d(long j2, C2260i c2260i) {
        AbstractC2404x0 abstractC2404x0 = AbstractC2404x0.f6366a;
        InterfaceC2202y.a aVar = f5609a;
        return new C2251m0(abstractC2404x0, aVar, j2, -9223372036854775807L, 1, null, false, TrackGroupArray.f9396c, c2260i, aVar, j2, 0L, j2);
    }

    @CheckResult
    /* renamed from: a */
    public C2251m0 m2140a(InterfaceC2202y.a aVar, long j2, long j3, long j4) {
        return new C2251m0(this.f5610b, aVar, j2, aVar.m2024a() ? j3 : -9223372036854775807L, this.f5614f, this.f5615g, this.f5616h, this.f5617i, this.f5618j, this.f5619k, this.f5620l, j4, j2);
    }

    @CheckResult
    /* renamed from: b */
    public C2251m0 m2141b(@Nullable C1936b0 c1936b0) {
        return new C2251m0(this.f5610b, this.f5611c, this.f5612d, this.f5613e, this.f5614f, c1936b0, this.f5616h, this.f5617i, this.f5618j, this.f5619k, this.f5620l, this.f5621m, this.f5622n);
    }

    @CheckResult
    /* renamed from: c */
    public C2251m0 m2142c(TrackGroupArray trackGroupArray, C2260i c2260i) {
        return new C2251m0(this.f5610b, this.f5611c, this.f5612d, this.f5613e, this.f5614f, this.f5615g, this.f5616h, trackGroupArray, c2260i, this.f5619k, this.f5620l, this.f5621m, this.f5622n);
    }

    /* renamed from: e */
    public InterfaceC2202y.a m2143e(boolean z, AbstractC2404x0.c cVar, AbstractC2404x0.b bVar) {
        if (this.f5610b.m2691q()) {
            return f5609a;
        }
        int mo1926a = this.f5610b.mo1926a(z);
        int i2 = this.f5610b.m2690n(mo1926a, cVar).f6378g;
        int mo1831b = this.f5610b.mo1831b(this.f5611c.f5247a);
        long j2 = -1;
        if (mo1831b != -1 && mo1926a == this.f5610b.m2687f(mo1831b, bVar).f6368b) {
            j2 = this.f5611c.f5250d;
        }
        return new InterfaceC2202y.a(this.f5610b.mo1834m(i2), j2);
    }
}
