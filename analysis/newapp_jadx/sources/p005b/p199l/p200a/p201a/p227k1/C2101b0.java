package p005b.p199l.p200a.p201a.p227k1;

import android.net.Uri;
import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p205d1.InterfaceC1954e;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2043j;
import p005b.p199l.p200a.p201a.p227k1.C2099a0;
import p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2288e;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2291f0;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2321m;
import p005b.p199l.p200a.p201a.p248o1.InterfaceC2334z;

/* renamed from: b.l.a.a.k1.b0 */
/* loaded from: classes.dex */
public final class C2101b0 extends AbstractC2185n implements C2099a0.c {

    /* renamed from: i */
    public final Uri f4506i;

    /* renamed from: j */
    public final InterfaceC2321m.a f4507j;

    /* renamed from: k */
    public final InterfaceC2043j f4508k;

    /* renamed from: l */
    public final InterfaceC1954e<?> f4509l;

    /* renamed from: m */
    public final InterfaceC2334z f4510m;

    /* renamed from: o */
    public final int f4512o;

    /* renamed from: r */
    public boolean f4515r;

    /* renamed from: s */
    public boolean f4516s;

    /* renamed from: t */
    @Nullable
    public InterfaceC2291f0 f4517t;

    /* renamed from: n */
    @Nullable
    public final String f4511n = null;

    /* renamed from: q */
    public long f4514q = -9223372036854775807L;

    /* renamed from: p */
    @Nullable
    public final Object f4513p = null;

    public C2101b0(Uri uri, InterfaceC2321m.a aVar, InterfaceC2043j interfaceC2043j, InterfaceC1954e<?> interfaceC1954e, InterfaceC2334z interfaceC2334z, @Nullable String str, int i2, @Nullable Object obj) {
        this.f4506i = uri;
        this.f4507j = aVar;
        this.f4508k = interfaceC2043j;
        this.f4509l = interfaceC1954e;
        this.f4510m = interfaceC2334z;
        this.f4512o = i2;
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: a */
    public InterfaceC2201x mo1789a(InterfaceC2202y.a aVar, InterfaceC2288e interfaceC2288e, long j2) {
        InterfaceC2321m createDataSource = this.f4507j.createDataSource();
        InterfaceC2291f0 interfaceC2291f0 = this.f4517t;
        if (interfaceC2291f0 != null) {
            createDataSource.addTransferListener(interfaceC2291f0);
        }
        return new C2099a0(this.f4506i, createDataSource, this.f4508k.mo1571a(), this.f4509l, this.f4510m, this.f5128f.m2045u(0, aVar, 0L), this, interfaceC2288e, this.f4511n, this.f4512o);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: f */
    public void mo1790f() {
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.InterfaceC2202y
    /* renamed from: g */
    public void mo1791g(InterfaceC2201x interfaceC2201x) {
        C2099a0 c2099a0 = (C2099a0) interfaceC2201x;
        if (c2099a0.f4439A) {
            for (C2105d0 c2105d0 : c2099a0.f4474x) {
                c2105d0.m1830z();
            }
        }
        c2099a0.f4465o.m2185g(c2099a0);
        c2099a0.f4470t.removeCallbacksAndMessages(null);
        c2099a0.f4471u = null;
        c2099a0.f4455Q = true;
        c2099a0.f4460j.m2041q();
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.AbstractC2185n
    /* renamed from: o */
    public void mo1792o(@Nullable InterfaceC2291f0 interfaceC2291f0) {
        this.f4517t = interfaceC2291f0;
        this.f4509l.mo1443b();
        m1794r(this.f4514q, this.f4515r, this.f4516s);
    }

    @Override // p005b.p199l.p200a.p201a.p227k1.AbstractC2185n
    /* renamed from: q */
    public void mo1793q() {
        this.f4509l.release();
    }

    /* renamed from: r */
    public final void m1794r(long j2, boolean z, boolean z2) {
        this.f4514q = j2;
        this.f4515r = z;
        this.f4516s = z2;
        long j3 = this.f4514q;
        m2001p(new C2113h0(j3, j3, 0L, 0L, this.f4515r, false, this.f4516s, null, this.f4513p));
    }

    /* renamed from: t */
    public void m1795t(long j2, boolean z, boolean z2) {
        if (j2 == -9223372036854775807L) {
            j2 = this.f4514q;
        }
        if (this.f4514q == j2 && this.f4515r == z && this.f4516s == z2) {
            return;
        }
        m1794r(j2, z, z2);
    }
}
