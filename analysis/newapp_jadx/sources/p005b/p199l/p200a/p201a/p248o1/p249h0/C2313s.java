package p005b.p199l.p200a.p201a.p248o1.p249h0;

import java.util.Comparator;
import java.util.TreeSet;
import p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: b.l.a.a.o1.h0.s */
/* loaded from: classes.dex */
public final class C2313s implements InterfaceC2302h {

    /* renamed from: a */
    public final TreeSet<C2305k> f5898a = new TreeSet<>(new Comparator() { // from class: b.l.a.a.o1.h0.b
        @Override // java.util.Comparator
        public final int compare(Object obj, Object obj2) {
            C2305k c2305k = (C2305k) obj;
            C2305k c2305k2 = (C2305k) obj2;
            long j2 = c2305k.f5868i;
            long j3 = c2305k2.f5868i;
            return j2 - j3 == 0 ? c2305k.compareTo(c2305k2) : j2 < j3 ? -1 : 1;
        }
    });

    /* renamed from: b */
    public long f5899b;

    public C2313s(long j2) {
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c.b
    /* renamed from: a */
    public void mo2212a(InterfaceC2297c interfaceC2297c, C2305k c2305k) {
        this.f5898a.remove(c2305k);
        this.f5899b -= c2305k.f5865f;
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c.b
    /* renamed from: b */
    public void mo2213b(InterfaceC2297c interfaceC2297c, C2305k c2305k, C2305k c2305k2) {
        this.f5898a.remove(c2305k);
        this.f5899b -= c2305k.f5865f;
        mo2214c(interfaceC2297c, c2305k2);
    }

    @Override // p005b.p199l.p200a.p201a.p248o1.p249h0.InterfaceC2297c.b
    /* renamed from: c */
    public void mo2214c(InterfaceC2297c interfaceC2297c, C2305k c2305k) {
        this.f5898a.add(c2305k);
        this.f5899b += c2305k.f5865f;
        m2253d(interfaceC2297c, 0L);
    }

    /* renamed from: d */
    public final void m2253d(InterfaceC2297c interfaceC2297c, long j2) {
        while (this.f5899b + j2 > IjkMediaMeta.AV_CH_STEREO_LEFT && !this.f5898a.isEmpty()) {
            try {
                interfaceC2297c.mo2203d(this.f5898a.first());
            } catch (InterfaceC2297c.a unused) {
            }
        }
    }
}
