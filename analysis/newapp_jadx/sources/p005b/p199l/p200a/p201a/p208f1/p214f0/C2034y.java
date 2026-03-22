package p005b.p199l.p200a.p201a.p208f1.p214f0;

import com.google.android.exoplayer2.Format;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2042i;
import p005b.p199l.p200a.p201a.p208f1.InterfaceC2052s;
import p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2011c0;
import p005b.p199l.p200a.p201a.p250p1.C2342c0;

/* renamed from: b.l.a.a.f1.f0.y */
/* loaded from: classes.dex */
public final class C2034y implements InterfaceC2031v {

    /* renamed from: a */
    public C2342c0 f4120a;

    /* renamed from: b */
    public InterfaceC2052s f4121b;

    /* renamed from: c */
    public boolean f4122c;

    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2031v
    /* renamed from: a */
    public void mo1578a(C2342c0 c2342c0, InterfaceC2042i interfaceC2042i, InterfaceC2011c0.d dVar) {
        this.f4120a = c2342c0;
        dVar.m1584a();
        InterfaceC2052s mo1625t = interfaceC2042i.mo1625t(dVar.m1586c(), 4);
        this.f4121b = mo1625t;
        mo1625t.mo1615d(Format.m4028E(dVar.m1585b(), "application/x-scte35", null, -1, null));
    }

    /* JADX WARN: Code restructure failed: missing block: B:15:0x004c, code lost:
    
        if (r4 != Long.MAX_VALUE) goto L15;
     */
    @Override // p005b.p199l.p200a.p201a.p208f1.p214f0.InterfaceC2031v
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo1579b(p005b.p199l.p200a.p201a.p250p1.C2360t r11) {
        /*
            r10 = this;
            boolean r0 = r10.f4122c
            r1 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            if (r0 != 0) goto L29
            b.l.a.a.p1.c0 r0 = r10.f4120a
            long r3 = r0.m2307c()
            int r0 = (r3 > r1 ? 1 : (r3 == r1 ? 0 : -1))
            if (r0 != 0) goto L14
            return
        L14:
            b.l.a.a.f1.s r0 = r10.f4121b
            r3 = 0
            b.l.a.a.p1.c0 r4 = r10.f4120a
            long r4 = r4.m2307c()
            java.lang.String r6 = "application/x-scte35"
            com.google.android.exoplayer2.Format r3 = com.google.android.exoplayer2.Format.m4027D(r3, r6, r4)
            r0.mo1615d(r3)
            r0 = 1
            r10.f4122c = r0
        L29:
            int r7 = r11.m2569a()
            b.l.a.a.f1.s r0 = r10.f4121b
            r0.mo1613b(r11, r7)
            b.l.a.a.f1.s r3 = r10.f4121b
            b.l.a.a.p1.c0 r11 = r10.f4120a
            long r4 = r11.f6033c
            int r0 = (r4 > r1 ? 1 : (r4 == r1 ? 0 : -1))
            if (r0 == 0) goto L43
            long r0 = r11.f6033c
            long r4 = r11.f6032b
            long r1 = r4 + r0
            goto L4f
        L43:
            long r4 = r11.f6031a
            r8 = 9223372036854775807(0x7fffffffffffffff, double:NaN)
            int r11 = (r4 > r8 ? 1 : (r4 == r8 ? 0 : -1))
            if (r11 == 0) goto L4f
            goto L50
        L4f:
            r4 = r1
        L50:
            r6 = 1
            r8 = 0
            r9 = 0
            r3.mo1614c(r4, r6, r7, r8, r9)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p208f1.p214f0.C2034y.mo1579b(b.l.a.a.p1.t):void");
    }
}
