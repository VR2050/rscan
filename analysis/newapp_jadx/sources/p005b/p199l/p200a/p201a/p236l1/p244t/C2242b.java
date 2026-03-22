package p005b.p199l.p200a.p201a.p236l1.p244t;

import java.util.ArrayList;
import java.util.Collections;
import p005b.p199l.p200a.p201a.p236l1.AbstractC2208c;
import p005b.p199l.p200a.p201a.p236l1.C2212g;
import p005b.p199l.p200a.p201a.p236l1.InterfaceC2210e;
import p005b.p199l.p200a.p201a.p236l1.p244t.C2245e;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.l1.t.b */
/* loaded from: classes.dex */
public final class C2242b extends AbstractC2208c {

    /* renamed from: n */
    public final C2360t f5558n;

    /* renamed from: o */
    public final C2245e.b f5559o;

    public C2242b() {
        super("Mp4WebvttDecoder");
        this.f5558n = new C2360t();
        this.f5559o = new C2245e.b();
    }

    @Override // p005b.p199l.p200a.p201a.p236l1.AbstractC2208c
    /* renamed from: j */
    public InterfaceC2210e mo2047j(byte[] bArr, int i2, boolean z) {
        C2360t c2360t = this.f5558n;
        c2360t.f6133a = bArr;
        c2360t.f6135c = i2;
        c2360t.f6134b = 0;
        ArrayList arrayList = new ArrayList();
        while (this.f5558n.m2569a() > 0) {
            if (this.f5558n.m2569a() < 8) {
                throw new C2212g("Incomplete Mp4Webvtt Top Level box header found.");
            }
            int m2573e = this.f5558n.m2573e();
            if (this.f5558n.m2573e() == 1987343459) {
                C2360t c2360t2 = this.f5558n;
                C2245e.b bVar = this.f5559o;
                int i3 = m2573e - 8;
                bVar.m2129b();
                while (i3 > 0) {
                    if (i3 < 8) {
                        throw new C2212g("Incomplete vtt cue box header found.");
                    }
                    int m2573e2 = c2360t2.m2573e();
                    int m2573e3 = c2360t2.m2573e();
                    int i4 = m2573e2 - 8;
                    String m2333k = C2344d0.m2333k(c2360t2.f6133a, c2360t2.f6134b, i4);
                    c2360t2.m2568D(i4);
                    i3 = (i3 - 8) - i4;
                    if (m2573e3 == 1937011815) {
                        C2246f.m2132c(m2333k, bVar);
                    } else if (m2573e3 == 1885436268) {
                        C2246f.m2133d(null, m2333k.trim(), bVar, Collections.emptyList());
                    }
                }
                arrayList.add(bVar.m2128a());
            } else {
                this.f5558n.m2568D(m2573e - 8);
            }
        }
        return new C2243c(arrayList);
    }
}
