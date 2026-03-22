package p005b.p295o.p296a.p297a.p298p;

import p005b.p131d.p132a.p133a.C1499a;
import p005b.p295o.p296a.p297a.C2685m;

/* renamed from: b.o.a.a.p.b */
/* loaded from: classes2.dex */
public abstract class AbstractC2690b extends AbstractC2694e {

    /* renamed from: b */
    public final String f7360b;

    public AbstractC2690b(String str, String str2) {
        super(str);
        this.f7360b = C2685m.m3223a(str2);
    }

    /* renamed from: b */
    public String m3231b(String str) {
        StringBuilder m586H = C1499a.m586H("[");
        C1499a.m606a0(m586H, super.toString(), str, "'");
        return C1499a.m582D(m586H, this.f7360b, "']");
    }
}
