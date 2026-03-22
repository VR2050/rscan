package p005b.p199l.p266d.p282y.p283r.p284f;

import java.util.ArrayList;
import java.util.List;

/* renamed from: b.l.d.y.r.f.b */
/* loaded from: classes2.dex */
public final class C2594b {

    /* renamed from: a */
    public final List<C2593a> f7091a;

    /* renamed from: b */
    public final int f7092b;

    /* renamed from: c */
    public final boolean f7093c;

    public C2594b(List<C2593a> list, int i2, boolean z) {
        this.f7091a = new ArrayList(list);
        this.f7092b = i2;
        this.f7093c = z;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof C2594b)) {
            return false;
        }
        C2594b c2594b = (C2594b) obj;
        return this.f7091a.equals(c2594b.f7091a) && this.f7093c == c2594b.f7093c;
    }

    public int hashCode() {
        return this.f7091a.hashCode() ^ Boolean.valueOf(this.f7093c).hashCode();
    }

    public String toString() {
        return "{ " + this.f7091a + " }";
    }
}
