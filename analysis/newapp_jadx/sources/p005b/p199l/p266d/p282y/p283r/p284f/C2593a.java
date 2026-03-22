package p005b.p199l.p266d.p282y.p283r.p284f;

import java.util.Objects;
import p005b.p199l.p266d.p282y.p283r.C2589b;
import p005b.p199l.p266d.p282y.p283r.C2590c;

/* renamed from: b.l.d.y.r.f.a */
/* loaded from: classes2.dex */
public final class C2593a {

    /* renamed from: a */
    public final C2589b f7088a;

    /* renamed from: b */
    public final C2589b f7089b;

    /* renamed from: c */
    public final C2590c f7090c;

    public C2593a(C2589b c2589b, C2589b c2589b2, C2590c c2590c) {
        this.f7088a = c2589b;
        this.f7089b = c2589b2;
        this.f7090c = c2590c;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof C2593a)) {
            return false;
        }
        C2593a c2593a = (C2593a) obj;
        return Objects.equals(this.f7088a, c2593a.f7088a) && Objects.equals(this.f7089b, c2593a.f7089b) && Objects.equals(this.f7090c, c2593a.f7090c);
    }

    public int hashCode() {
        return (Objects.hashCode(this.f7088a) ^ Objects.hashCode(this.f7089b)) ^ Objects.hashCode(this.f7090c);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder("[ ");
        sb.append(this.f7088a);
        sb.append(" , ");
        sb.append(this.f7089b);
        sb.append(" : ");
        C2590c c2590c = this.f7090c;
        sb.append(c2590c == null ? "null" : Integer.valueOf(c2590c.f7074a));
        sb.append(" ]");
        return sb.toString();
    }
}
