package p005b.p199l.p266d.p282y.p283r;

import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.l.d.y.r.b */
/* loaded from: classes2.dex */
public class C2589b {

    /* renamed from: a */
    public final int f7072a;

    /* renamed from: b */
    public final int f7073b;

    public C2589b(int i2, int i3) {
        this.f7072a = i2;
        this.f7073b = i3;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof C2589b)) {
            return false;
        }
        C2589b c2589b = (C2589b) obj;
        return this.f7072a == c2589b.f7072a && this.f7073b == c2589b.f7073b;
    }

    public final int hashCode() {
        return this.f7072a ^ this.f7073b;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.f7072a);
        sb.append(ChineseToPinyinResource.Field.LEFT_BRACKET);
        return C1499a.m579A(sb, this.f7073b, ')');
    }
}
