package p005b.p327w.p330b.p331b.p335f;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.w.b.b.f.a */
/* loaded from: classes2.dex */
public final class C2848a {

    /* renamed from: a */
    public final boolean f7763a;

    /* renamed from: b */
    @NotNull
    public final String f7764b;

    /* renamed from: c */
    public final boolean f7765c;

    /* renamed from: d */
    public final boolean f7766d;

    public C2848a() {
        this(false, null, false, false, 15);
    }

    public C2848a(boolean z, String str, boolean z2, boolean z3, int i2) {
        z = (i2 & 1) != 0 ? false : z;
        String msg = (i2 & 2) != 0 ? "Loading..." : null;
        z2 = (i2 & 4) != 0 ? false : z2;
        z3 = (i2 & 8) != 0 ? true : z3;
        Intrinsics.checkNotNullParameter(msg, "msg");
        this.f7763a = z;
        this.f7764b = msg;
        this.f7765c = z2;
        this.f7766d = z3;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C2848a)) {
            return false;
        }
        C2848a c2848a = (C2848a) obj;
        return this.f7763a == c2848a.f7763a && Intrinsics.areEqual(this.f7764b, c2848a.f7764b) && this.f7765c == c2848a.f7765c && this.f7766d == c2848a.f7766d;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1, types: [int] */
    /* JADX WARN: Type inference failed for: r0v7 */
    /* JADX WARN: Type inference failed for: r0v8 */
    /* JADX WARN: Type inference failed for: r2v1, types: [boolean] */
    public int hashCode() {
        boolean z = this.f7763a;
        ?? r0 = z;
        if (z) {
            r0 = 1;
        }
        int m598T = C1499a.m598T(this.f7764b, r0 * 31, 31);
        ?? r2 = this.f7765c;
        int i2 = r2;
        if (r2 != 0) {
            i2 = 1;
        }
        int i3 = (m598T + i2) * 31;
        boolean z2 = this.f7766d;
        return i3 + (z2 ? 1 : z2 ? 1 : 0);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("LoadingBean(isLoading=");
        m586H.append(this.f7763a);
        m586H.append(", msg=");
        m586H.append(this.f7764b);
        m586H.append(", now=");
        m586H.append(this.f7765c);
        m586H.append(", isDialog=");
        m586H.append(this.f7766d);
        m586H.append(')');
        return m586H.toString();
    }
}
