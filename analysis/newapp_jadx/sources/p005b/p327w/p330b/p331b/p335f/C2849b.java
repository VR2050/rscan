package p005b.p327w.p330b.p331b.p335f;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.w.b.b.f.b */
/* loaded from: classes2.dex */
public final class C2849b {

    /* renamed from: a */
    public final boolean f7767a;

    /* renamed from: b */
    @NotNull
    public final String f7768b;

    /* renamed from: c */
    public final boolean f7769c;

    public C2849b() {
        this(false, "NetError", false);
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C2849b)) {
            return false;
        }
        C2849b c2849b = (C2849b) obj;
        return this.f7767a == c2849b.f7767a && Intrinsics.areEqual(this.f7768b, c2849b.f7768b) && this.f7769c == c2849b.f7769c;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v1, types: [int] */
    /* JADX WARN: Type inference failed for: r0v5 */
    /* JADX WARN: Type inference failed for: r0v6 */
    public int hashCode() {
        boolean z = this.f7767a;
        ?? r0 = z;
        if (z) {
            r0 = 1;
        }
        int m598T = C1499a.m598T(this.f7768b, r0 * 31, 31);
        boolean z2 = this.f7769c;
        return m598T + (z2 ? 1 : z2 ? 1 : 0);
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("NetErrorBean(isError=");
        m586H.append(this.f7767a);
        m586H.append(", msg=");
        m586H.append(this.f7768b);
        m586H.append(", showOnView=");
        m586H.append(this.f7769c);
        m586H.append(')');
        return m586H.toString();
    }

    public C2849b(boolean z, @NotNull String msg, boolean z2) {
        Intrinsics.checkNotNullParameter(msg, "msg");
        this.f7767a = z;
        this.f7768b = msg;
        this.f7769c = z2;
    }
}
