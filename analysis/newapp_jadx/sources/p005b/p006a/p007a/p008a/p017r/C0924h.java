package p005b.p006a.p007a.p008a.p017r;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.a.a.a.r.h */
/* loaded from: classes2.dex */
public final class C0924h {

    /* renamed from: a */
    @NotNull
    public final String f434a;

    /* renamed from: b */
    @NotNull
    public final String f435b;

    /* renamed from: c */
    public final boolean f436c;

    public C0924h(@NotNull String code, @NotNull String url, boolean z) {
        Intrinsics.checkNotNullParameter(code, "code");
        Intrinsics.checkNotNullParameter(url, "url");
        this.f434a = code;
        this.f435b = url;
        this.f436c = z;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0924h)) {
            return false;
        }
        C0924h c0924h = (C0924h) obj;
        return Intrinsics.areEqual(this.f434a, c0924h.f434a) && Intrinsics.areEqual(this.f435b, c0924h.f435b) && this.f436c == c0924h.f436c;
    }

    /* JADX WARN: Multi-variable type inference failed */
    public int hashCode() {
        int m598T = C1499a.m598T(this.f435b, this.f434a.hashCode() * 31, 31);
        boolean z = this.f436c;
        int i2 = z;
        if (z != 0) {
            i2 = 1;
        }
        return m598T + i2;
    }

    @NotNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("Line(code=");
        m586H.append(this.f434a);
        m586H.append(", url=");
        m586H.append(this.f435b);
        m586H.append(", isGaoFang=");
        m586H.append(this.f436c);
        m586H.append(')');
        return m586H.toString();
    }
}
