package Q1;

import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class h {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f2445a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f2446b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f2447c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f2448d;

    public h(int i3, int i4, int i5, int i6) {
        this.f2445a = i3;
        this.f2446b = i4;
        this.f2447c = i5;
        this.f2448d = i6;
    }

    public final int a() {
        return this.f2448d;
    }

    public final int b() {
        return this.f2445a;
    }

    public final int c() {
        return this.f2447c;
    }

    public final int d() {
        return this.f2446b;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.f2445a == hVar.f2445a && this.f2446b == hVar.f2446b && this.f2447c == hVar.f2447c && this.f2448d == hVar.f2448d;
    }

    public int hashCode() {
        return (((((Integer.hashCode(this.f2445a) * 31) + Integer.hashCode(this.f2446b)) * 31) + Integer.hashCode(this.f2447c)) * 31) + Integer.hashCode(this.f2448d);
    }

    public String toString() {
        return "ColorEdges(left=" + this.f2445a + ", top=" + this.f2446b + ", right=" + this.f2447c + ", bottom=" + this.f2448d + ")";
    }

    public /* synthetic */ h(int i3, int i4, int i5, int i6, int i7, DefaultConstructorMarker defaultConstructorMarker) {
        this((i7 & 1) != 0 ? -16777216 : i3, (i7 & 2) != 0 ? -16777216 : i4, (i7 & 4) != 0 ? -16777216 : i5, (i7 & 8) != 0 ? -16777216 : i6);
    }
}
