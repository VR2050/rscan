package Q1;

import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
final class q {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Integer f2504a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final Float f2505b;

    public q(Integer num, Float f3) {
        this.f2504a = num;
        this.f2505b = f3;
    }

    public final Integer a() {
        return this.f2504a;
    }

    public final Float b() {
        return this.f2505b;
    }

    public final void c(Integer num) {
        this.f2504a = num;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return t2.j.b(this.f2504a, qVar.f2504a) && t2.j.b(this.f2505b, qVar.f2505b);
    }

    public int hashCode() {
        Integer num = this.f2504a;
        int iHashCode = (num == null ? 0 : num.hashCode()) * 31;
        Float f3 = this.f2505b;
        return iHashCode + (f3 != null ? f3.hashCode() : 0);
    }

    public String toString() {
        return "ProcessedColorStop(color=" + this.f2504a + ", position=" + this.f2505b + ")";
    }

    public /* synthetic */ q(Integer num, Float f3, int i3, DefaultConstructorMarker defaultConstructorMarker) {
        this((i3 & 1) != 0 ? null : num, (i3 & 2) != 0 ? null : f3);
    }
}
