package Q1;

import com.facebook.react.uimanager.W;

/* JADX INFO: loaded from: classes.dex */
final class i {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private Integer f2449a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final W f2450b;

    public i(Integer num, W w3) {
        this.f2449a = num;
        this.f2450b = w3;
    }

    public final Integer a() {
        return this.f2449a;
    }

    public final W b() {
        return this.f2450b;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return t2.j.b(this.f2449a, iVar.f2449a) && t2.j.b(this.f2450b, iVar.f2450b);
    }

    public int hashCode() {
        Integer num = this.f2449a;
        int iHashCode = (num == null ? 0 : num.hashCode()) * 31;
        W w3 = this.f2450b;
        return iHashCode + (w3 != null ? w3.hashCode() : 0);
    }

    public String toString() {
        return "ColorStop(color=" + this.f2449a + ", position=" + this.f2450b + ")";
    }
}
