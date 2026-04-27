package Q1;

import com.facebook.react.uimanager.C0444f0;

/* JADX INFO: loaded from: classes.dex */
public final class k {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final float f2455a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final float f2456b;

    public k(float f3, float f4) {
        this.f2455a = f3;
        this.f2456b = f4;
    }

    public final float a() {
        return this.f2455a;
    }

    public final float b() {
        return this.f2456b;
    }

    public final k c() {
        return new k(C0444f0.h(this.f2455a), C0444f0.h(this.f2456b));
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof k)) {
            return false;
        }
        k kVar = (k) obj;
        return Float.compare(this.f2455a, kVar.f2455a) == 0 && Float.compare(this.f2456b, kVar.f2456b) == 0;
    }

    public int hashCode() {
        return (Float.hashCode(this.f2455a) * 31) + Float.hashCode(this.f2456b);
    }

    public String toString() {
        return "CornerRadii(horizontal=" + this.f2455a + ", vertical=" + this.f2456b + ")";
    }
}
