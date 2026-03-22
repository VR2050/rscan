package p005b.p199l.p200a.p201a.p202a1;

import androidx.annotation.Nullable;

/* renamed from: b.l.a.a.a1.q */
/* loaded from: classes.dex */
public final class C1925q {

    /* renamed from: a */
    public final int f3120a;

    /* renamed from: b */
    public final float f3121b;

    public C1925q(int i2, float f2) {
        this.f3120a = i2;
        this.f3121b = f2;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C1925q.class != obj.getClass()) {
            return false;
        }
        C1925q c1925q = (C1925q) obj;
        return this.f3120a == c1925q.f3120a && Float.compare(c1925q.f3121b, this.f3121b) == 0;
    }

    public int hashCode() {
        return Float.floatToIntBits(this.f3121b) + ((527 + this.f3120a) * 31);
    }
}
