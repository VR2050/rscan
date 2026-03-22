package p005b.p199l.p266d;

import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.l.d.r */
/* loaded from: classes2.dex */
public class C2536r {

    /* renamed from: a */
    public final float f6871a;

    /* renamed from: b */
    public final float f6872b;

    public C2536r(float f2, float f3) {
        this.f6871a = f2;
        this.f6872b = f3;
    }

    /* renamed from: a */
    public static float m2934a(C2536r c2536r, C2536r c2536r2) {
        return C2354n.m2428S(c2536r.f6871a, c2536r.f6872b, c2536r2.f6871a, c2536r2.f6872b);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof C2536r) {
            C2536r c2536r = (C2536r) obj;
            if (this.f6871a == c2536r.f6871a && this.f6872b == c2536r.f6872b) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return Float.floatToIntBits(this.f6872b) + (Float.floatToIntBits(this.f6871a) * 31);
    }

    public final String toString() {
        return ChineseToPinyinResource.Field.LEFT_BRACKET + this.f6871a + ',' + this.f6872b + ')';
    }
}
