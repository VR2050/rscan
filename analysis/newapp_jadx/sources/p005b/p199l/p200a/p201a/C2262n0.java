package p005b.p199l.p200a.p201a;

import androidx.annotation.Nullable;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.l.a.a.n0 */
/* loaded from: classes.dex */
public final class C2262n0 {

    /* renamed from: a */
    public static final C2262n0 f5668a = new C2262n0(1.0f, 1.0f, false);

    /* renamed from: b */
    public final float f5669b;

    /* renamed from: c */
    public final float f5670c;

    /* renamed from: d */
    public final boolean f5671d;

    /* renamed from: e */
    public final int f5672e;

    public C2262n0(float f2, float f3, boolean z) {
        C4195m.m4765F(f2 > 0.0f);
        C4195m.m4765F(f3 > 0.0f);
        this.f5669b = f2;
        this.f5670c = f3;
        this.f5671d = z;
        this.f5672e = Math.round(f2 * 1000.0f);
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2262n0.class != obj.getClass()) {
            return false;
        }
        C2262n0 c2262n0 = (C2262n0) obj;
        return this.f5669b == c2262n0.f5669b && this.f5670c == c2262n0.f5670c && this.f5671d == c2262n0.f5671d;
    }

    public int hashCode() {
        return ((Float.floatToRawIntBits(this.f5670c) + ((Float.floatToRawIntBits(this.f5669b) + 527) * 31)) * 31) + (this.f5671d ? 1 : 0);
    }
}
