package p458k.p459p0.p465i;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: k.p0.i.t */
/* loaded from: classes3.dex */
public final class C4454t {

    /* renamed from: a */
    public int f11955a;

    /* renamed from: b */
    public final int[] f11956b = new int[10];

    /* renamed from: a */
    public final int m5221a() {
        if ((this.f11955a & 128) != 0) {
            return this.f11956b[7];
        }
        return 65535;
    }

    /* renamed from: b */
    public final void m5222b(@NotNull C4454t other) {
        Intrinsics.checkParameterIsNotNull(other, "other");
        for (int i2 = 0; i2 < 10; i2++) {
            if (((1 << i2) & other.f11955a) != 0) {
                m5223c(i2, other.f11956b[i2]);
            }
        }
    }

    @NotNull
    /* renamed from: c */
    public final C4454t m5223c(int i2, int i3) {
        if (i2 >= 0) {
            int[] iArr = this.f11956b;
            if (i2 < iArr.length) {
                this.f11955a = (1 << i2) | this.f11955a;
                iArr[i2] = i3;
            }
        }
        return this;
    }
}
