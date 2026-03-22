package p005b.p199l.p200a.p201a.p202a1;

import android.annotation.TargetApi;
import androidx.annotation.Nullable;
import java.util.Arrays;
import p005b.p131d.p132a.p133a.C1499a;

@TargetApi(21)
/* renamed from: b.l.a.a.a1.j */
/* loaded from: classes.dex */
public final class C1918j {

    /* renamed from: a */
    public static final C1918j f3072a = new C1918j(new int[]{2}, 8);

    /* renamed from: b */
    public static final C1918j f3073b = new C1918j(new int[]{2, 5, 6}, 8);

    /* renamed from: c */
    public final int[] f3074c;

    /* renamed from: d */
    public final int f3075d;

    public C1918j(@Nullable int[] iArr, int i2) {
        if (iArr != null) {
            int[] copyOf = Arrays.copyOf(iArr, iArr.length);
            this.f3074c = copyOf;
            Arrays.sort(copyOf);
        } else {
            this.f3074c = new int[0];
        }
        this.f3075d = i2;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1918j)) {
            return false;
        }
        C1918j c1918j = (C1918j) obj;
        return Arrays.equals(this.f3074c, c1918j.f3074c) && this.f3075d == c1918j.f3075d;
    }

    public int hashCode() {
        return (Arrays.hashCode(this.f3074c) * 31) + this.f3075d;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("AudioCapabilities[maxChannelCount=");
        m586H.append(this.f3075d);
        m586H.append(", supportedEncodings=");
        m586H.append(Arrays.toString(this.f3074c));
        m586H.append("]");
        return m586H.toString();
    }
}
