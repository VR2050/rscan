package p005b.p199l.p200a.p201a.p245m1;

import androidx.annotation.Nullable;
import java.util.Arrays;

/* renamed from: b.l.a.a.m1.g */
/* loaded from: classes.dex */
public final class C2258g {

    /* renamed from: a */
    public final int f5659a;

    /* renamed from: b */
    public final InterfaceC2257f[] f5660b;

    /* renamed from: c */
    public int f5661c;

    public C2258g(InterfaceC2257f... interfaceC2257fArr) {
        this.f5660b = interfaceC2257fArr;
        this.f5659a = interfaceC2257fArr.length;
    }

    /* renamed from: a */
    public InterfaceC2257f[] m2164a() {
        return (InterfaceC2257f[]) this.f5660b.clone();
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2258g.class != obj.getClass()) {
            return false;
        }
        return Arrays.equals(this.f5660b, ((C2258g) obj).f5660b);
    }

    public int hashCode() {
        if (this.f5661c == 0) {
            this.f5661c = 527 + Arrays.hashCode(this.f5660b);
        }
        return this.f5661c;
    }
}
