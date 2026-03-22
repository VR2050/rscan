package p005b.p199l.p200a.p201a.p227k1.p230l0.p231k;

import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.k1.l0.k.d */
/* loaded from: classes.dex */
public final class C2147d {

    /* renamed from: a */
    public final String f4803a;

    /* renamed from: b */
    @Nullable
    public final String f4804b;

    /* renamed from: c */
    @Nullable
    public final String f4805c;

    public C2147d(String str, @Nullable String str2, @Nullable String str3) {
        this.f4803a = str;
        this.f4804b = str2;
        this.f4805c = str3;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2147d.class != obj.getClass()) {
            return false;
        }
        C2147d c2147d = (C2147d) obj;
        return C2344d0.m2323a(this.f4803a, c2147d.f4803a) && C2344d0.m2323a(this.f4804b, c2147d.f4804b) && C2344d0.m2323a(this.f4805c, c2147d.f4805c);
    }

    public int hashCode() {
        int hashCode = this.f4803a.hashCode() * 31;
        String str = this.f4804b;
        int hashCode2 = (hashCode + (str != null ? str.hashCode() : 0)) * 31;
        String str2 = this.f4805c;
        return hashCode2 + (str2 != null ? str2.hashCode() : 0);
    }
}
