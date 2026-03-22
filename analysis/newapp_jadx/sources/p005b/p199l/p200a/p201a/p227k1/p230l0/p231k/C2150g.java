package p005b.p199l.p200a.p201a.p227k1.p230l0.p231k;

import androidx.annotation.Nullable;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.k1.l0.k.g */
/* loaded from: classes.dex */
public class C2150g {

    /* renamed from: a */
    @Nullable
    public final String f4814a;

    /* renamed from: b */
    @Nullable
    public final String f4815b;

    /* renamed from: c */
    @Nullable
    public final String f4816c;

    /* renamed from: d */
    @Nullable
    public final String f4817d;

    /* renamed from: e */
    @Nullable
    public final String f4818e;

    public C2150g(@Nullable String str, @Nullable String str2, @Nullable String str3, @Nullable String str4, @Nullable String str5) {
        this.f4814a = str;
        this.f4815b = str2;
        this.f4816c = str3;
        this.f4817d = str4;
        this.f4818e = str5;
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2150g.class != obj.getClass()) {
            return false;
        }
        C2150g c2150g = (C2150g) obj;
        return C2344d0.m2323a(this.f4814a, c2150g.f4814a) && C2344d0.m2323a(this.f4815b, c2150g.f4815b) && C2344d0.m2323a(this.f4816c, c2150g.f4816c) && C2344d0.m2323a(this.f4817d, c2150g.f4817d) && C2344d0.m2323a(this.f4818e, c2150g.f4818e);
    }

    public int hashCode() {
        String str = this.f4814a;
        int hashCode = (527 + (str != null ? str.hashCode() : 0)) * 31;
        String str2 = this.f4815b;
        int hashCode2 = (hashCode + (str2 != null ? str2.hashCode() : 0)) * 31;
        String str3 = this.f4816c;
        int hashCode3 = (hashCode2 + (str3 != null ? str3.hashCode() : 0)) * 31;
        String str4 = this.f4817d;
        int hashCode4 = (hashCode3 + (str4 != null ? str4.hashCode() : 0)) * 31;
        String str5 = this.f4818e;
        return hashCode4 + (str5 != null ? str5.hashCode() : 0);
    }
}
