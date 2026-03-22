package p005b.p199l.p200a.p201a.p227k1.p230l0.p231k;

import android.net.Uri;
import androidx.annotation.Nullable;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

/* renamed from: b.l.a.a.k1.l0.k.h */
/* loaded from: classes.dex */
public final class C2151h {

    /* renamed from: a */
    public final long f4819a;

    /* renamed from: b */
    public final long f4820b;

    /* renamed from: c */
    public final String f4821c;

    /* renamed from: d */
    public int f4822d;

    public C2151h(@Nullable String str, long j2, long j3) {
        this.f4821c = str == null ? "" : str;
        this.f4819a = j2;
        this.f4820b = j3;
    }

    @Nullable
    /* renamed from: a */
    public C2151h m1915a(@Nullable C2151h c2151h, String str) {
        String m2511r1 = C2354n.m2511r1(str, this.f4821c);
        if (c2151h != null && m2511r1.equals(C2354n.m2511r1(str, c2151h.f4821c))) {
            long j2 = this.f4820b;
            if (j2 != -1) {
                long j3 = this.f4819a;
                if (j3 + j2 == c2151h.f4819a) {
                    long j4 = c2151h.f4820b;
                    return new C2151h(m2511r1, j3, j4 == -1 ? -1L : j2 + j4);
                }
            }
            long j5 = c2151h.f4820b;
            if (j5 != -1) {
                long j6 = c2151h.f4819a;
                if (j6 + j5 == this.f4819a) {
                    return new C2151h(m2511r1, j6, j2 == -1 ? -1L : j5 + j2);
                }
            }
        }
        return null;
    }

    /* renamed from: b */
    public Uri m1916b(String str) {
        return C2354n.m2514s1(str, this.f4821c);
    }

    public boolean equals(@Nullable Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2151h.class != obj.getClass()) {
            return false;
        }
        C2151h c2151h = (C2151h) obj;
        return this.f4819a == c2151h.f4819a && this.f4820b == c2151h.f4820b && this.f4821c.equals(c2151h.f4821c);
    }

    public int hashCode() {
        if (this.f4822d == 0) {
            this.f4822d = this.f4821c.hashCode() + ((((527 + ((int) this.f4819a)) * 31) + ((int) this.f4820b)) * 31);
        }
        return this.f4822d;
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("RangedUri(referenceUri=");
        m586H.append(this.f4821c);
        m586H.append(", start=");
        m586H.append(this.f4819a);
        m586H.append(", length=");
        m586H.append(this.f4820b);
        m586H.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
        return m586H.toString();
    }
}
