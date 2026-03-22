package p005b.p199l.p258c.p260c0;

import java.math.BigDecimal;

/* renamed from: b.l.c.c0.r */
/* loaded from: classes2.dex */
public final class C2460r extends Number {

    /* renamed from: c */
    public final String f6609c;

    public C2460r(String str) {
        this.f6609c = str;
    }

    private Object writeReplace() {
        return new BigDecimal(this.f6609c);
    }

    @Override // java.lang.Number
    public double doubleValue() {
        return Double.parseDouble(this.f6609c);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C2460r)) {
            return false;
        }
        String str = this.f6609c;
        String str2 = ((C2460r) obj).f6609c;
        return str == str2 || str.equals(str2);
    }

    @Override // java.lang.Number
    public float floatValue() {
        return Float.parseFloat(this.f6609c);
    }

    public int hashCode() {
        return this.f6609c.hashCode();
    }

    @Override // java.lang.Number
    public int intValue() {
        try {
            try {
                return Integer.parseInt(this.f6609c);
            } catch (NumberFormatException unused) {
                return (int) Long.parseLong(this.f6609c);
            }
        } catch (NumberFormatException unused2) {
            return new BigDecimal(this.f6609c).intValue();
        }
    }

    @Override // java.lang.Number
    public long longValue() {
        try {
            return Long.parseLong(this.f6609c);
        } catch (NumberFormatException unused) {
            return new BigDecimal(this.f6609c).longValue();
        }
    }

    public String toString() {
        return this.f6609c;
    }
}
