package p005b.p199l.p258c;

import java.math.BigInteger;
import p005b.p199l.p258c.p260c0.C2460r;

/* renamed from: b.l.c.t */
/* loaded from: classes2.dex */
public final class C2490t extends AbstractC2485o {

    /* renamed from: a */
    public static final Class<?>[] f6697a = {Integer.TYPE, Long.TYPE, Short.TYPE, Float.TYPE, Double.TYPE, Byte.TYPE, Boolean.TYPE, Character.TYPE, Integer.class, Long.class, Short.class, Float.class, Double.class, Byte.class, Boolean.class, Character.class};

    /* renamed from: b */
    public Object f6698b;

    public C2490t(Boolean bool) {
        m2864f(bool);
    }

    /* renamed from: e */
    public static boolean m2860e(C2490t c2490t) {
        Object obj = c2490t.f6698b;
        if (obj instanceof Number) {
            Number number = (Number) obj;
            if ((number instanceof BigInteger) || (number instanceof Long) || (number instanceof Integer) || (number instanceof Short) || (number instanceof Byte)) {
                return true;
            }
        }
        return false;
    }

    /* renamed from: b */
    public boolean m2861b() {
        Object obj = this.f6698b;
        return obj instanceof Boolean ? ((Boolean) obj).booleanValue() : Boolean.parseBoolean(m2863d());
    }

    /* renamed from: c */
    public Number m2862c() {
        Object obj = this.f6698b;
        return obj instanceof String ? new C2460r((String) this.f6698b) : (Number) obj;
    }

    /* renamed from: d */
    public String m2863d() {
        Object obj = this.f6698b;
        return obj instanceof Number ? m2862c().toString() : obj instanceof Boolean ? ((Boolean) obj).toString() : (String) obj;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C2490t.class != obj.getClass()) {
            return false;
        }
        C2490t c2490t = (C2490t) obj;
        if (this.f6698b == null) {
            return c2490t.f6698b == null;
        }
        if (m2860e(this) && m2860e(c2490t)) {
            return m2862c().longValue() == c2490t.m2862c().longValue();
        }
        Object obj2 = this.f6698b;
        if (!(obj2 instanceof Number) || !(c2490t.f6698b instanceof Number)) {
            return obj2.equals(c2490t.f6698b);
        }
        double doubleValue = m2862c().doubleValue();
        double doubleValue2 = c2490t.m2862c().doubleValue();
        if (doubleValue != doubleValue2) {
            return Double.isNaN(doubleValue) && Double.isNaN(doubleValue2);
        }
        return true;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0037  */
    /* renamed from: f */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void m2864f(java.lang.Object r8) {
        /*
            r7 = this;
            boolean r0 = r8 instanceof java.lang.Character
            if (r0 == 0) goto L11
            java.lang.Character r8 = (java.lang.Character) r8
            char r8 = r8.charValue()
            java.lang.String r8 = java.lang.String.valueOf(r8)
            r7.f6698b = r8
            goto L3d
        L11:
            boolean r0 = r8 instanceof java.lang.Number
            r1 = 1
            r2 = 0
            if (r0 != 0) goto L38
            boolean r0 = r8 instanceof java.lang.String
            if (r0 == 0) goto L1c
            goto L2e
        L1c:
            java.lang.Class r0 = r8.getClass()
            java.lang.Class<?>[] r3 = p005b.p199l.p258c.C2490t.f6697a
            int r4 = r3.length
            r5 = 0
        L24:
            if (r5 >= r4) goto L33
            r6 = r3[r5]
            boolean r6 = r6.isAssignableFrom(r0)
            if (r6 == 0) goto L30
        L2e:
            r0 = 1
            goto L34
        L30:
            int r5 = r5 + 1
            goto L24
        L33:
            r0 = 0
        L34:
            if (r0 == 0) goto L37
            goto L38
        L37:
            r1 = 0
        L38:
            p005b.p199l.p200a.p201a.p250p1.C2354n.m2524w(r1)
            r7.f6698b = r8
        L3d:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p258c.C2490t.m2864f(java.lang.Object):void");
    }

    public int hashCode() {
        long doubleToLongBits;
        if (this.f6698b == null) {
            return 31;
        }
        if (m2860e(this)) {
            doubleToLongBits = m2862c().longValue();
        } else {
            Object obj = this.f6698b;
            if (!(obj instanceof Number)) {
                return obj.hashCode();
            }
            doubleToLongBits = Double.doubleToLongBits(m2862c().doubleValue());
        }
        return (int) ((doubleToLongBits >>> 32) ^ doubleToLongBits);
    }

    public C2490t(Number number) {
        m2864f(number);
    }

    public C2490t(String str) {
        m2864f(str);
    }
}
