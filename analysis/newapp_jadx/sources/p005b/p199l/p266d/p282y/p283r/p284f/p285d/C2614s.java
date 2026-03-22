package p005b.p199l.p266d.p282y.p283r.p284f.p285d;

import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.r.f.d.s */
/* loaded from: classes2.dex */
public final class C2614s {

    /* renamed from: a */
    public final C2543a f7124a;

    /* renamed from: b */
    public final C2608m f7125b = new C2608m();

    /* renamed from: c */
    public final StringBuilder f7126c = new StringBuilder();

    public C2614s(C2543a c2543a) {
        this.f7124a = c2543a;
    }

    /* renamed from: d */
    public static int m3053d(C2543a c2543a, int i2, int i3) {
        int i4 = 0;
        for (int i5 = 0; i5 < i3; i5++) {
            if (c2543a.m2950g(i2 + i5)) {
                i4 |= 1 << ((i3 - i5) - 1);
            }
        }
        return i4;
    }

    /* renamed from: a */
    public String m3054a(StringBuilder sb, int i2) {
        String str = null;
        while (true) {
            C2610o m3055b = m3055b(i2, str);
            String m3050a = C2613r.m3050a(m3055b.f7113b);
            if (m3050a != null) {
                sb.append(m3050a);
            }
            String valueOf = m3055b.f7115d ? String.valueOf(m3055b.f7114c) : null;
            int i3 = m3055b.f7118a;
            if (i2 == i3) {
                return sb.toString();
            }
            i2 = i3;
            str = valueOf;
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:167:0x0174, code lost:
    
        if (r1 >= 253) goto L94;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x03a0, code lost:
    
        r1 = r2.f7108a;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x03a2, code lost:
    
        if (r1 == null) goto L230;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x03a6, code lost:
    
        if (r1.f7115d == false) goto L230;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x03b5, code lost:
    
        return new p005b.p199l.p266d.p282y.p283r.p284f.p285d.C2610o(r7, r16.f7126c.toString(), r1.f7114c);
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x03c1, code lost:
    
        return new p005b.p199l.p266d.p282y.p283r.p284f.p285d.C2610o(r7, r16.f7126c.toString());
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x005a, code lost:
    
        if (r1 >= 63) goto L26;
     */
    /* JADX WARN: Removed duplicated region for block: B:145:0x0249 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:176:0x02b9  */
    /* JADX WARN: Removed duplicated region for block: B:17:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:207:0x0358 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:221:0x037e  */
    /* JADX WARN: Removed duplicated region for block: B:223:0x0387  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0399  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x039c A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:66:0x00ed A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:95:0x017b  */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p005b.p199l.p266d.p282y.p283r.p284f.p285d.C2610o m3055b(int r17, java.lang.String r18) {
        /*
            Method dump skipped, instructions count: 1026
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p282y.p283r.p284f.p285d.C2614s.m3055b(int, java.lang.String):b.l.d.y.r.f.d.o");
    }

    /* renamed from: c */
    public int m3056c(int i2, int i3) {
        return m3053d(this.f7124a, i2, i3);
    }

    /* renamed from: e */
    public final boolean m3057e(int i2) {
        int i3 = i2 + 3;
        if (i3 > this.f7124a.f6892e) {
            return false;
        }
        while (i2 < i3) {
            if (this.f7124a.m2950g(i2)) {
                return false;
            }
            i2++;
        }
        return true;
    }

    /* renamed from: f */
    public final boolean m3058f(int i2) {
        if (i2 + 1 > this.f7124a.f6892e) {
            return false;
        }
        for (int i3 = 0; i3 < 5; i3++) {
            int i4 = i3 + i2;
            C2543a c2543a = this.f7124a;
            if (i4 >= c2543a.f6892e) {
                return true;
            }
            if (i3 == 2) {
                if (!c2543a.m2950g(i2 + 2)) {
                    return false;
                }
            } else if (c2543a.m2950g(i4)) {
                return false;
            }
        }
        return true;
    }
}
