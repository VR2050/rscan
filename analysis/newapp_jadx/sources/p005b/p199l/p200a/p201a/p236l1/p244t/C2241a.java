package p005b.p199l.p200a.p201a.p236l1.p244t;

import androidx.annotation.Nullable;
import java.util.regex.Pattern;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.l1.t.a */
/* loaded from: classes.dex */
public final class C2241a {

    /* renamed from: a */
    public static final Pattern f5555a = Pattern.compile("\\[voice=\"([^\"]*)\"\\]");

    /* renamed from: b */
    public final C2360t f5556b = new C2360t();

    /* renamed from: c */
    public final StringBuilder f5557c = new StringBuilder();

    /* renamed from: a */
    public static String m2123a(C2360t c2360t, StringBuilder sb) {
        boolean z = false;
        sb.setLength(0);
        int i2 = c2360t.f6134b;
        int i3 = c2360t.f6135c;
        while (i2 < i3 && !z) {
            char c2 = (char) c2360t.f6133a[i2];
            if ((c2 < 'A' || c2 > 'Z') && ((c2 < 'a' || c2 > 'z') && !((c2 >= '0' && c2 <= '9') || c2 == '#' || c2 == '-' || c2 == '.' || c2 == '_'))) {
                z = true;
            } else {
                i2++;
                sb.append(c2);
            }
        }
        c2360t.m2568D(i2 - c2360t.f6134b);
        return sb.toString();
    }

    @Nullable
    /* renamed from: b */
    public static String m2124b(C2360t c2360t, StringBuilder sb) {
        m2125c(c2360t);
        if (c2360t.m2569a() == 0) {
            return null;
        }
        String m2123a = m2123a(c2360t, sb);
        if (!"".equals(m2123a)) {
            return m2123a;
        }
        StringBuilder m586H = C1499a.m586H("");
        m586H.append((char) c2360t.m2585q());
        return m586H.toString();
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x0068 A[LOOP:1: B:3:0x0002->B:41:0x0068, LOOP_END] */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void m2125c(p005b.p199l.p200a.p201a.p250p1.C2360t r8) {
        /*
            r0 = 1
        L1:
            r1 = 1
        L2:
            int r2 = r8.m2569a()
            if (r2 <= 0) goto L6a
            if (r1 == 0) goto L6a
            int r1 = r8.f6134b
            byte[] r2 = r8.f6133a
            r1 = r2[r1]
            char r1 = (char) r1
            r2 = 9
            r3 = 0
            if (r1 == r2) goto L28
            r2 = 10
            if (r1 == r2) goto L28
            r2 = 12
            if (r1 == r2) goto L28
            r2 = 13
            if (r1 == r2) goto L28
            r2 = 32
            if (r1 == r2) goto L28
            r1 = 0
            goto L2c
        L28:
            r8.m2568D(r0)
            r1 = 1
        L2c:
            if (r1 != 0) goto L1
            int r1 = r8.f6134b
            int r2 = r8.f6135c
            byte[] r4 = r8.f6133a
            int r5 = r1 + 2
            if (r5 > r2) goto L64
            int r5 = r1 + 1
            r1 = r4[r1]
            r6 = 47
            if (r1 != r6) goto L64
            int r1 = r5 + 1
            r5 = r4[r5]
            r7 = 42
            if (r5 != r7) goto L64
        L48:
            int r5 = r1 + 1
            if (r5 >= r2) goto L5c
            r1 = r4[r1]
            char r1 = (char) r1
            if (r1 != r7) goto L5a
            r1 = r4[r5]
            char r1 = (char) r1
            if (r1 != r6) goto L5a
            int r2 = r5 + 1
            r1 = r2
            goto L48
        L5a:
            r1 = r5
            goto L48
        L5c:
            int r1 = r8.f6134b
            int r2 = r2 - r1
            r8.m2568D(r2)
            r1 = 1
            goto L65
        L64:
            r1 = 0
        L65:
            if (r1 == 0) goto L68
            goto L1
        L68:
            r1 = 0
            goto L2
        L6a:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p200a.p201a.p236l1.p244t.C2241a.m2125c(b.l.a.a.p1.t):void");
    }
}
