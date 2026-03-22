package p005b.p199l.p266d.p267a0.p269d;

import java.util.ArrayList;
import java.util.List;
import p005b.p199l.p266d.InterfaceC2537s;
import p005b.p199l.p266d.p274v.C2544b;

/* renamed from: b.l.d.a0.d.b */
/* loaded from: classes2.dex */
public final class C2511b {

    /* renamed from: a */
    public final C2544b f6775a;

    /* renamed from: c */
    public final int f6777c;

    /* renamed from: d */
    public final int f6778d;

    /* renamed from: e */
    public final int f6779e;

    /* renamed from: f */
    public final int f6780f;

    /* renamed from: g */
    public final float f6781g;

    /* renamed from: i */
    public final InterfaceC2537s f6783i;

    /* renamed from: b */
    public final List<C2510a> f6776b = new ArrayList(5);

    /* renamed from: h */
    public final int[] f6782h = new int[3];

    public C2511b(C2544b c2544b, int i2, int i3, int i4, int i5, float f2, InterfaceC2537s interfaceC2537s) {
        this.f6775a = c2544b;
        this.f6777c = i2;
        this.f6778d = i3;
        this.f6779e = i4;
        this.f6780f = i5;
        this.f6781g = f2;
        this.f6783i = interfaceC2537s;
    }

    /* renamed from: a */
    public static float m2892a(int[] iArr, int i2) {
        return (i2 - iArr[2]) - (iArr[1] / 2.0f);
    }

    /* renamed from: b */
    public final boolean m2893b(int[] iArr) {
        float f2 = this.f6781g;
        float f3 = f2 / 2.0f;
        for (int i2 = 0; i2 < 3; i2++) {
            if (Math.abs(f2 - iArr[i2]) >= f3) {
                return false;
            }
        }
        return true;
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x0071, code lost:
    
        if (r8[1] <= r5) goto L34;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0074, code lost:
    
        if (r14 >= r7) goto L81;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x007a, code lost:
    
        if (r6.m2958c(r4, r14) != false) goto L82;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x007e, code lost:
    
        if (r8[2] > r5) goto L83;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x0080, code lost:
    
        r8[2] = r8[2] + 1;
        r14 = r14 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x008a, code lost:
    
        if (r8[2] <= r5) goto L43;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x009e, code lost:
    
        if ((java.lang.Math.abs(((r8[0] + r8[1]) + r8[2]) - r1) * 5) < (r1 * 2)) goto L46;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x00a5, code lost:
    
        if (m2893b(r8) == false) goto L49;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x00a7, code lost:
    
        r10 = m2892a(r8, r14);
     */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0100 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:73:? A[LOOP:4: B:56:0x00c3->B:73:?, LOOP_END, SYNTHETIC] */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final p005b.p199l.p266d.p267a0.p269d.C2510a m2894c(int[] r13, int r14, int r15) {
        /*
            Method dump skipped, instructions count: 295
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p267a0.p269d.C2511b.m2894c(int[], int, int):b.l.d.a0.d.a");
    }
}
