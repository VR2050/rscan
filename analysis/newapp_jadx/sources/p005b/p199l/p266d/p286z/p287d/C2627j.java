package p005b.p199l.p266d.p286z.p287d;

import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.p274v.C2544b;
import p005b.p199l.p266d.p286z.p287d.p288k.C2628a;

/* renamed from: b.l.d.z.d.j */
/* loaded from: classes2.dex */
public final class C2627j {

    /* renamed from: a */
    public static final C2628a f7163a = new C2628a();

    /* JADX WARN: Removed duplicated region for block: B:50:0x00f2  */
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static p005b.p199l.p266d.p286z.p287d.C2620c m3076a(p005b.p199l.p266d.p286z.p287d.C2625h r15) {
        /*
            Method dump skipped, instructions count: 285
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p286z.p287d.C2627j.m3076a(b.l.d.z.d.h):b.l.d.z.d.c");
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to find 'out' block for switch in B:220:0x03f2. Please report as an issue. */
    /* JADX WARN: Failed to find 'out' block for switch in B:221:0x03f5. Please report as an issue. */
    /* JADX WARN: Removed duplicated region for block: B:141:0x0299  */
    /* JADX WARN: Removed duplicated region for block: B:161:0x0334  */
    /* JADX WARN: Removed duplicated region for block: B:179:0x024e  */
    /* JADX WARN: Removed duplicated region for block: B:195:0x03ad A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:204:0x03c4 A[ADDED_TO_REGION, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:220:0x03f2  */
    /* JADX WARN: Removed duplicated region for block: B:239:0x041d A[SYNTHETIC] */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:126:0x0294 -> B:116:0x0295). Please report as a decompilation issue!!! */
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static p005b.p199l.p266d.p274v.C2547e m3077b(int[] r25, int r26, int[] r27) {
        /*
            Method dump skipped, instructions count: 1272
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p286z.p287d.C2627j.m3077b(int[], int, int[]):b.l.d.v.e");
    }

    /* JADX WARN: Code restructure failed: missing block: B:132:0x0032, code lost:
    
        continue;
     */
    /* JADX WARN: Code restructure failed: missing block: B:134:0x0032, code lost:
    
        continue;
     */
    /* JADX WARN: Code restructure failed: missing block: B:136:0x0032, code lost:
    
        continue;
     */
    /* JADX WARN: Removed duplicated region for block: B:11:0x0025  */
    /* JADX WARN: Removed duplicated region for block: B:23:0x004e  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0060 A[EDGE_INSN: B:32:0x0060->B:33:0x0060 BREAK  A[LOOP:2: B:20:0x0045->B:28:0x0045], SYNTHETIC] */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static p005b.p199l.p266d.p286z.p287d.C2621d m3078c(p005b.p199l.p266d.p274v.C2544b r18, int r19, int r20, boolean r21, int r22, int r23, int r24, int r25) {
        /*
            Method dump skipped, instructions count: 370
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p286z.p287d.C2627j.m3078c(b.l.d.v.b, int, int, boolean, int, int, int, int):b.l.d.z.d.d");
    }

    /* renamed from: d */
    public static C2625h m3079d(C2544b c2544b, C2620c c2620c, C2536r c2536r, boolean z, int i2, int i3) {
        C2625h c2625h = new C2625h(c2620c, z);
        int i4 = 0;
        while (i4 < 2) {
            int i5 = i4 == 0 ? 1 : -1;
            int i6 = (int) c2536r.f6871a;
            for (int i7 = (int) c2536r.f6872b; i7 <= c2620c.f7146i && i7 >= c2620c.f7145h; i7 += i5) {
                C2621d m3078c = m3078c(c2544b, 0, c2544b.f6893c, z, i6, i7, i2, i3);
                if (m3078c != null) {
                    c2625h.f7160b[i7 - c2625h.f7159a.f7145h] = m3078c;
                    i6 = z ? m3078c.f7147a : m3078c.f7148b;
                }
            }
            i4++;
        }
        return c2625h;
    }

    /* renamed from: e */
    public static boolean m3080e(C2623f c2623f, int i2) {
        return i2 >= 0 && i2 <= c2623f.f7158d + 1;
    }
}
