package p005b.p199l.p266d.p282y;

import p005b.p199l.p266d.C2522d;
import tv.danmaku.ijk.media.player.IjkMediaCodecInfo;

/* renamed from: b.l.d.y.d */
/* loaded from: classes2.dex */
public final class C2574d extends AbstractC2581k {

    /* renamed from: a */
    public static final char[] f7028a = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-. $/+%abcd*".toCharArray();

    /* renamed from: b */
    public static final int[] f7029b;

    /* renamed from: c */
    public static final int f7030c;

    /* renamed from: d */
    public final StringBuilder f7031d = new StringBuilder(20);

    /* renamed from: e */
    public final int[] f7032e = new int[6];

    static {
        int[] iArr = {276, 328, 324, 322, 296, 292, 290, 336, 274, 266, 424, 420, 418, 404, 402, 394, 360, 356, 354, 308, 282, 344, 332, 326, IjkMediaCodecInfo.RANK_SECURE, 278, 436, 434, 428, 422, 406, 410, 364, 358, 310, 314, 302, 468, 466, 458, 366, 374, 430, 294, 474, 470, 306, 350};
        f7029b = iArr;
        f7030c = iArr[47];
    }

    /* renamed from: g */
    public static void m3004g(CharSequence charSequence, int i2, int i3) {
        int i4 = 0;
        int i5 = 1;
        for (int i6 = i2 - 1; i6 >= 0; i6--) {
            i4 += "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-. $/+%abcd*".indexOf(charSequence.charAt(i6)) * i5;
            i5++;
            if (i5 > i3) {
                i5 = 1;
            }
        }
        if (charSequence.charAt(i2) != f7028a[i4 % 47]) {
            throw C2522d.m2924a();
        }
    }

    /* renamed from: h */
    public static int m3005h(int[] iArr) {
        int i2 = 0;
        for (int i3 : iArr) {
            i2 += i3;
        }
        int length = iArr.length;
        int i4 = 0;
        for (int i5 = 0; i5 < length; i5++) {
            int round = Math.round((iArr[i5] * 9.0f) / i2);
            if (round <= 0 || round > 4) {
                return -1;
            }
            if ((i5 & 1) == 0) {
                for (int i6 = 0; i6 < round; i6++) {
                    i4 = (i4 << 1) | 1;
                }
            } else {
                i4 <<= round;
            }
        }
        return i4;
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x013e, code lost:
    
        if (r9 < 'X') goto L128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:101:0x0140, code lost:
    
        if (r9 > 'Z') goto L130;
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x0142, code lost:
    
        r8 = 127;
     */
    /* JADX WARN: Code restructure failed: missing block: B:105:0x0149, code lost:
    
        throw p005b.p199l.p266d.C2525g.m2925a();
     */
    /* JADX WARN: Code restructure failed: missing block: B:107:0x014a, code lost:
    
        if (r9 < 'A') goto L131;
     */
    /* JADX WARN: Code restructure failed: missing block: B:108:0x014c, code lost:
    
        if (r9 > 'Z') goto L132;
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x014e, code lost:
    
        r9 = r9 - '@';
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x0156, code lost:
    
        throw p005b.p199l.p266d.C2525g.m2925a();
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x0157, code lost:
    
        r8 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:117:0x0160, code lost:
    
        throw p005b.p199l.p266d.C2525g.m2925a();
     */
    /* JADX WARN: Code restructure failed: missing block: B:118:0x0161, code lost:
    
        r5.append(r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:121:0x0167, code lost:
    
        r9 = r17;
     */
    /* JADX WARN: Code restructure failed: missing block: B:122:0x0193, code lost:
    
        return new p005b.p199l.p266d.C2534p(r5.toString(), null, new p005b.p199l.p266d.C2536r[]{new p005b.p199l.p266d.C2536r((r2[1] + r2[0]) / 2.0f, r9), new p005b.p199l.p266d.C2536r((r12 / 2.0f) + r4, r9)}, p005b.p199l.p266d.EnumC2497a.CODE_93);
     */
    /* JADX WARN: Code restructure failed: missing block: B:124:0x0196, code lost:
    
        throw p005b.p199l.p266d.C2529k.f6843f;
     */
    /* JADX WARN: Code restructure failed: missing block: B:126:0x0199, code lost:
    
        throw p005b.p199l.p266d.C2529k.f6843f;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0060, code lost:
    
        r8 = p005b.p199l.p266d.p282y.C2574d.f7028a[r9];
        r7.append(r8);
        r9 = r6.length;
        r12 = r4;
        r10 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x006a, code lost:
    
        if (r10 >= r9) goto L126;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x006c, code lost:
    
        r12 = r12 + r6[r10];
        r10 = r10 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x0072, code lost:
    
        r9 = r18.m2951h(r12);
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x0078, code lost:
    
        if (r8 != '*') goto L106;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x007a, code lost:
    
        r7.deleteCharAt(r7.length() - 1);
        r8 = r6.length;
        r10 = 0;
        r12 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x0085, code lost:
    
        if (r10 >= r8) goto L127;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x0087, code lost:
    
        r12 = r12 + r6[r10];
        r10 = r10 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x008d, code lost:
    
        if (r9 == r5) goto L104;
     */
    /* JADX WARN: Code restructure failed: missing block: B:40:0x0093, code lost:
    
        if (r18.m2950g(r9) == false) goto L104;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0099, code lost:
    
        if (r7.length() < 2) goto L102;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x009b, code lost:
    
        r1 = r7.length();
        m3004g(r7, r1 - 2, 20);
        m3004g(r7, r1 - 1, 15);
        r7.setLength(r7.length() - 2);
        r1 = r7.length();
        r5 = new java.lang.StringBuilder(r1);
        r6 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x00bf, code lost:
    
        if (r6 >= r1) goto L129;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x00c1, code lost:
    
        r8 = r7.charAt(r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x00c7, code lost:
    
        if (r8 < 'a') goto L98;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x00cb, code lost:
    
        if (r8 > 'd') goto L98;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x00cf, code lost:
    
        if (r6 >= (r1 - 1)) goto L133;
     */
    /* JADX WARN: Code restructure failed: missing block: B:51:0x00d1, code lost:
    
        r6 = r6 + 1;
        r9 = r7.charAt(r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x00dd, code lost:
    
        switch(r8) {
            case 97: goto L88;
            case 98: goto L55;
            case 99: goto L48;
            case 100: goto L43;
            default: goto L94;
        };
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x00e2, code lost:
    
        if (r9 < 'A') goto L134;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00e4, code lost:
    
        if (r9 > 'Z') goto L135;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x00e6, code lost:
    
        r9 = r9 + ' ';
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0150, code lost:
    
        r8 = (char) r9;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0158, code lost:
    
        r5.append(r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x0164, code lost:
    
        r6 = r6 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x00ee, code lost:
    
        throw p005b.p199l.p266d.C2525g.m2925a();
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x00ef, code lost:
    
        if (r9 < 'A') goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x00f1, code lost:
    
        if (r9 > 'O') goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x00f3, code lost:
    
        r9 = r9 - ' ';
     */
    /* JADX WARN: Code restructure failed: missing block: B:68:0x00f6, code lost:
    
        if (r9 != 'Z') goto L136;
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x00f8, code lost:
    
        r8 = ':';
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x0100, code lost:
    
        throw p005b.p199l.p266d.C2525g.m2925a();
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x0101, code lost:
    
        if (r9 < 'A') goto L59;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x0105, code lost:
    
        if (r9 > 'E') goto L59;
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x0107, code lost:
    
        r9 = r9 - '&';
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x010c, code lost:
    
        if (r9 < 'F') goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:80:0x0110, code lost:
    
        if (r9 > 'J') goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x0112, code lost:
    
        r9 = r9 - 11;
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x0117, code lost:
    
        if (r9 < 'K') goto L68;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x0119, code lost:
    
        if (r9 > 'O') goto L68;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x011b, code lost:
    
        r9 = r9 + 16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:87:0x0120, code lost:
    
        if (r9 < 'P') goto L73;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x0124, code lost:
    
        if (r9 > 'T') goto L73;
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x0126, code lost:
    
        r9 = r9 + '+';
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x012b, code lost:
    
        if (r9 != 'U') goto L76;
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x0130, code lost:
    
        if (r9 != 'V') goto L79;
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x0132, code lost:
    
        r8 = '@';
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x0137, code lost:
    
        if (r9 != 'W') goto L82;
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x0139, code lost:
    
        r8 = '`';
     */
    @Override // p005b.p199l.p266d.p282y.AbstractC2581k
    /* renamed from: b */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public p005b.p199l.p266d.C2534p mo3000b(int r17, p005b.p199l.p266d.p274v.C2543a r18, java.util.Map<p005b.p199l.p266d.EnumC2523e, ?> r19) {
        /*
            Method dump skipped, instructions count: 474
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p282y.C2574d.mo3000b(int, b.l.d.v.a, java.util.Map):b.l.d.p");
    }
}
