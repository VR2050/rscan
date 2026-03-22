package p005b.p199l.p266d.p282y;

import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.q */
/* loaded from: classes2.dex */
public final class C2587q extends AbstractC2586p {

    /* renamed from: h */
    public static final int[] f7063h = {1, 1, 1, 1, 1, 1};

    /* renamed from: i */
    public static final int[][] f7064i = {new int[]{56, 52, 50, 49, 44, 38, 35, 42, 41, 37}, new int[]{7, 11, 13, 14, 19, 25, 28, 21, 22, 26}};

    /* renamed from: j */
    public final int[] f7065j = new int[4];

    @Override // p005b.p199l.p266d.p282y.AbstractC2586p
    /* renamed from: g */
    public boolean mo3024g(String str) {
        char[] cArr = new char[6];
        str.getChars(1, 7, cArr, 0);
        StringBuilder sb = new StringBuilder(12);
        sb.append(str.charAt(0));
        char c2 = cArr[5];
        switch (c2) {
            case '0':
            case '1':
            case '2':
                sb.append(cArr, 0, 2);
                sb.append(c2);
                sb.append("0000");
                sb.append(cArr, 2, 3);
                break;
            case '3':
                sb.append(cArr, 0, 3);
                sb.append("00000");
                sb.append(cArr, 3, 2);
                break;
            case '4':
                sb.append(cArr, 0, 4);
                sb.append("00000");
                sb.append(cArr[4]);
                break;
            default:
                sb.append(cArr, 0, 5);
                sb.append("0000");
                sb.append(c2);
                break;
        }
        if (str.length() >= 8) {
            sb.append(str.charAt(7));
        }
        return super.mo3024g(sb.toString());
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2586p
    /* renamed from: i */
    public int[] mo3025i(C2543a c2543a, int i2) {
        int[] iArr = f7063h;
        return AbstractC2586p.m3022l(c2543a, i2, true, iArr, new int[iArr.length]);
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2586p
    /* renamed from: j */
    public int mo3006j(C2543a c2543a, int[] iArr, StringBuilder sb) {
        int[] iArr2 = this.f7065j;
        iArr2[0] = 0;
        iArr2[1] = 0;
        iArr2[2] = 0;
        iArr2[3] = 0;
        int i2 = c2543a.f6892e;
        int i3 = iArr[1];
        int i4 = 0;
        for (int i5 = 0; i5 < 6 && i3 < i2; i5++) {
            int m3021h = AbstractC2586p.m3021h(c2543a, iArr2, i3, AbstractC2586p.f7059d);
            sb.append((char) ((m3021h % 10) + 48));
            for (int i6 : iArr2) {
                i3 += i6;
            }
            if (m3021h >= 10) {
                i4 |= 1 << (5 - i5);
            }
        }
        for (int i7 = 0; i7 <= 1; i7++) {
            for (int i8 = 0; i8 < 10; i8++) {
                if (i4 == f7064i[i7][i8]) {
                    sb.insert(0, (char) (i7 + 48));
                    sb.append((char) (i8 + 48));
                    return i3;
                }
            }
        }
        throw C2529k.f6843f;
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2586p
    /* renamed from: n */
    public EnumC2497a mo3007n() {
        return EnumC2497a.UPC_E;
    }
}
