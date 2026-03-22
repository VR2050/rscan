package p005b.p199l.p266d.p286z.p287d;

import java.math.BigInteger;
import p005b.p199l.p266d.C2525g;

/* renamed from: b.l.d.z.d.e */
/* loaded from: classes2.dex */
public final class C2622e {

    /* renamed from: a */
    public static final char[] f7152a = ";<>@[\\]_`~!\r\t,:\n-.$/\"|*()?{}'".toCharArray();

    /* renamed from: b */
    public static final char[] f7153b = "0123456789&\r\t,:#-.$/+%*=^".toCharArray();

    /* renamed from: c */
    public static final BigInteger[] f7154c;

    static {
        BigInteger[] bigIntegerArr = new BigInteger[16];
        f7154c = bigIntegerArr;
        bigIntegerArr[0] = BigInteger.ONE;
        BigInteger valueOf = BigInteger.valueOf(900L);
        bigIntegerArr[1] = valueOf;
        int i2 = 2;
        while (true) {
            BigInteger[] bigIntegerArr2 = f7154c;
            if (i2 >= bigIntegerArr2.length) {
                return;
            }
            bigIntegerArr2[i2] = bigIntegerArr2[i2 - 1].multiply(valueOf);
            i2++;
        }
    }

    /* renamed from: a */
    public static String m3067a(int[] iArr, int i2) {
        BigInteger bigInteger = BigInteger.ZERO;
        for (int i3 = 0; i3 < i2; i3++) {
            bigInteger = bigInteger.add(f7154c[(i2 - i3) - 1].multiply(BigInteger.valueOf(iArr[i3])));
        }
        String bigInteger2 = bigInteger.toString();
        if (bigInteger2.charAt(0) == '1') {
            return bigInteger2.substring(1);
        }
        throw C2525g.m2925a();
    }

    /* renamed from: b */
    public static int m3068b(int[] iArr, int i2, StringBuilder sb) {
        int[] iArr2 = new int[15];
        boolean z = false;
        int i3 = 0;
        while (i2 < iArr[0] && !z) {
            int i4 = i2 + 1;
            int i5 = iArr[i2];
            if (i4 == iArr[0]) {
                z = true;
            }
            if (i5 < 900) {
                iArr2[i3] = i5;
                i3++;
            } else {
                if (i5 != 900 && i5 != 901 && i5 != 928) {
                    switch (i5) {
                    }
                }
                i4--;
                z = true;
            }
            if ((i3 % 15 == 0 || i5 == 902 || z) && i3 > 0) {
                sb.append(m3067a(iArr2, i3));
                i3 = 0;
            }
            i2 = i4;
        }
        return i2;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x0098, code lost:
    
        if (r13 != 900) goto L45;
     */
    /* JADX WARN: Failed to find 'out' block for switch in B:15:0x0039. Please report as an issue. */
    /* JADX WARN: Failed to find 'out' block for switch in B:16:0x003c. Please report as an issue. */
    /* JADX WARN: Failed to find 'out' block for switch in B:80:0x00c6. Please report as an issue. */
    /* JADX WARN: Failed to find 'out' block for switch in B:94:0x00e3. Please report as an issue. */
    /* JADX WARN: Removed duplicated region for block: B:65:0x00f2 A[PHI: r11
      0x00f2: PHI (r11v11 int) = (r11v1 int), (r11v1 int), (r11v14 int) binds: [B:94:0x00e3, B:80:0x00c6, B:64:0x009d] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:84:0x00e7  */
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static int m3069c(int[] r16, int r17, java.lang.StringBuilder r18) {
        /*
            Method dump skipped, instructions count: 366
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p199l.p266d.p286z.p287d.C2622e.m3069c(int[], int, java.lang.StringBuilder):int");
    }
}
