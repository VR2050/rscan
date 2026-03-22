package p005b.p199l.p266d.p280x;

import androidx.exifinterface.media.ExifInterface;
import java.text.DecimalFormat;
import java.util.Map;
import java.util.Objects;
import p005b.p199l.p266d.C2521c;
import p005b.p199l.p266d.C2525g;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.EnumC2535q;
import p005b.p199l.p266d.InterfaceC2532n;
import p005b.p199l.p266d.p274v.C2544b;
import p005b.p199l.p266d.p280x.p281b.C2568a;
import p005b.p199l.p266d.p280x.p281b.C2569b;
import p005b.p199l.p266d.p280x.p281b.C2570c;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: b.l.d.x.a */
/* loaded from: classes2.dex */
public final class C2567a implements InterfaceC2532n {

    /* renamed from: a */
    public static final C2536r[] f7012a = new C2536r[0];

    /* renamed from: b */
    public final C2570c f7013b = new C2570c();

    @Override // p005b.p199l.p266d.InterfaceC2532n
    /* renamed from: a */
    public C2534p mo2867a(C2521c c2521c, Map<EnumC2523e, ?> map) {
        byte[] bArr;
        String valueOf;
        C2544b m2922a = c2521c.m2922a();
        int i2 = m2922a.f6893c;
        int i3 = m2922a.f6894e;
        int i4 = -1;
        int i5 = -1;
        for (int i6 = 0; i6 < m2922a.f6894e; i6++) {
            int i7 = 0;
            while (true) {
                int i8 = m2922a.f6895f;
                if (i7 < i8) {
                    int i9 = m2922a.f6896g[(i8 * i6) + i7];
                    if (i9 != 0) {
                        if (i6 < i3) {
                            i3 = i6;
                        }
                        if (i6 > i5) {
                            i5 = i6;
                        }
                        int i10 = i7 << 5;
                        if (i10 < i2) {
                            int i11 = 0;
                            while ((i9 << (31 - i11)) == 0) {
                                i11++;
                            }
                            int i12 = i11 + i10;
                            if (i12 < i2) {
                                i2 = i12;
                            }
                        }
                        if (i10 + 31 > i4) {
                            int i13 = 31;
                            while ((i9 >>> i13) == 0) {
                                i13--;
                            }
                            int i14 = i10 + i13;
                            if (i14 > i4) {
                                i4 = i14;
                            }
                        }
                    }
                    i7++;
                }
            }
        }
        int[] iArr = (i4 < i2 || i5 < i3) ? null : new int[]{i2, i3, (i4 - i2) + 1, (i5 - i3) + 1};
        if (iArr == null) {
            throw C2529k.f6843f;
        }
        int i15 = iArr[0];
        int i16 = iArr[1];
        int i17 = iArr[2];
        int i18 = iArr[3];
        int i19 = (30 + 31) / 32;
        int[] iArr2 = new int[i19 * 33];
        for (int i20 = 0; i20 < 33; i20++) {
            int i21 = (((i18 / 2) + (i20 * i18)) / 33) + i16;
            for (int i22 = 0; i22 < 30; i22++) {
                if (m2922a.m2958c((((((i20 & 1) * i17) / 2) + ((i17 / 2) + (i22 * i17))) / 30) + i15, i21)) {
                    int i23 = (i22 / 32) + (i20 * i19);
                    iArr2[i23] = (1 << (i22 & 31)) | iArr2[i23];
                }
            }
        }
        C2570c c2570c = this.f7013b;
        Objects.requireNonNull(c2570c);
        byte[] bArr2 = new byte[IjkMediaMeta.FF_PROFILE_H264_HIGH_444];
        for (int i24 = 0; i24 < 33; i24++) {
            int[] iArr3 = C2568a.f7014a[i24];
            for (int i25 = 0; i25 < 30; i25++) {
                int i26 = iArr3[i25];
                if (i26 >= 0) {
                    if (((iArr2[(i25 / 32) + (i24 * i19)] >>> (i25 & 31)) & 1) != 0) {
                        int i27 = i26 / 6;
                        bArr2[i27] = (byte) (((byte) (1 << (5 - (i26 % 6)))) | bArr2[i27]);
                    }
                }
            }
        }
        c2570c.m2998a(bArr2, 0, 10, 10, 0);
        int i28 = bArr2[0] & 15;
        if (i28 == 2 || i28 == 3 || i28 == 4) {
            c2570c.m2998a(bArr2, 20, 84, 40, 1);
            c2570c.m2998a(bArr2, 20, 84, 40, 2);
            bArr = new byte[94];
        } else {
            if (i28 != 5) {
                throw C2525g.m2925a();
            }
            c2570c.m2998a(bArr2, 20, 68, 56, 1);
            c2570c.m2998a(bArr2, 20, 68, 56, 2);
            bArr = new byte[78];
        }
        System.arraycopy(bArr2, 0, bArr, 0, 10);
        System.arraycopy(bArr2, 20, bArr, 10, bArr.length - 10);
        StringBuilder sb = new StringBuilder(IjkMediaMeta.FF_PROFILE_H264_HIGH_444);
        if (i28 == 2 || i28 == 3) {
            if (i28 == 2) {
                valueOf = new DecimalFormat("0000000000".substring(0, C2569b.m2996a(bArr, new byte[]{39, 40, 41, ExifInterface.START_CODE, 31, 32}))).format(C2569b.m2996a(bArr, new byte[]{33, 34, 35, 36, 25, 26, 27, 28, 29, 30, 19, 20, 21, 22, 23, 24, 13, 14, 15, 16, 17, 18, 7, 8, 9, 10, 11, 12, 1, 2}));
            } else {
                String[] strArr = C2569b.f7015a;
                valueOf = String.valueOf(new char[]{strArr[0].charAt(C2569b.m2996a(bArr, new byte[]{39, 40, 41, ExifInterface.START_CODE, 31, 32})), strArr[0].charAt(C2569b.m2996a(bArr, new byte[]{33, 34, 35, 36, 25, 26})), strArr[0].charAt(C2569b.m2996a(bArr, new byte[]{27, 28, 29, 30, 19, 20})), strArr[0].charAt(C2569b.m2996a(bArr, new byte[]{21, 22, 23, 24, 13, 14})), strArr[0].charAt(C2569b.m2996a(bArr, new byte[]{15, 16, 17, 18, 7, 8})), strArr[0].charAt(C2569b.m2996a(bArr, new byte[]{9, 10, 11, 12, 1, 2}))});
            }
            DecimalFormat decimalFormat = new DecimalFormat("000");
            String format = decimalFormat.format(C2569b.m2996a(bArr, new byte[]{53, 54, 43, 44, 45, 46, 47, 48, 37, 38}));
            String format2 = decimalFormat.format(C2569b.m2996a(bArr, new byte[]{55, 56, 57, 58, 59, 60, 49, 50, 51, 52}));
            sb.append(C2569b.m2997b(bArr, 10, 84));
            if (sb.toString().startsWith("[)>\u001e01\u001d")) {
                sb.insert(9, valueOf + (char) 29 + format + (char) 29 + format2 + (char) 29);
            } else {
                sb.insert(0, valueOf + (char) 29 + format + (char) 29 + format2 + (char) 29);
            }
        } else if (i28 == 4) {
            sb.append(C2569b.m2997b(bArr, 1, 93));
        } else if (i28 == 5) {
            sb.append(C2569b.m2997b(bArr, 1, 77));
        }
        String sb2 = sb.toString();
        String valueOf2 = String.valueOf(i28);
        C2534p c2534p = new C2534p(sb2, bArr, f7012a, EnumC2497a.MAXICODE);
        if (valueOf2 != null) {
            c2534p.m2933b(EnumC2535q.ERROR_CORRECTION_LEVEL, valueOf2);
        }
        return c2534p;
    }

    @Override // p005b.p199l.p266d.InterfaceC2532n
    public void reset() {
    }
}
