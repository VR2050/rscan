package p005b.p199l.p266d.p271u.p272c;

import androidx.exifinterface.media.ExifInterface;
import com.google.android.material.badge.BadgeDrawable;
import com.jbzd.media.movecartoons.bean.response.system.MainMenusBean;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
import java.util.Arrays;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import p005b.p085c.p088b.p089a.C1345b;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p199l.p266d.AbstractC2533o;
import p005b.p199l.p266d.C2525g;
import p005b.p199l.p266d.p271u.C2539a;
import p005b.p199l.p266d.p274v.C2544b;
import p005b.p199l.p266d.p274v.C2547e;
import p005b.p199l.p266d.p274v.p276m.C2555a;
import p005b.p199l.p266d.p274v.p276m.C2557c;
import p005b.p199l.p266d.p274v.p276m.C2559e;
import p005b.p310s.p311a.C2743m;

/* renamed from: b.l.d.u.c.a */
/* loaded from: classes2.dex */
public final class C2541a {

    /* renamed from: a */
    public static final String[] f6876a = {"CTRL_PS", " ", ExifInterface.GPS_MEASUREMENT_IN_PROGRESS, "B", "C", "D", ExifInterface.LONGITUDE_EAST, "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", ExifInterface.LATITUDE_SOUTH, ExifInterface.GPS_DIRECTION_TRUE, "U", ExifInterface.GPS_MEASUREMENT_INTERRUPTED, ExifInterface.LONGITUDE_WEST, "X", "Y", "Z", "CTRL_LL", "CTRL_ML", "CTRL_DL", "CTRL_BS"};

    /* renamed from: b */
    public static final String[] f6877b = {"CTRL_PS", " ", "a", "b", "c", "d", C1568e.f1949a, "f", "g", "h", "i", "j", "k", "l", C2743m.f7506a, "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "CTRL_US", "CTRL_ML", "CTRL_DL", "CTRL_BS"};

    /* renamed from: c */
    public static final String[] f6878c = {"CTRL_PS", " ", "\u0001", "\u0002", "\u0003", "\u0004", "\u0005", "\u0006", "\u0007", "\b", "\t", "\n", "\u000b", "\f", "\r", "\u001b", "\u001c", "\u001d", "\u001e", "\u001f", "@", "\\", "^", "_", "`", "|", "~", "\u007f", "CTRL_LL", "CTRL_UL", "CTRL_PL", "CTRL_BS"};

    /* renamed from: d */
    public static final String[] f6879d = {"", "\r", "\r\n", ". ", ", ", ": ", "!", "\"", "#", "$", "%", "&", "'", ChineseToPinyinResource.Field.LEFT_BRACKET, ChineseToPinyinResource.Field.RIGHT_BRACKET, "*", BadgeDrawable.DEFAULT_EXCEED_MAX_BADGE_NUMBER_SUFFIX, ChineseToPinyinResource.Field.COMMA, "-", ".", "/", ":", ";", "<", "=", ">", "?", "[", "]", "{", "}", "CTRL_UL"};

    /* renamed from: e */
    public static final String[] f6880e = {"CTRL_PS", " ", "0", "1", "2", "3", HomeDataHelper.type_tag, "5", "6", MainMenusBean.TYPE_APPS_CENTER, MainMenusBean.TYPE_DAY_PICKS, MainMenusBean.TYPE_PICK_COLLECTION, ChineseToPinyinResource.Field.COMMA, ".", "CTRL_UL", "CTRL_US"};

    /* renamed from: f */
    public C2539a f6881f;

    /* renamed from: b */
    public static int m2936b(boolean[] zArr, int i2, int i3) {
        int i4 = 0;
        for (int i5 = i2; i5 < i2 + i3; i5++) {
            i4 <<= 1;
            if (zArr[i5]) {
                i4 |= 1;
            }
        }
        return i4;
    }

    /* renamed from: a */
    public C2547e m2937a(C2539a c2539a) {
        int i2;
        C2555a c2555a;
        String str;
        this.f6881f = c2539a;
        C2544b c2544b = c2539a.f6941a;
        boolean z = c2539a.f6873c;
        int i3 = c2539a.f6875e;
        int i4 = (z ? 11 : 14) + (i3 << 2);
        int[] iArr = new int[i4];
        int i5 = ((z ? 88 : 112) + (i3 << 4)) * i3;
        boolean[] zArr = new boolean[i5];
        int i6 = 2;
        if (z) {
            for (int i7 = 0; i7 < i4; i7++) {
                iArr[i7] = i7;
            }
        } else {
            int i8 = i4 / 2;
            int i9 = ((((i8 - 1) / 15) * 2) + (i4 + 1)) / 2;
            for (int i10 = 0; i10 < i8; i10++) {
                iArr[(i8 - i10) - 1] = (i9 - r15) - 1;
                iArr[i8 + i10] = (i10 / 15) + i10 + i9 + 1;
            }
        }
        int i11 = 0;
        int i12 = 0;
        while (true) {
            if (i11 >= i3) {
                break;
            }
            int i13 = ((i3 - i11) << i6) + (z ? 9 : 12);
            int i14 = i11 << 1;
            int i15 = (i4 - 1) - i14;
            int i16 = 0;
            while (i16 < i13) {
                int i17 = i16 << 1;
                int i18 = 0;
                while (i18 < i6) {
                    int i19 = i14 + i18;
                    int i20 = i14 + i16;
                    zArr[i12 + i17 + i18] = c2544b.m2958c(iArr[i19], iArr[i20]);
                    int i21 = i15 - i18;
                    zArr[(i13 * 2) + i12 + i17 + i18] = c2544b.m2958c(iArr[i20], iArr[i21]);
                    int i22 = i15 - i16;
                    zArr[(i13 * 4) + i12 + i17 + i18] = c2544b.m2958c(iArr[i21], iArr[i22]);
                    zArr[(i13 * 6) + i12 + i17 + i18] = c2544b.m2958c(iArr[i22], iArr[i19]);
                    i18++;
                    z = z;
                    i3 = i3;
                    i6 = 2;
                }
                i16++;
                i6 = 2;
            }
            i12 += i13 << 3;
            i11++;
            i3 = i3;
            i6 = 2;
        }
        C2539a c2539a2 = this.f6881f;
        int i23 = c2539a2.f6875e;
        int i24 = 8;
        if (i23 <= 2) {
            c2555a = C2555a.f6967c;
            i2 = 6;
        } else if (i23 <= 8) {
            c2555a = C2555a.f6971g;
            i2 = 8;
        } else if (i23 <= 22) {
            i2 = 10;
            c2555a = C2555a.f6966b;
        } else {
            c2555a = C2555a.f6965a;
        }
        int i25 = c2539a2.f6874d;
        int i26 = i5 / i2;
        if (i26 < i25) {
            throw C2525g.m2925a();
        }
        int i27 = i5 % i2;
        int[] iArr2 = new int[i26];
        int i28 = 0;
        while (i28 < i26) {
            iArr2[i28] = m2936b(zArr, i27, i2);
            i28++;
            i27 += i2;
        }
        try {
            new C2557c(c2555a).m2986a(iArr2, i26 - i25);
            int i29 = 1;
            int i30 = (1 << i2) - 1;
            int i31 = 0;
            int i32 = 0;
            while (i31 < i25) {
                int i33 = iArr2[i31];
                if (i33 == 0 || i33 == i30) {
                    throw C2525g.m2925a();
                }
                if (i33 == i29 || i33 == i30 - 1) {
                    i32++;
                }
                i31++;
                i29 = 1;
            }
            int i34 = (i25 * i2) - i32;
            boolean[] zArr2 = new boolean[i34];
            int i35 = 0;
            for (int i36 = 0; i36 < i25; i36++) {
                int i37 = iArr2[i36];
                int i38 = 1;
                if (i37 == 1 || i37 == i30 - 1) {
                    Arrays.fill(zArr2, i35, (i35 + i2) - 1, i37 > 1);
                    i35 = (i2 - 1) + i35;
                } else {
                    int i39 = i2 - 1;
                    while (i39 >= 0) {
                        int i40 = i35 + 1;
                        zArr2[i35] = ((i38 << i39) & i37) != 0;
                        i39--;
                        i35 = i40;
                        i38 = 1;
                    }
                }
            }
            int i41 = (i34 + 7) / 8;
            byte[] bArr = new byte[i41];
            for (int i42 = 0; i42 < i41; i42++) {
                int i43 = i42 << 3;
                int i44 = i34 - i43;
                bArr[i42] = (byte) (i44 >= 8 ? m2936b(zArr2, i43, 8) : m2936b(zArr2, i43, i44) << (8 - i44));
            }
            StringBuilder sb = new StringBuilder(20);
            int i45 = 1;
            int i46 = 1;
            int i47 = 0;
            while (i47 < i34) {
                if (i45 != 6) {
                    int i48 = i45 == 4 ? 4 : 5;
                    if (i34 - i47 < i48) {
                        break;
                    }
                    int m2936b = m2936b(zArr2, i47, i48);
                    i47 += i48;
                    int m350b = C1345b.m350b(i45);
                    int i49 = 3;
                    if (m350b == 0) {
                        str = f6876a[m2936b];
                    } else if (m350b == 1) {
                        str = f6877b[m2936b];
                    } else if (m350b == 2) {
                        str = f6878c[m2936b];
                    } else if (m350b == 3) {
                        str = f6880e[m2936b];
                    } else {
                        if (m350b != 4) {
                            throw new IllegalStateException("Bad table");
                        }
                        str = f6879d[m2936b];
                    }
                    if (str.startsWith("CTRL_")) {
                        char charAt = str.charAt(5);
                        if (charAt == 'B') {
                            i49 = 6;
                        } else if (charAt == 'D') {
                            i49 = 4;
                        } else if (charAt == 'P') {
                            i49 = 5;
                        } else if (charAt == 'L') {
                            i49 = 2;
                        } else if (charAt != 'M') {
                            i49 = 1;
                        }
                        if (str.charAt(6) == 'L') {
                            i46 = i49;
                        } else {
                            i46 = i45;
                            i45 = i49;
                        }
                    } else {
                        sb.append(str);
                    }
                    i45 = i46;
                } else {
                    if (i34 - i47 < 5) {
                        break;
                    }
                    int m2936b2 = m2936b(zArr2, i47, 5);
                    i47 += 5;
                    if (m2936b2 == 0) {
                        if (i34 - i47 < 11) {
                            break;
                        }
                        m2936b2 = m2936b(zArr2, i47, 11) + 31;
                        i47 += 11;
                    }
                    int i50 = 0;
                    while (true) {
                        if (i50 >= m2936b2) {
                            break;
                        }
                        if (i34 - i47 < i24) {
                            i47 = i34;
                            break;
                        }
                        sb.append((char) m2936b(zArr2, i47, i24));
                        i47 += 8;
                        i50++;
                    }
                    i45 = i46;
                }
                i24 = 8;
            }
            C2547e c2547e = new C2547e(bArr, sb.toString(), null, null);
            c2547e.f6933b = i34;
            return c2547e;
        } catch (C2559e e2) {
            if (AbstractC2533o.f6852c) {
                throw new C2525g(e2);
            }
            throw C2525g.f6836f;
        }
    }
}
