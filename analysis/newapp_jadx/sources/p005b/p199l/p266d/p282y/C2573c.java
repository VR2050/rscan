package p005b.p199l.p266d.p282y;

import com.alibaba.fastjson.asm.Opcodes;
import com.luck.picture.lib.camera.CustomCameraView;
import java.util.Arrays;
import java.util.Map;
import p005b.p199l.p266d.C2522d;
import p005b.p199l.p266d.C2529k;
import p005b.p199l.p266d.C2534p;
import p005b.p199l.p266d.C2536r;
import p005b.p199l.p266d.EnumC2497a;
import p005b.p199l.p266d.EnumC2523e;
import p005b.p199l.p266d.p274v.C2543a;

/* renamed from: b.l.d.y.c */
/* loaded from: classes2.dex */
public final class C2573c extends AbstractC2581k {

    /* renamed from: a */
    public static final int[] f7024a = {52, 289, 97, 352, 49, 304, 112, 37, 292, 100, 265, 73, 328, 25, 280, 88, 13, 268, 76, 28, CustomCameraView.BUTTON_STATE_BOTH, 67, 322, 19, 274, 82, 7, 262, 70, 22, 385, Opcodes.INSTANCEOF, 448, 145, 400, 208, 133, 388, 196, 168, Opcodes.IF_ICMPGE, 138, 42};

    /* renamed from: b */
    public final boolean f7025b;

    /* renamed from: c */
    public final StringBuilder f7026c = new StringBuilder(20);

    /* renamed from: d */
    public final int[] f7027d = new int[9];

    public C2573c(boolean z) {
        this.f7025b = z;
    }

    /* renamed from: g */
    public static int m3003g(int[] iArr) {
        int length = iArr.length;
        int i2 = 0;
        while (true) {
            int i3 = Integer.MAX_VALUE;
            for (int i4 : iArr) {
                if (i4 < i3 && i4 > i2) {
                    i3 = i4;
                }
            }
            int i5 = 0;
            int i6 = 0;
            int i7 = 0;
            for (int i8 = 0; i8 < length; i8++) {
                int i9 = iArr[i8];
                if (i9 > i3) {
                    i6 |= 1 << ((length - 1) - i8);
                    i5++;
                    i7 += i9;
                }
            }
            if (i5 == 3) {
                for (int i10 = 0; i10 < length && i5 > 0; i10++) {
                    int i11 = iArr[i10];
                    if (i11 > i3) {
                        i5--;
                        if ((i11 << 1) >= i7) {
                            return -1;
                        }
                    }
                }
                return i6;
            }
            if (i5 <= 3) {
                return -1;
            }
            i2 = i3;
        }
    }

    @Override // p005b.p199l.p266d.p282y.AbstractC2581k
    /* renamed from: b */
    public C2534p mo3000b(int i2, C2543a c2543a, Map<EnumC2523e, ?> map) {
        char c2;
        int[] iArr = this.f7027d;
        Arrays.fill(iArr, 0);
        StringBuilder sb = this.f7026c;
        sb.setLength(0);
        int i3 = c2543a.f6892e;
        int m2951h = c2543a.m2951h(0);
        int length = iArr.length;
        int i4 = m2951h;
        boolean z = false;
        int i5 = 0;
        while (m2951h < i3) {
            if (c2543a.m2950g(m2951h) != z) {
                iArr[i5] = iArr[i5] + 1;
            } else {
                if (i5 != length - 1) {
                    i5++;
                } else if (m3003g(iArr) == 148 && c2543a.m2954l(Math.max(0, i4 - ((m2951h - i4) / 2)), i4, false)) {
                    int m2951h2 = c2543a.m2951h(new int[]{i4, m2951h}[1]);
                    int i6 = c2543a.f6892e;
                    while (true) {
                        AbstractC2581k.m3014e(c2543a, m2951h2, iArr);
                        int m3003g = m3003g(iArr);
                        if (m3003g < 0) {
                            throw C2529k.f6843f;
                        }
                        int i7 = 0;
                        while (true) {
                            int[] iArr2 = f7024a;
                            if (i7 < iArr2.length) {
                                if (iArr2[i7] == m3003g) {
                                    c2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-. $/+%".charAt(i7);
                                    break;
                                }
                                i7++;
                            } else {
                                if (m3003g != 148) {
                                    throw C2529k.f6843f;
                                }
                                c2 = '*';
                            }
                        }
                        sb.append(c2);
                        int i8 = m2951h2;
                        for (int i9 : iArr) {
                            i8 += i9;
                        }
                        int m2951h3 = c2543a.m2951h(i8);
                        if (c2 == '*') {
                            sb.setLength(sb.length() - 1);
                            int i10 = 0;
                            for (int i11 : iArr) {
                                i10 += i11;
                            }
                            int i12 = (m2951h3 - m2951h2) - i10;
                            if (m2951h3 != i6 && (i12 << 1) < i10) {
                                throw C2529k.f6843f;
                            }
                            if (this.f7025b) {
                                int length2 = sb.length() - 1;
                                int i13 = 0;
                                for (int i14 = 0; i14 < length2; i14++) {
                                    i13 += "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-. $/+%".indexOf(this.f7026c.charAt(i14));
                                }
                                if (sb.charAt(length2) != "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-. $/+%".charAt(i13 % 43)) {
                                    throw C2522d.m2924a();
                                }
                                sb.setLength(length2);
                            }
                            if (sb.length() == 0) {
                                throw C2529k.f6843f;
                            }
                            float f2 = i2;
                            return new C2534p(sb.toString(), null, new C2536r[]{new C2536r((r5[1] + r5[0]) / 2.0f, f2), new C2536r((i10 / 2.0f) + m2951h2, f2)}, EnumC2497a.CODE_39);
                        }
                        m2951h2 = m2951h3;
                    }
                } else {
                    i4 += iArr[0] + iArr[1];
                    int i15 = i5 - 1;
                    System.arraycopy(iArr, 2, iArr, 0, i15);
                    iArr[i15] = 0;
                    iArr[i5] = 0;
                    i5 = i15;
                }
                iArr[i5] = 1;
                z = !z;
            }
            m2951h++;
        }
        throw C2529k.f6843f;
    }
}
