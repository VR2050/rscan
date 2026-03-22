package p005b.p199l.p200a.p201a.p202a1;

import com.alibaba.fastjson.asm.Opcodes;
import com.shuyu.gsyvideoplayer.utils.NeuQuant;

/* renamed from: b.l.a.a.a1.g */
/* loaded from: classes.dex */
public final class C1915g {

    /* renamed from: a */
    public static final int[] f3056a = {1, 2, 3, 6};

    /* renamed from: b */
    public static final int[] f3057b = {48000, 44100, 32000};

    /* renamed from: c */
    public static final int[] f3058c = {24000, 22050, 16000};

    /* renamed from: d */
    public static final int[] f3059d = {2, 1, 2, 3, 3, 4, 4, 5};

    /* renamed from: e */
    public static final int[] f3060e = {32, 40, 48, 56, 64, 80, 96, 112, 128, Opcodes.IF_ICMPNE, Opcodes.CHECKCAST, 224, 256, 320, 384, 448, 512, 576, 640};

    /* renamed from: f */
    public static final int[] f3061f = {69, 87, 104, 121, 139, 174, 208, 243, 278, 348, 417, NeuQuant.prime3, 557, 696, 835, 975, 1114, 1253, 1393};

    /* renamed from: a */
    public static int m1263a(int i2, int i3) {
        int i4 = i3 / 2;
        if (i2 < 0) {
            return -1;
        }
        int[] iArr = f3057b;
        if (i2 >= iArr.length || i3 < 0) {
            return -1;
        }
        int[] iArr2 = f3061f;
        if (i4 >= iArr2.length) {
            return -1;
        }
        int i5 = iArr[i2];
        if (i5 == 44100) {
            return ((i3 % 2) + iArr2[i4]) * 2;
        }
        int i6 = f3060e[i4];
        return i5 == 32000 ? i6 * 6 : i6 * 4;
    }
}
