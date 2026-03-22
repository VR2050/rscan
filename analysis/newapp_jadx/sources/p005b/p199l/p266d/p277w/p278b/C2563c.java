package p005b.p199l.p266d.p277w.p278b;

import com.alibaba.fastjson.asm.Opcodes;
import kotlin.text.Typography;

/* renamed from: b.l.d.w.b.c */
/* loaded from: classes2.dex */
public final class C2563c {

    /* renamed from: a */
    public static final char[] f6992a = {'*', '*', '*', ' ', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};

    /* renamed from: b */
    public static final char[] f6993b;

    /* renamed from: c */
    public static final char[] f6994c;

    /* renamed from: d */
    public static final char[] f6995d;

    /* renamed from: e */
    public static final char[] f6996e;

    static {
        char[] cArr = {'!', Typography.quote, '#', Typography.dollar, '%', Typography.amp, '\'', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', Typography.less, '=', Typography.greater, '?', '@', '[', '\\', ']', '^', '_'};
        f6993b = cArr;
        f6994c = new char[]{'*', '*', '*', ' ', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};
        f6995d = cArr;
        f6996e = new char[]{'`', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '{', '|', '}', '~', 127};
    }

    /* renamed from: a */
    public static void m2989a(int i2, int i3, int[] iArr) {
        int i4 = ((i2 << 8) + i3) - 1;
        int i5 = i4 / 1600;
        iArr[0] = i5;
        int i6 = i4 - (i5 * 1600);
        int i7 = i6 / 40;
        iArr[1] = i7;
        iArr[2] = i6 - (i7 * 40);
    }

    /* renamed from: b */
    public static int m2990b(int i2, int i3) {
        int i4 = i2 - (((i3 * Opcodes.FCMPL) % 255) + 1);
        return i4 >= 0 ? i4 : i4 + 256;
    }
}
