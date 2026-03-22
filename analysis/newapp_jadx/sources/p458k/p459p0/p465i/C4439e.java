package p458k.p459p0.p465i;

import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.p459p0.C4401c;
import p474l.C4747i;

/* renamed from: k.p0.i.e */
/* loaded from: classes3.dex */
public final class C4439e {

    /* renamed from: d */
    public static final String[] f11816d;

    /* renamed from: e */
    public static final C4439e f11817e = new C4439e();

    /* renamed from: a */
    @JvmField
    @NotNull
    public static final C4747i f11813a = C4747i.f12136e.m5412c("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

    /* renamed from: b */
    public static final String[] f11814b = {"DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION"};

    /* renamed from: c */
    public static final String[] f11815c = new String[64];

    static {
        String[] strArr = new String[256];
        for (int i2 = 0; i2 < 256; i2++) {
            String binaryString = Integer.toBinaryString(i2);
            Intrinsics.checkExpressionValueIsNotNull(binaryString, "Integer.toBinaryString(it)");
            strArr[i2] = StringsKt__StringsJVMKt.replace$default(C4401c.m5024i("%8s", binaryString), ' ', '0', false, 4, (Object) null);
        }
        f11816d = strArr;
        String[] strArr2 = f11815c;
        strArr2[0] = "";
        strArr2[1] = "END_STREAM";
        int[] iArr = {1};
        strArr2[8] = "PADDED";
        for (int i3 = 0; i3 < 1; i3++) {
            int i4 = iArr[i3];
            String[] strArr3 = f11815c;
            strArr3[i4 | 8] = Intrinsics.stringPlus(strArr3[i4], "|PADDED");
        }
        String[] strArr4 = f11815c;
        strArr4[4] = "END_HEADERS";
        strArr4[32] = "PRIORITY";
        strArr4[36] = "END_HEADERS|PRIORITY";
        int[] iArr2 = {4, 32, 36};
        for (int i5 = 0; i5 < 3; i5++) {
            int i6 = iArr2[i5];
            for (int i7 = 0; i7 < 1; i7++) {
                int i8 = iArr[i7];
                String[] strArr5 = f11815c;
                int i9 = i8 | i6;
                strArr5[i9] = strArr5[i8] + "|" + strArr5[i6];
                StringBuilder sb = new StringBuilder();
                sb.append(strArr5[i8]);
                sb.append("|");
                strArr5[i9 | 8] = C1499a.m582D(sb, strArr5[i6], "|PADDED");
            }
        }
        int length = f11815c.length;
        for (int i10 = 0; i10 < length; i10++) {
            String[] strArr6 = f11815c;
            if (strArr6[i10] == null) {
                strArr6[i10] = f11816d[i10];
            }
        }
    }

    @NotNull
    /* renamed from: a */
    public final String m5166a(boolean z, int i2, int i3, int i4, int i5) {
        String str;
        String str2;
        String[] strArr = f11814b;
        String m5024i = i4 < strArr.length ? strArr[i4] : C4401c.m5024i("0x%02x", Integer.valueOf(i4));
        if (i5 == 0) {
            str = "";
        } else {
            if (i4 != 2 && i4 != 3) {
                if (i4 == 4 || i4 == 6) {
                    str = i5 == 1 ? "ACK" : f11816d[i5];
                } else if (i4 != 7 && i4 != 8) {
                    String[] strArr2 = f11815c;
                    if (i5 < strArr2.length) {
                        str2 = strArr2[i5];
                        if (str2 == null) {
                            Intrinsics.throwNpe();
                        }
                    } else {
                        str2 = f11816d[i5];
                    }
                    String str3 = str2;
                    str = (i4 != 5 || (i5 & 4) == 0) ? (i4 != 0 || (i5 & 32) == 0) ? str3 : StringsKt__StringsJVMKt.replace$default(str3, "PRIORITY", "COMPRESSED", false, 4, (Object) null) : StringsKt__StringsJVMKt.replace$default(str3, "HEADERS", "PUSH_PROMISE", false, 4, (Object) null);
                }
            }
            str = f11816d[i5];
        }
        return C4401c.m5024i("%s 0x%08x %5d %-13s %s", z ? "<<" : ">>", Integer.valueOf(i2), Integer.valueOf(i3), m5024i, str);
    }
}
