package kotlin.reflect.jvm.internal.impl.metadata.jvm.deserialization;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class UtfEncodingKt {
    @NotNull
    public static final byte[] stringsToBytes(@NotNull String[] strings) {
        int i2;
        Intrinsics.checkNotNullParameter(strings, "strings");
        int i3 = 0;
        for (String str : strings) {
            i3 += str.length();
        }
        byte[] bArr = new byte[i3];
        int length = strings.length;
        int i4 = 0;
        int i5 = 0;
        while (i4 < length) {
            String str2 = strings[i4];
            i4++;
            int length2 = str2.length() - 1;
            if (length2 >= 0) {
                int i6 = 0;
                while (true) {
                    int i7 = i6 + 1;
                    i2 = i5 + 1;
                    bArr[i5] = (byte) str2.charAt(i6);
                    if (i6 == length2) {
                        break;
                    }
                    i6 = i7;
                    i5 = i2;
                }
                i5 = i2;
            }
        }
        return bArr;
    }
}
