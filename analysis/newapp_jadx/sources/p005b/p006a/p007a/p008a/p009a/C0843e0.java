package p005b.p006a.p007a.p008a.p009a;

import android.text.TextUtils;
import java.math.BigDecimal;
import java.util.regex.Pattern;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: b.a.a.a.a.e0 */
/* loaded from: classes2.dex */
public final class C0843e0 {
    @JvmStatic
    @NotNull
    /* renamed from: a */
    public static final String m182a(@Nullable String str) {
        String bigDecimal;
        String str2;
        if (str == null || str.length() == 0) {
            return "";
        }
        try {
            StringBuffer stringBuffer = new StringBuffer();
            Pattern compile = Pattern.compile("[0-9]*");
            Intrinsics.checkNotNullExpressionValue(compile, "compile(\"[0-9]*\")");
            if (!compile.matcher(str).matches() || str.length() < 5) {
                return str;
            }
            BigDecimal bigDecimal2 = new BigDecimal("10000");
            BigDecimal bigDecimal3 = new BigDecimal("100000000");
            BigDecimal bigDecimal4 = new BigDecimal(str);
            if ((bigDecimal4.compareTo(bigDecimal2) == 0 && bigDecimal4.compareTo(bigDecimal2) == 1) || bigDecimal4.compareTo(bigDecimal3) == -1) {
                bigDecimal = bigDecimal4.divide(bigDecimal2).toString();
                Intrinsics.checkNotNullExpressionValue(bigDecimal, "b3.divide(b1).toString()");
                str2 = "w";
            } else {
                if (bigDecimal4.compareTo(bigDecimal3) != 0 && bigDecimal4.compareTo(bigDecimal3) != 1) {
                    bigDecimal = "";
                    str2 = bigDecimal;
                }
                bigDecimal = bigDecimal4.divide(bigDecimal3).toString();
                Intrinsics.checkNotNullExpressionValue(bigDecimal, "b3.divide(b2).toString()");
                str2 = "亿";
            }
            if (!Intrinsics.areEqual("", bigDecimal)) {
                int indexOf$default = StringsKt__StringsKt.indexOf$default((CharSequence) bigDecimal, ".", 0, false, 6, (Object) null);
                if (indexOf$default == -1) {
                    stringBuffer.append(bigDecimal);
                    stringBuffer.append(str2);
                } else {
                    int i2 = indexOf$default + 1;
                    int i3 = i2 + 1;
                    String substring = bigDecimal.substring(i2, i3);
                    Intrinsics.checkNotNullExpressionValue(substring, "this as java.lang.String…ing(startIndex, endIndex)");
                    if (Intrinsics.areEqual(substring, "0")) {
                        String substring2 = bigDecimal.substring(0, i2 - 1);
                        Intrinsics.checkNotNullExpressionValue(substring2, "this as java.lang.String…ing(startIndex, endIndex)");
                        stringBuffer.append(substring2);
                        stringBuffer.append(str2);
                    } else {
                        String substring3 = bigDecimal.substring(0, i3);
                        Intrinsics.checkNotNullExpressionValue(substring3, "this as java.lang.String…ing(startIndex, endIndex)");
                        stringBuffer.append(substring3);
                        stringBuffer.append(str2);
                    }
                }
            }
            if (stringBuffer.length() == 0) {
                return "0";
            }
            String stringBuffer2 = stringBuffer.toString();
            Intrinsics.checkNotNullExpressionValue(stringBuffer2, "sb.toString()");
            return stringBuffer2;
        } catch (Exception e2) {
            e2.printStackTrace();
            return str;
        }
    }

    @NotNull
    /* renamed from: b */
    public static final String m183b(int i2, @NotNull String symbol) {
        Intrinsics.checkNotNullParameter(symbol, "symbol");
        int i3 = i2 / 86400;
        int i4 = i2 % 86400;
        int i5 = i4 / 3600;
        int i6 = i4 % 3600;
        int i7 = i6 / 60;
        int i8 = i6 % 60;
        return TextUtils.equals("day", symbol) ? String.valueOf(i3) : TextUtils.equals("hour", symbol) ? i5 < 10 ? Intrinsics.stringPlus("0", Integer.valueOf(i5)) : String.valueOf(i5) : TextUtils.equals("min", symbol) ? i7 < 10 ? Intrinsics.stringPlus("0", Integer.valueOf(i7)) : String.valueOf(i7) : i8 < 10 ? Intrinsics.stringPlus("0", Integer.valueOf(i8)) : String.valueOf(i8);
    }
}
