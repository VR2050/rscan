package p458k.p459p0.p463g;

import java.net.ProtocolException;
import kotlin.jvm.JvmField;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.EnumC4377e0;

/* renamed from: k.p0.g.j */
/* loaded from: classes3.dex */
public final class C4433j {

    /* renamed from: a */
    @JvmField
    @NotNull
    public final EnumC4377e0 f11748a;

    /* renamed from: b */
    @JvmField
    public final int f11749b;

    /* renamed from: c */
    @JvmField
    @NotNull
    public final String f11750c;

    public C4433j(@NotNull EnumC4377e0 protocol, int i2, @NotNull String message) {
        Intrinsics.checkParameterIsNotNull(protocol, "protocol");
        Intrinsics.checkParameterIsNotNull(message, "message");
        this.f11748a = protocol;
        this.f11749b = i2;
        this.f11750c = message;
    }

    @NotNull
    /* renamed from: a */
    public static final C4433j m5144a(@NotNull String statusLine) {
        String str;
        EnumC4377e0 enumC4377e0 = EnumC4377e0.HTTP_1_0;
        Intrinsics.checkParameterIsNotNull(statusLine, "statusLine");
        int i2 = 9;
        if (StringsKt__StringsJVMKt.startsWith$default(statusLine, "HTTP/1.", false, 2, null)) {
            if (statusLine.length() < 9 || statusLine.charAt(8) != ' ') {
                throw new ProtocolException(C1499a.m637w("Unexpected status line: ", statusLine));
            }
            int charAt = statusLine.charAt(7) - '0';
            if (charAt != 0) {
                if (charAt != 1) {
                    throw new ProtocolException(C1499a.m637w("Unexpected status line: ", statusLine));
                }
                enumC4377e0 = EnumC4377e0.HTTP_1_1;
            }
        } else {
            if (!StringsKt__StringsJVMKt.startsWith$default(statusLine, "ICY ", false, 2, null)) {
                throw new ProtocolException(C1499a.m637w("Unexpected status line: ", statusLine));
            }
            i2 = 4;
        }
        int i3 = i2 + 3;
        if (statusLine.length() < i3) {
            throw new ProtocolException(C1499a.m637w("Unexpected status line: ", statusLine));
        }
        try {
            String substring = statusLine.substring(i2, i3);
            Intrinsics.checkExpressionValueIsNotNull(substring, "(this as java.lang.Strin…ing(startIndex, endIndex)");
            int parseInt = Integer.parseInt(substring);
            if (statusLine.length() <= i3) {
                str = "";
            } else {
                if (statusLine.charAt(i3) != ' ') {
                    throw new ProtocolException(C1499a.m637w("Unexpected status line: ", statusLine));
                }
                str = statusLine.substring(i2 + 4);
                Intrinsics.checkExpressionValueIsNotNull(str, "(this as java.lang.String).substring(startIndex)");
            }
            return new C4433j(enumC4377e0, parseInt, str);
        } catch (NumberFormatException unused) {
            throw new ProtocolException(C1499a.m637w("Unexpected status line: ", statusLine));
        }
    }

    @NotNull
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (this.f11748a == EnumC4377e0.HTTP_1_0) {
            sb.append("HTTP/1.0");
        } else {
            sb.append("HTTP/1.1");
        }
        sb.append(' ');
        sb.append(this.f11749b);
        sb.append(' ');
        sb.append(this.f11750c);
        String sb2 = sb.toString();
        Intrinsics.checkExpressionValueIsNotNull(sb2, "StringBuilder().apply(builderAction).toString()");
        return sb2;
    }
}
