package p005b.p006a.p007a.p008a.p009a.p011p0;

import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.a.a.a.a.p0.a */
/* loaded from: classes2.dex */
public final class C0867a {

    /* renamed from: a */
    @NotNull
    public final StringBuilder f303a = new StringBuilder();

    @NotNull
    /* renamed from: a */
    public final String m199a(char c2) {
        int length;
        this.f303a.append(c2);
        String sb = this.f303a.toString();
        Intrinsics.checkNotNullExpressionValue(sb, "accruedInput.toString()");
        StringBuilder sb2 = new StringBuilder();
        if ((sb.length() > 0) && sb.length() - 1 >= 0) {
            int i2 = 0;
            while (true) {
                int i3 = i2 + 1;
                if (i2 == 3 || i2 == 8 || sb.charAt(i2) != ' ') {
                    sb2.append(sb.charAt(i2));
                    boolean z = sb2.length() == 4 || sb2.length() == 9;
                    boolean z2 = sb2.charAt(sb2.length() - 1) != ' ';
                    if (z && z2) {
                        sb2.insert(sb2.length() - 1, ' ');
                    }
                }
                if (i3 > length) {
                    break;
                }
                i2 = i3;
            }
        }
        String sb3 = sb2.toString();
        Intrinsics.checkNotNullExpressionValue(sb3, "formattingNumber.toString()");
        return sb3.length() == 0 ? sb : sb3;
    }
}
