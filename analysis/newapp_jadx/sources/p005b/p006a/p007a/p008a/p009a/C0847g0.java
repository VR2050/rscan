package p005b.p006a.p007a.p008a.p009a;

import java.text.SimpleDateFormat;
import java.util.Locale;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.a.a.a.a.g0 */
/* loaded from: classes2.dex */
public final class C0847g0 {

    /* renamed from: a */
    @NotNull
    public static final C0847g0 f249a = null;

    static {
        new SimpleDateFormat("yyyy-MM-dd hh:mm:ss", Locale.CHINA);
    }

    /* renamed from: a */
    public static final boolean m184a(@NotNull String left, @NotNull String right) {
        Intrinsics.checkNotNullParameter(left, "left");
        Intrinsics.checkNotNullParameter(right, "right");
        return Intrinsics.areEqual((String) CollectionsKt___CollectionsKt.first(StringsKt__StringsKt.split$default((CharSequence) left, new String[]{" "}, false, 0, 6, (Object) null)), (String) CollectionsKt___CollectionsKt.first(StringsKt__StringsKt.split$default((CharSequence) right, new String[]{" "}, false, 0, 6, (Object) null)));
    }
}
