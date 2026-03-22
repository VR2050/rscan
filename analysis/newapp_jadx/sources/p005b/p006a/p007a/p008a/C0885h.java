package p005b.p006a.p007a.p008a;

import android.content.SharedPreferences;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

/* renamed from: b.a.a.a.h */
/* loaded from: classes2.dex */
public final class C0885h {

    /* renamed from: a */
    @NotNull
    public static String f329a = "sagjcm886@gmail.com";

    /* renamed from: b */
    public static boolean f330b = true;

    @NotNull
    /* renamed from: a */
    public static final String m209a() {
        Intrinsics.checkNotNullParameter("novel_theme_position", "key");
        Intrinsics.checkNotNullParameter("", "default");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        String string = sharedPreferences.getString("novel_theme_position", "");
        Intrinsics.checkNotNull(string);
        return string;
    }

    @NotNull
    /* renamed from: b */
    public static final String m210b() {
        Intrinsics.checkNotNullParameter("novel_text_size", "key");
        Intrinsics.checkNotNullParameter("", "default");
        ApplicationC2828a applicationC2828a = C2827a.f7670a;
        if (applicationC2828a == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
        Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
        String string = sharedPreferences.getString("novel_text_size", "");
        Intrinsics.checkNotNull(string);
        return string;
    }
}
