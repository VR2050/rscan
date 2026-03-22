package android.view;

import androidx.annotation.IdRes;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a\u001b\u0010\u0004\u001a\u00020\u0003*\u00020\u00002\b\b\u0001\u0010\u0002\u001a\u00020\u0001¢\u0006\u0004\b\u0004\u0010\u0005¨\u0006\u0006"}, m5311d2 = {"Landroid/app/Activity;", "", "viewId", "Landroidx/navigation/NavController;", "findNavController", "(Landroid/app/Activity;I)Landroidx/navigation/NavController;", "navigation-runtime-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* renamed from: androidx.navigation.ActivityKt, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public final class Activity {
    @NotNull
    public static final NavController findNavController(@NotNull android.app.Activity findNavController, @IdRes int i2) {
        Intrinsics.checkParameterIsNotNull(findNavController, "$this$findNavController");
        NavController findNavController2 = Navigation.findNavController(findNavController, i2);
        Intrinsics.checkExpressionValueIsNotNull(findNavController2, "Navigation.findNavController(this, viewId)");
        return findNavController2;
    }
}
