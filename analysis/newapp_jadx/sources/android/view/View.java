package android.view;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a\u0011\u0010\u0002\u001a\u00020\u0001*\u00020\u0000¢\u0006\u0004\b\u0002\u0010\u0003¨\u0006\u0004"}, m5311d2 = {"Landroid/view/View;", "Landroidx/navigation/NavController;", "findNavController", "(Landroid/view/View;)Landroidx/navigation/NavController;", "navigation-runtime-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* renamed from: androidx.navigation.ViewKt, reason: from Kotlin metadata */
/* loaded from: classes.dex */
public final class View {
    @NotNull
    public static final NavController findNavController(@NotNull android.view.View findNavController) {
        Intrinsics.checkParameterIsNotNull(findNavController, "$this$findNavController");
        NavController findNavController2 = Navigation.findNavController(findNavController);
        Intrinsics.checkExpressionValueIsNotNull(findNavController2, "Navigation.findNavController(this)");
        return findNavController2;
    }
}
