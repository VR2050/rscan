package android.view.fragment;

import android.view.NavController;
import androidx.fragment.app.Fragment;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a\u0011\u0010\u0002\u001a\u00020\u0001*\u00020\u0000¢\u0006\u0004\b\u0002\u0010\u0003¨\u0006\u0004"}, m5311d2 = {"Landroidx/fragment/app/Fragment;", "Landroidx/navigation/NavController;", "findNavController", "(Landroidx/fragment/app/Fragment;)Landroidx/navigation/NavController;", "navigation-fragment-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class FragmentKt {
    @NotNull
    public static final NavController findNavController(@NotNull Fragment findNavController) {
        Intrinsics.checkParameterIsNotNull(findNavController, "$this$findNavController");
        NavController findNavController2 = NavHostFragment.findNavController(findNavController);
        Intrinsics.checkExpressionValueIsNotNull(findNavController2, "NavHostFragment.findNavController(this)");
        return findNavController2;
    }
}
