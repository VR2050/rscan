package android.view.fragment;

import android.view.NavGraphBuilder;
import android.view.Navigator;
import androidx.annotation.IdRes;
import androidx.fragment.app.Fragment;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a*\u0010\u0006\u001a\u00020\u0005\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u0000*\u00020\u00022\b\b\u0001\u0010\u0004\u001a\u00020\u0003H\u0086\b¢\u0006\u0004\b\u0006\u0010\u0007\u001aC\u0010\u0006\u001a\u00020\u0005\"\n\b\u0000\u0010\u0001\u0018\u0001*\u00020\u0000*\u00020\u00022\b\b\u0001\u0010\u0004\u001a\u00020\u00032\u0017\u0010\u000b\u001a\u0013\u0012\u0004\u0012\u00020\t\u0012\u0004\u0012\u00020\u00050\b¢\u0006\u0002\b\nH\u0086\b¢\u0006\u0004\b\u0006\u0010\f¨\u0006\r"}, m5311d2 = {"Landroidx/fragment/app/Fragment;", "F", "Landroidx/navigation/NavGraphBuilder;", "", "id", "", "fragment", "(Landroidx/navigation/NavGraphBuilder;I)V", "Lkotlin/Function1;", "Landroidx/navigation/fragment/FragmentNavigatorDestinationBuilder;", "Lkotlin/ExtensionFunctionType;", "builder", "(Landroidx/navigation/NavGraphBuilder;ILkotlin/jvm/functions/Function1;)V", "navigation-fragment-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class FragmentNavigatorDestinationBuilderKt {
    public static final /* synthetic */ <F extends Fragment> void fragment(@NotNull NavGraphBuilder fragment, @IdRes int i2, @NotNull Function1<? super FragmentNavigatorDestinationBuilder, Unit> builder) {
        Intrinsics.checkParameterIsNotNull(fragment, "$this$fragment");
        Intrinsics.checkParameterIsNotNull(builder, "builder");
        Navigator navigator = fragment.getProvider().getNavigator((Class<Navigator>) FragmentNavigator.class);
        Intrinsics.checkExpressionValueIsNotNull(navigator, "getNavigator(clazz.java)");
        Intrinsics.reifiedOperationMarker(4, "F");
        FragmentNavigatorDestinationBuilder fragmentNavigatorDestinationBuilder = new FragmentNavigatorDestinationBuilder((FragmentNavigator) navigator, i2, Reflection.getOrCreateKotlinClass(Fragment.class));
        builder.invoke(fragmentNavigatorDestinationBuilder);
        fragment.destination(fragmentNavigatorDestinationBuilder);
    }

    public static final /* synthetic */ <F extends Fragment> void fragment(@NotNull NavGraphBuilder fragment, @IdRes int i2) {
        Intrinsics.checkParameterIsNotNull(fragment, "$this$fragment");
        Navigator navigator = fragment.getProvider().getNavigator((Class<Navigator>) FragmentNavigator.class);
        Intrinsics.checkExpressionValueIsNotNull(navigator, "getNavigator(clazz.java)");
        Intrinsics.reifiedOperationMarker(4, "F");
        fragment.destination(new FragmentNavigatorDestinationBuilder((FragmentNavigator) navigator, i2, Reflection.getOrCreateKotlinClass(Fragment.class)));
    }
}
