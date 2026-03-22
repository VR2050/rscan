package android.view;

import androidx.annotation.IdRes;
import androidx.core.app.NotificationCompat;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\u001aA\u0010\n\u001a\u00020\t*\u00020\u00002\b\b\u0003\u0010\u0002\u001a\u00020\u00012\b\b\u0001\u0010\u0003\u001a\u00020\u00012\u0017\u0010\b\u001a\u0013\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004¢\u0006\u0002\b\u0007H\u0086\b¢\u0006\u0004\b\n\u0010\u000b\u001aA\u0010\n\u001a\u00020\u0006*\u00020\u00052\b\b\u0001\u0010\u0002\u001a\u00020\u00012\b\b\u0001\u0010\u0003\u001a\u00020\u00012\u0017\u0010\b\u001a\u0013\u0012\u0004\u0012\u00020\u0005\u0012\u0004\u0012\u00020\u00060\u0004¢\u0006\u0002\b\u0007H\u0086\b¢\u0006\u0004\b\n\u0010\f¨\u0006\r"}, m5311d2 = {"Landroidx/navigation/NavigatorProvider;", "", "id", "startDestination", "Lkotlin/Function1;", "Landroidx/navigation/NavGraphBuilder;", "", "Lkotlin/ExtensionFunctionType;", "builder", "Landroidx/navigation/NavGraph;", NotificationCompat.CATEGORY_NAVIGATION, "(Landroidx/navigation/NavigatorProvider;IILkotlin/jvm/functions/Function1;)Landroidx/navigation/NavGraph;", "(Landroidx/navigation/NavGraphBuilder;IILkotlin/jvm/functions/Function1;)V", "navigation-common-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class NavGraphBuilderKt {
    @NotNull
    public static final NavGraph navigation(@NotNull NavigatorProvider navigation, @IdRes int i2, @IdRes int i3, @NotNull Function1<? super NavGraphBuilder, Unit> builder) {
        Intrinsics.checkParameterIsNotNull(navigation, "$this$navigation");
        Intrinsics.checkParameterIsNotNull(builder, "builder");
        NavGraphBuilder navGraphBuilder = new NavGraphBuilder(navigation, i2, i3);
        builder.invoke(navGraphBuilder);
        return navGraphBuilder.build();
    }

    public static /* synthetic */ NavGraph navigation$default(NavigatorProvider navigation, int i2, int i3, Function1 builder, int i4, Object obj) {
        if ((i4 & 1) != 0) {
            i2 = 0;
        }
        Intrinsics.checkParameterIsNotNull(navigation, "$this$navigation");
        Intrinsics.checkParameterIsNotNull(builder, "builder");
        NavGraphBuilder navGraphBuilder = new NavGraphBuilder(navigation, i2, i3);
        builder.invoke(navGraphBuilder);
        return navGraphBuilder.build();
    }

    public static final void navigation(@NotNull NavGraphBuilder navigation, @IdRes int i2, @IdRes int i3, @NotNull Function1<? super NavGraphBuilder, Unit> builder) {
        Intrinsics.checkParameterIsNotNull(navigation, "$this$navigation");
        Intrinsics.checkParameterIsNotNull(builder, "builder");
        NavGraphBuilder navGraphBuilder = new NavGraphBuilder(navigation.getProvider(), i2, i3);
        builder.invoke(navGraphBuilder);
        navigation.destination(navGraphBuilder);
    }
}
