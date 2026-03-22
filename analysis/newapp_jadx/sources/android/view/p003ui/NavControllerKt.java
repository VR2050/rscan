package android.view.p003ui;

import android.view.NavController;
import android.view.NavGraph;
import android.view.p003ui.AppBarConfiguration;
import androidx.customview.widget.Openable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a\u001b\u0010\u0004\u001a\u00020\u0003*\u00020\u00002\b\u0010\u0002\u001a\u0004\u0018\u00010\u0001¢\u0006\u0004\b\u0004\u0010\u0005\u001a\u0019\u0010\u0004\u001a\u00020\u0003*\u00020\u00002\u0006\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\u0004\u0010\b¨\u0006\t"}, m5311d2 = {"Landroidx/navigation/NavController;", "Landroidx/customview/widget/Openable;", "drawerLayout", "", "navigateUp", "(Landroidx/navigation/NavController;Landroidx/customview/widget/Openable;)Z", "Landroidx/navigation/ui/AppBarConfiguration;", "appBarConfiguration", "(Landroidx/navigation/NavController;Landroidx/navigation/ui/AppBarConfiguration;)Z", "navigation-ui-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class NavControllerKt {
    public static final boolean navigateUp(@NotNull NavController navigateUp, @Nullable Openable openable) {
        Intrinsics.checkParameterIsNotNull(navigateUp, "$this$navigateUp");
        NavGraph graph = navigateUp.getGraph();
        Intrinsics.checkExpressionValueIsNotNull(graph, "graph");
        AppBarConfigurationKt$AppBarConfiguration$1 appBarConfigurationKt$AppBarConfiguration$1 = AppBarConfigurationKt$AppBarConfiguration$1.INSTANCE;
        AppBarConfiguration.Builder openableLayout = new AppBarConfiguration.Builder(graph).setOpenableLayout(openable);
        Object obj = appBarConfigurationKt$AppBarConfiguration$1;
        if (appBarConfigurationKt$AppBarConfiguration$1 != null) {
            obj = new C0578x56421ee5(appBarConfigurationKt$AppBarConfiguration$1);
        }
        AppBarConfiguration build = openableLayout.setFallbackOnNavigateUpListener((AppBarConfiguration.OnNavigateUpListener) obj).build();
        Intrinsics.checkExpressionValueIsNotNull(build, "AppBarConfiguration.Buil…eUpListener)\n    .build()");
        return NavigationUI.navigateUp(navigateUp, build);
    }

    public static final boolean navigateUp(@NotNull NavController navigateUp, @NotNull AppBarConfiguration appBarConfiguration) {
        Intrinsics.checkParameterIsNotNull(navigateUp, "$this$navigateUp");
        Intrinsics.checkParameterIsNotNull(appBarConfiguration, "appBarConfiguration");
        return NavigationUI.navigateUp(navigateUp, appBarConfiguration);
    }
}
