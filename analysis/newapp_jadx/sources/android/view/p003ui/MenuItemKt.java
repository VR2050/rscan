package android.view.p003ui;

import android.view.MenuItem;
import android.view.NavController;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0012\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0003\u001a\u0019\u0010\u0004\u001a\u00020\u0003*\u00020\u00002\u0006\u0010\u0002\u001a\u00020\u0001¢\u0006\u0004\b\u0004\u0010\u0005¨\u0006\u0006"}, m5311d2 = {"Landroid/view/MenuItem;", "Landroidx/navigation/NavController;", "navController", "", "onNavDestinationSelected", "(Landroid/view/MenuItem;Landroidx/navigation/NavController;)Z", "navigation-ui-ktx_release"}, m5312k = 2, m5313mv = {1, 4, 0})
/* loaded from: classes.dex */
public final class MenuItemKt {
    public static final boolean onNavDestinationSelected(@NotNull MenuItem onNavDestinationSelected, @NotNull NavController navController) {
        Intrinsics.checkParameterIsNotNull(onNavDestinationSelected, "$this$onNavDestinationSelected");
        Intrinsics.checkParameterIsNotNull(navController, "navController");
        return NavigationUI.onNavDestinationSelected(onNavDestinationSelected, navController);
    }
}
