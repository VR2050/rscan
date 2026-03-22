package android.view;

import android.os.Bundle;
import android.view.Navigator;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;
import p005b.p131d.p132a.p133a.C1499a;

@Navigator.Name(NotificationCompat.CATEGORY_NAVIGATION)
/* loaded from: classes.dex */
public class NavGraphNavigator extends Navigator<NavGraph> {
    private final NavigatorProvider mNavigatorProvider;

    public NavGraphNavigator(@NonNull NavigatorProvider navigatorProvider) {
        this.mNavigatorProvider = navigatorProvider;
    }

    @Override // android.view.Navigator
    public boolean popBackStack() {
        return true;
    }

    @Override // android.view.Navigator
    @NonNull
    public NavGraph createDestination() {
        return new NavGraph(this);
    }

    @Override // android.view.Navigator
    @Nullable
    public NavDestination navigate(@NonNull NavGraph navGraph, @Nullable Bundle bundle, @Nullable NavOptions navOptions, @Nullable Navigator.Extras extras) {
        int startDestination = navGraph.getStartDestination();
        if (startDestination == 0) {
            StringBuilder m586H = C1499a.m586H("no start destination defined via app:startDestination for ");
            m586H.append(navGraph.getDisplayName());
            throw new IllegalStateException(m586H.toString());
        }
        NavDestination findNode = navGraph.findNode(startDestination, false);
        if (findNode != null) {
            return this.mNavigatorProvider.getNavigator(findNode.getNavigatorName()).navigate(findNode, findNode.addInDefaultArgs(bundle), navOptions, extras);
        }
        throw new IllegalArgumentException(C1499a.m639y("navigation destination ", navGraph.getStartDestDisplayName(), " is not a direct child of this NavGraph"));
    }
}
