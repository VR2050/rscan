package android.view;

import android.os.Bundle;
import android.view.Navigator;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RestrictTo;

@Navigator.Name("NoOp")
@RestrictTo({RestrictTo.Scope.LIBRARY_GROUP})
/* loaded from: classes.dex */
public class NoOpNavigator extends Navigator<NavDestination> {
    @Override // android.view.Navigator
    @NonNull
    public NavDestination createDestination() {
        return new NavDestination(this);
    }

    @Override // android.view.Navigator
    @Nullable
    public NavDestination navigate(@NonNull NavDestination navDestination, @Nullable Bundle bundle, @Nullable NavOptions navOptions, @Nullable Navigator.Extras extras) {
        return navDestination;
    }

    @Override // android.view.Navigator
    public boolean popBackStack() {
        return true;
    }
}
