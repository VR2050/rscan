package android.view;

import android.app.Activity;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.Navigator;
import androidx.annotation.IdRes;
import androidx.annotation.NavigationRes;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.app.TaskStackBuilder;
import java.util.ArrayDeque;
import java.util.Iterator;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public final class NavDeepLinkBuilder {
    private Bundle mArgs;
    private final Context mContext;
    private int mDestId;
    private NavGraph mGraph;
    private final Intent mIntent;

    public static class PermissiveNavigatorProvider extends NavigatorProvider {
        private final Navigator<NavDestination> mDestNavigator = new Navigator<NavDestination>() { // from class: androidx.navigation.NavDeepLinkBuilder.PermissiveNavigatorProvider.1
            @Override // android.view.Navigator
            @NonNull
            public NavDestination createDestination() {
                return new NavDestination("permissive");
            }

            @Override // android.view.Navigator
            @Nullable
            public NavDestination navigate(@NonNull NavDestination navDestination, @Nullable Bundle bundle, @Nullable NavOptions navOptions, @Nullable Navigator.Extras extras) {
                throw new IllegalStateException("navigate is not supported");
            }

            @Override // android.view.Navigator
            public boolean popBackStack() {
                throw new IllegalStateException("popBackStack is not supported");
            }
        };

        public PermissiveNavigatorProvider() {
            addNavigator(new NavGraphNavigator(this));
        }

        @Override // android.view.NavigatorProvider
        @NonNull
        public Navigator<? extends NavDestination> getNavigator(@NonNull String str) {
            try {
                return super.getNavigator(str);
            } catch (IllegalStateException unused) {
                return this.mDestNavigator;
            }
        }
    }

    public NavDeepLinkBuilder(@NonNull Context context) {
        this.mContext = context;
        if (context instanceof Activity) {
            this.mIntent = new Intent(context, context.getClass());
        } else {
            Intent launchIntentForPackage = context.getPackageManager().getLaunchIntentForPackage(context.getPackageName());
            this.mIntent = launchIntentForPackage == null ? new Intent() : launchIntentForPackage;
        }
        this.mIntent.addFlags(268468224);
    }

    private void fillInIntent() {
        ArrayDeque arrayDeque = new ArrayDeque();
        arrayDeque.add(this.mGraph);
        NavDestination navDestination = null;
        while (!arrayDeque.isEmpty() && navDestination == null) {
            NavDestination navDestination2 = (NavDestination) arrayDeque.poll();
            if (navDestination2.getId() == this.mDestId) {
                navDestination = navDestination2;
            } else if (navDestination2 instanceof NavGraph) {
                Iterator<NavDestination> it = ((NavGraph) navDestination2).iterator();
                while (it.hasNext()) {
                    arrayDeque.add(it.next());
                }
            }
        }
        if (navDestination != null) {
            this.mIntent.putExtra(NavController.KEY_DEEP_LINK_IDS, navDestination.buildDeepLinkIds());
        } else {
            StringBuilder m591M = C1499a.m591M("Navigation destination ", NavDestination.getDisplayName(this.mContext, this.mDestId), " cannot be found in the navigation graph ");
            m591M.append(this.mGraph);
            throw new IllegalArgumentException(m591M.toString());
        }
    }

    @NonNull
    public PendingIntent createPendingIntent() {
        Bundle bundle = this.mArgs;
        int i2 = 0;
        if (bundle != null) {
            Iterator<String> it = bundle.keySet().iterator();
            int i3 = 0;
            while (it.hasNext()) {
                Object obj = this.mArgs.get(it.next());
                i3 = (i3 * 31) + (obj != null ? obj.hashCode() : 0);
            }
            i2 = i3;
        }
        return createTaskStackBuilder().getPendingIntent((i2 * 31) + this.mDestId, 134217728);
    }

    @NonNull
    public TaskStackBuilder createTaskStackBuilder() {
        if (this.mIntent.getIntArrayExtra(NavController.KEY_DEEP_LINK_IDS) == null) {
            if (this.mGraph == null) {
                throw new IllegalStateException("You must call setGraph() before constructing the deep link");
            }
            throw new IllegalStateException("You must call setDestination() before constructing the deep link");
        }
        TaskStackBuilder addNextIntentWithParentStack = TaskStackBuilder.create(this.mContext).addNextIntentWithParentStack(new Intent(this.mIntent));
        for (int i2 = 0; i2 < addNextIntentWithParentStack.getIntentCount(); i2++) {
            addNextIntentWithParentStack.editIntentAt(i2).putExtra(NavController.KEY_DEEP_LINK_INTENT, this.mIntent);
        }
        return addNextIntentWithParentStack;
    }

    @NonNull
    public NavDeepLinkBuilder setArguments(@Nullable Bundle bundle) {
        this.mArgs = bundle;
        this.mIntent.putExtra(NavController.KEY_DEEP_LINK_EXTRAS, bundle);
        return this;
    }

    @NonNull
    public NavDeepLinkBuilder setComponentName(@NonNull Class<? extends Activity> cls) {
        return setComponentName(new ComponentName(this.mContext, cls));
    }

    @NonNull
    public NavDeepLinkBuilder setDestination(@IdRes int i2) {
        this.mDestId = i2;
        if (this.mGraph != null) {
            fillInIntent();
        }
        return this;
    }

    @NonNull
    public NavDeepLinkBuilder setGraph(@NavigationRes int i2) {
        return setGraph(new NavInflater(this.mContext, new PermissiveNavigatorProvider()).inflate(i2));
    }

    @NonNull
    public NavDeepLinkBuilder setComponentName(@NonNull ComponentName componentName) {
        this.mIntent.setComponent(componentName);
        return this;
    }

    @NonNull
    public NavDeepLinkBuilder setGraph(@NonNull NavGraph navGraph) {
        this.mGraph = navGraph;
        if (this.mDestId != 0) {
            fillInIntent();
        }
        return this;
    }

    public NavDeepLinkBuilder(@NonNull NavController navController) {
        this(navController.getContext());
        this.mGraph = navController.getGraph();
    }
}
