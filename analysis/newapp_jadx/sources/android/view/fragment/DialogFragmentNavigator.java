package android.view.fragment;

import android.content.Context;
import android.content.res.TypedArray;
import android.os.Bundle;
import android.util.AttributeSet;
import android.view.FloatingWindow;
import android.view.NavDestination;
import android.view.NavOptions;
import android.view.Navigator;
import android.view.NavigatorProvider;
import androidx.annotation.CallSuper;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleEventObserver;
import androidx.lifecycle.LifecycleOwner;
import p005b.p131d.p132a.p133a.C1499a;

@Navigator.Name("dialog")
/* loaded from: classes.dex */
public final class DialogFragmentNavigator extends Navigator<Destination> {
    private static final String DIALOG_TAG = "androidx-nav-fragment:navigator:dialog:";
    private static final String KEY_DIALOG_COUNT = "androidx-nav-dialogfragment:navigator:count";
    private static final String TAG = "DialogFragmentNavigator";
    private final Context mContext;
    private final FragmentManager mFragmentManager;
    private int mDialogCount = 0;
    private LifecycleEventObserver mObserver = new LifecycleEventObserver() { // from class: androidx.navigation.fragment.DialogFragmentNavigator.1
        @Override // androidx.lifecycle.LifecycleEventObserver
        public void onStateChanged(@NonNull LifecycleOwner lifecycleOwner, @NonNull Lifecycle.Event event) {
            if (event == Lifecycle.Event.ON_STOP) {
                DialogFragment dialogFragment = (DialogFragment) lifecycleOwner;
                if (dialogFragment.requireDialog().isShowing()) {
                    return;
                }
                NavHostFragment.findNavController(dialogFragment).popBackStack();
            }
        }
    };

    @NavDestination.ClassType(DialogFragment.class)
    public static class Destination extends NavDestination implements FloatingWindow {
        private String mClassName;

        public Destination(@NonNull NavigatorProvider navigatorProvider) {
            this((Navigator<? extends Destination>) navigatorProvider.getNavigator(DialogFragmentNavigator.class));
        }

        @NonNull
        public final String getClassName() {
            String str = this.mClassName;
            if (str != null) {
                return str;
            }
            throw new IllegalStateException("DialogFragment class was not set");
        }

        @Override // android.view.NavDestination
        @CallSuper
        public void onInflate(@NonNull Context context, @NonNull AttributeSet attributeSet) {
            super.onInflate(context, attributeSet);
            TypedArray obtainAttributes = context.getResources().obtainAttributes(attributeSet, C0574R.styleable.DialogFragmentNavigator);
            String string = obtainAttributes.getString(C0574R.styleable.DialogFragmentNavigator_android_name);
            if (string != null) {
                setClassName(string);
            }
            obtainAttributes.recycle();
        }

        @NonNull
        public final Destination setClassName(@NonNull String str) {
            this.mClassName = str;
            return this;
        }

        public Destination(@NonNull Navigator<? extends Destination> navigator) {
            super(navigator);
        }
    }

    public DialogFragmentNavigator(@NonNull Context context, @NonNull FragmentManager fragmentManager) {
        this.mContext = context;
        this.mFragmentManager = fragmentManager;
    }

    @Override // android.view.Navigator
    public void onRestoreState(@Nullable Bundle bundle) {
        if (bundle != null) {
            this.mDialogCount = bundle.getInt(KEY_DIALOG_COUNT, 0);
            for (int i2 = 0; i2 < this.mDialogCount; i2++) {
                DialogFragment dialogFragment = (DialogFragment) this.mFragmentManager.findFragmentByTag(DIALOG_TAG + i2);
                if (dialogFragment == null) {
                    throw new IllegalStateException(C1499a.m628n("DialogFragment ", i2, " doesn't exist in the FragmentManager"));
                }
                dialogFragment.getLifecycle().addObserver(this.mObserver);
            }
        }
    }

    @Override // android.view.Navigator
    @Nullable
    public Bundle onSaveState() {
        if (this.mDialogCount == 0) {
            return null;
        }
        Bundle bundle = new Bundle();
        bundle.putInt(KEY_DIALOG_COUNT, this.mDialogCount);
        return bundle;
    }

    @Override // android.view.Navigator
    public boolean popBackStack() {
        if (this.mDialogCount == 0 || this.mFragmentManager.isStateSaved()) {
            return false;
        }
        FragmentManager fragmentManager = this.mFragmentManager;
        StringBuilder m586H = C1499a.m586H(DIALOG_TAG);
        int i2 = this.mDialogCount - 1;
        this.mDialogCount = i2;
        m586H.append(i2);
        Fragment findFragmentByTag = fragmentManager.findFragmentByTag(m586H.toString());
        if (findFragmentByTag != null) {
            findFragmentByTag.getLifecycle().removeObserver(this.mObserver);
            ((DialogFragment) findFragmentByTag).dismiss();
        }
        return true;
    }

    @Override // android.view.Navigator
    @NonNull
    public Destination createDestination() {
        return new Destination(this);
    }

    @Override // android.view.Navigator
    @Nullable
    public NavDestination navigate(@NonNull Destination destination, @Nullable Bundle bundle, @Nullable NavOptions navOptions, @Nullable Navigator.Extras extras) {
        if (this.mFragmentManager.isStateSaved()) {
            return null;
        }
        String className = destination.getClassName();
        if (className.charAt(0) == '.') {
            className = this.mContext.getPackageName() + className;
        }
        Fragment instantiate = this.mFragmentManager.getFragmentFactory().instantiate(this.mContext.getClassLoader(), className);
        if (!DialogFragment.class.isAssignableFrom(instantiate.getClass())) {
            StringBuilder m586H = C1499a.m586H("Dialog destination ");
            m586H.append(destination.getClassName());
            m586H.append(" is not an instance of DialogFragment");
            throw new IllegalArgumentException(m586H.toString());
        }
        DialogFragment dialogFragment = (DialogFragment) instantiate;
        dialogFragment.setArguments(bundle);
        dialogFragment.getLifecycle().addObserver(this.mObserver);
        FragmentManager fragmentManager = this.mFragmentManager;
        StringBuilder m586H2 = C1499a.m586H(DIALOG_TAG);
        int i2 = this.mDialogCount;
        this.mDialogCount = i2 + 1;
        m586H2.append(i2);
        dialogFragment.show(fragmentManager, m586H2.toString());
        return destination;
    }
}
