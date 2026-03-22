package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragSearchBottomBinding implements ViewBinding {

    @NonNull
    public final FrameLayout errorView;

    @NonNull
    public final CoordinatorLayout layoutSearchEmpty;

    @NonNull
    private final RelativeLayout rootView;

    private FragSearchBottomBinding(@NonNull RelativeLayout relativeLayout, @NonNull FrameLayout frameLayout, @NonNull CoordinatorLayout coordinatorLayout) {
        this.rootView = relativeLayout;
        this.errorView = frameLayout;
        this.layoutSearchEmpty = coordinatorLayout;
    }

    @NonNull
    public static FragSearchBottomBinding bind(@NonNull View view) {
        int i2 = R.id.error_view;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.error_view);
        if (frameLayout != null) {
            i2 = R.id.layout_search_empty;
            CoordinatorLayout coordinatorLayout = (CoordinatorLayout) view.findViewById(R.id.layout_search_empty);
            if (coordinatorLayout != null) {
                return new FragSearchBottomBinding((RelativeLayout) view, frameLayout, coordinatorLayout);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragSearchBottomBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragSearchBottomBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_search_bottom, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RelativeLayout getRoot() {
        return this.rootView;
    }
}
