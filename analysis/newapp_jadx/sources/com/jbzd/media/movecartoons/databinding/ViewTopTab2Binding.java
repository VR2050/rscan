package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.flyco.tablayout.SlidingTabLayout;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class ViewTopTab2Binding implements ViewBinding {

    @NonNull
    private final SlidingTabLayout rootView;

    @NonNull
    public final SlidingTabLayout tabLayout;

    private ViewTopTab2Binding(@NonNull SlidingTabLayout slidingTabLayout, @NonNull SlidingTabLayout slidingTabLayout2) {
        this.rootView = slidingTabLayout;
        this.tabLayout = slidingTabLayout2;
    }

    @NonNull
    public static ViewTopTab2Binding bind(@NonNull View view) {
        Objects.requireNonNull(view, "rootView");
        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view;
        return new ViewTopTab2Binding(slidingTabLayout, slidingTabLayout);
    }

    @NonNull
    public static ViewTopTab2Binding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ViewTopTab2Binding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.view_top_tab2, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public SlidingTabLayout getRoot() {
        return this.rootView;
    }
}
