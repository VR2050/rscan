package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.flyco.tablayout.CommonTabLayout;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class ViewCanvasTabBinding implements ViewBinding {

    @NonNull
    private final CommonTabLayout rootView;

    @NonNull
    public final CommonTabLayout tabLayout;

    private ViewCanvasTabBinding(@NonNull CommonTabLayout commonTabLayout, @NonNull CommonTabLayout commonTabLayout2) {
        this.rootView = commonTabLayout;
        this.tabLayout = commonTabLayout2;
    }

    @NonNull
    public static ViewCanvasTabBinding bind(@NonNull View view) {
        Objects.requireNonNull(view, "rootView");
        CommonTabLayout commonTabLayout = (CommonTabLayout) view;
        return new ViewCanvasTabBinding(commonTabLayout, commonTabLayout);
    }

    @NonNull
    public static ViewCanvasTabBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ViewCanvasTabBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.view_canvas_tab, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public CommonTabLayout getRoot() {
        return this.rootView;
    }
}
