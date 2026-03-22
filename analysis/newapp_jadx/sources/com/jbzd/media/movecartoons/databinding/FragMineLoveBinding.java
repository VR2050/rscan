package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.appbar.AppBarLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragMineLoveBinding implements ViewBinding {

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    public final LinearLayout llAppbarLayout;

    @NonNull
    public final RelativeLayout rlShortLayout;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final RecyclerView rvTop;

    private FragMineLoveBinding(@NonNull RelativeLayout relativeLayout, @NonNull AppBarLayout appBarLayout, @NonNull FrameLayout frameLayout, @NonNull LinearLayout linearLayout, @NonNull RelativeLayout relativeLayout2, @NonNull RecyclerView recyclerView) {
        this.rootView = relativeLayout;
        this.appBarLayout = appBarLayout;
        this.fragContent = frameLayout;
        this.llAppbarLayout = linearLayout;
        this.rlShortLayout = relativeLayout2;
        this.rvTop = recyclerView;
    }

    @NonNull
    public static FragMineLoveBinding bind(@NonNull View view) {
        int i2 = R.id.app_bar_layout;
        AppBarLayout appBarLayout = (AppBarLayout) view.findViewById(R.id.app_bar_layout);
        if (appBarLayout != null) {
            i2 = R.id.frag_content;
            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
            if (frameLayout != null) {
                i2 = R.id.ll_appbarLayout;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_appbarLayout);
                if (linearLayout != null) {
                    i2 = R.id.rl_shortLayout;
                    RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_shortLayout);
                    if (relativeLayout != null) {
                        i2 = R.id.rv_top;
                        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_top);
                        if (recyclerView != null) {
                            return new FragMineLoveBinding((RelativeLayout) view, appBarLayout, frameLayout, linearLayout, relativeLayout, recyclerView);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragMineLoveBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragMineLoveBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_mine_love, viewGroup, false);
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
