package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.google.android.material.appbar.AppBarLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragDarkPlayHomeBinding implements ViewBinding {

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SlidingTabLayout slidingTabLayout;

    @NonNull
    public final ViewPager vpContent;

    private FragDarkPlayHomeBinding(@NonNull LinearLayout linearLayout, @NonNull AppBarLayout appBarLayout, @NonNull SlidingTabLayout slidingTabLayout, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.appBarLayout = appBarLayout;
        this.slidingTabLayout = slidingTabLayout;
        this.vpContent = viewPager;
    }

    @NonNull
    public static FragDarkPlayHomeBinding bind(@NonNull View view) {
        int i2 = R.id.app_bar_layout;
        AppBarLayout appBarLayout = (AppBarLayout) view.findViewById(R.id.app_bar_layout);
        if (appBarLayout != null) {
            i2 = R.id.sliding_tab_layout;
            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.sliding_tab_layout);
            if (slidingTabLayout != null) {
                i2 = R.id.vp_content;
                ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
                if (viewPager != null) {
                    return new FragDarkPlayHomeBinding((LinearLayout) view, appBarLayout, slidingTabLayout, viewPager);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragDarkPlayHomeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragDarkPlayHomeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_dark_play_home, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
