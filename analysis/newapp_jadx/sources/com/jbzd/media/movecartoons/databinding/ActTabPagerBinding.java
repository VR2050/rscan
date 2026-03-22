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
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActTabPagerBinding implements ViewBinding {

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SlidingTabLayout tabLayout;

    @NonNull
    public final ViewPager vpContent;

    private ActTabPagerBinding(@NonNull LinearLayout linearLayout, @NonNull SlidingTabLayout slidingTabLayout, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.tabLayout = slidingTabLayout;
        this.vpContent = viewPager;
    }

    @NonNull
    public static ActTabPagerBinding bind(@NonNull View view) {
        int i2 = R.id.tabLayout;
        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tabLayout);
        if (slidingTabLayout != null) {
            i2 = R.id.vp_content;
            ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
            if (viewPager != null) {
                return new ActTabPagerBinding((LinearLayout) view, slidingTabLayout, viewPager);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActTabPagerBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActTabPagerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_tab_pager, viewGroup, false);
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
