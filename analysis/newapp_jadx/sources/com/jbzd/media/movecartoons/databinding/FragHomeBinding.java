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
public final class FragHomeBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llDeepDarkTab;

    @NonNull
    public final LinearLayout llNodata;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SlidingTabLayout tabLayout;

    @NonNull
    public final SlidingTabLayout tabLayoutDeepDark;

    @NonNull
    public final ViewPager vpContent;

    private FragHomeBinding(@NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull SlidingTabLayout slidingTabLayout, @NonNull SlidingTabLayout slidingTabLayout2, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.llDeepDarkTab = linearLayout2;
        this.llNodata = linearLayout3;
        this.llTop = linearLayout4;
        this.tabLayout = slidingTabLayout;
        this.tabLayoutDeepDark = slidingTabLayout2;
        this.vpContent = viewPager;
    }

    @NonNull
    public static FragHomeBinding bind(@NonNull View view) {
        int i2 = R.id.ll_deep_dark_tab;
        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_deep_dark_tab);
        if (linearLayout != null) {
            i2 = R.id.ll_nodata;
            LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_nodata);
            if (linearLayout2 != null) {
                i2 = R.id.ll_top;
                LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_top);
                if (linearLayout3 != null) {
                    i2 = R.id.tabLayout;
                    SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tabLayout);
                    if (slidingTabLayout != null) {
                        i2 = R.id.tabLayout_deep_dark;
                        SlidingTabLayout slidingTabLayout2 = (SlidingTabLayout) view.findViewById(R.id.tabLayout_deep_dark);
                        if (slidingTabLayout2 != null) {
                            i2 = R.id.vp_content;
                            ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
                            if (viewPager != null) {
                                return new FragHomeBinding((LinearLayout) view, linearLayout, linearLayout2, linearLayout3, slidingTabLayout, slidingTabLayout2, viewPager);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragHomeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragHomeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_home, viewGroup, false);
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
