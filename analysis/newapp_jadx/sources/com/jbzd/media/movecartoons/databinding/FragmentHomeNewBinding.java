package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.angcyo.tablayout.DslTabLayout;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragmentHomeNewBinding implements ViewBinding {

    @NonNull
    public final TextView ivHomeNewSearch;

    @NonNull
    public final ImageTextView ivHomeNewSign;

    @NonNull
    public final ImageTextView ivHomeNewVip;

    @NonNull
    public final LinearLayout llNodata;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SlidingTabLayout tabLayout;

    @NonNull
    public final DslTabLayout tabLayoutBcy;

    @NonNull
    public final ViewPager vpContentBcy;

    private FragmentHomeNewBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull SlidingTabLayout slidingTabLayout, @NonNull DslTabLayout dslTabLayout, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.ivHomeNewSearch = textView;
        this.ivHomeNewSign = imageTextView;
        this.ivHomeNewVip = imageTextView2;
        this.llNodata = linearLayout2;
        this.llTop = linearLayout3;
        this.tabLayout = slidingTabLayout;
        this.tabLayoutBcy = dslTabLayout;
        this.vpContentBcy = viewPager;
    }

    @NonNull
    public static FragmentHomeNewBinding bind(@NonNull View view) {
        int i2 = R.id.iv_home_new_search;
        TextView textView = (TextView) view.findViewById(R.id.iv_home_new_search);
        if (textView != null) {
            i2 = R.id.iv_home_new_sign;
            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.iv_home_new_sign);
            if (imageTextView != null) {
                i2 = R.id.iv_home_new_vip;
                ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.iv_home_new_vip);
                if (imageTextView2 != null) {
                    i2 = R.id.ll_nodata;
                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_nodata);
                    if (linearLayout != null) {
                        i2 = R.id.ll_top;
                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_top);
                        if (linearLayout2 != null) {
                            i2 = R.id.tabLayout;
                            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tabLayout);
                            if (slidingTabLayout != null) {
                                i2 = R.id.tabLayout_bcy;
                                DslTabLayout dslTabLayout = (DslTabLayout) view.findViewById(R.id.tabLayout_bcy);
                                if (dslTabLayout != null) {
                                    i2 = R.id.vp_content_bcy;
                                    ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content_bcy);
                                    if (viewPager != null) {
                                        return new FragmentHomeNewBinding((LinearLayout) view, textView, imageTextView, imageTextView2, linearLayout, linearLayout2, slidingTabLayout, dslTabLayout, viewPager);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragmentHomeNewBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragmentHomeNewBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.fragment_home_new, viewGroup, false);
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
