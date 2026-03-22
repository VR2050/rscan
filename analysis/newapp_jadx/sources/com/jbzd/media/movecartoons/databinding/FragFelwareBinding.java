package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragFelwareBinding implements ViewBinding {

    @NonNull
    public final RelativeLayout ivBack;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final RelativeLayout llSigninTop;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final SlidingTabLayout tabWelfarePoints;

    @NonNull
    public final ViewPager vpWelfarePoints;

    private FragFelwareBinding(@NonNull FrameLayout frameLayout, @NonNull RelativeLayout relativeLayout, @NonNull ImageView imageView, @NonNull RelativeLayout relativeLayout2, @NonNull SlidingTabLayout slidingTabLayout, @NonNull ViewPager viewPager) {
        this.rootView = frameLayout;
        this.ivBack = relativeLayout;
        this.ivTitleLeftIcon = imageView;
        this.llSigninTop = relativeLayout2;
        this.tabWelfarePoints = slidingTabLayout;
        this.vpWelfarePoints = viewPager;
    }

    @NonNull
    public static FragFelwareBinding bind(@NonNull View view) {
        int i2 = R.id.ivBack;
        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.ivBack);
        if (relativeLayout != null) {
            i2 = R.id.iv_titleLeftIcon;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
            if (imageView != null) {
                i2 = R.id.ll_signin_top;
                RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.ll_signin_top);
                if (relativeLayout2 != null) {
                    i2 = R.id.tab_welfare_points;
                    SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tab_welfare_points);
                    if (slidingTabLayout != null) {
                        i2 = R.id.vp_welfare_points;
                        ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_welfare_points);
                        if (viewPager != null) {
                            return new FragFelwareBinding((FrameLayout) view, relativeLayout, imageView, relativeLayout2, slidingTabLayout, viewPager);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragFelwareBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragFelwareBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_felware, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
