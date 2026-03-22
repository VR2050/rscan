package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActFollowBinding implements ViewBinding {

    @NonNull
    public final FrameLayout btnTitleBack;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SlidingTabLayout tabLayout;

    @NonNull
    public final ViewPager vpContent;

    private ActFollowBinding(@NonNull LinearLayout linearLayout, @NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull SlidingTabLayout slidingTabLayout, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.btnTitleBack = frameLayout;
        this.ivTitleLeftIcon = imageView;
        this.tabLayout = slidingTabLayout;
        this.vpContent = viewPager;
    }

    @NonNull
    public static ActFollowBinding bind(@NonNull View view) {
        int i2 = R.id.btn_titleBack;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.btn_titleBack);
        if (frameLayout != null) {
            i2 = R.id.iv_titleLeftIcon;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
            if (imageView != null) {
                i2 = R.id.tabLayout;
                SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tabLayout);
                if (slidingTabLayout != null) {
                    i2 = R.id.vp_content;
                    ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
                    if (viewPager != null) {
                        return new ActFollowBinding((LinearLayout) view, frameLayout, imageView, slidingTabLayout, viewPager);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActFollowBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActFollowBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_follow, viewGroup, false);
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
