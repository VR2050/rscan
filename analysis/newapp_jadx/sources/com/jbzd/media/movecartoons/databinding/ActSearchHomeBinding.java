package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActSearchHomeBinding implements ViewBinding {

    @NonNull
    public final RelativeLayout btnTitleBack;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final SlidingTabLayout tabLayoutSearchandmoives;

    @NonNull
    public final ViewPager vpContent;

    private ActSearchHomeBinding(@NonNull FrameLayout frameLayout, @NonNull RelativeLayout relativeLayout, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout, @NonNull SlidingTabLayout slidingTabLayout, @NonNull ViewPager viewPager) {
        this.rootView = frameLayout;
        this.btnTitleBack = relativeLayout;
        this.ivTitleLeftIcon = imageView;
        this.llTop = linearLayout;
        this.tabLayoutSearchandmoives = slidingTabLayout;
        this.vpContent = viewPager;
    }

    @NonNull
    public static ActSearchHomeBinding bind(@NonNull View view) {
        int i2 = R.id.btn_titleBack;
        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.btn_titleBack);
        if (relativeLayout != null) {
            i2 = R.id.iv_titleLeftIcon;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
            if (imageView != null) {
                i2 = R.id.ll_top;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_top);
                if (linearLayout != null) {
                    i2 = R.id.tab_layout_searchandmoives;
                    SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tab_layout_searchandmoives);
                    if (slidingTabLayout != null) {
                        i2 = R.id.vp_content;
                        ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
                        if (viewPager != null) {
                            return new ActSearchHomeBinding((FrameLayout) view, relativeLayout, imageView, linearLayout, slidingTabLayout, viewPager);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActSearchHomeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActSearchHomeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_search_home, viewGroup, false);
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
