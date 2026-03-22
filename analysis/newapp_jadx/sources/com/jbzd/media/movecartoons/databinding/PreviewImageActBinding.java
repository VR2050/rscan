package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.HackyViewPager;
import com.jbzd.media.movecartoons.view.SlideCloseLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class PreviewImageActBinding implements ViewBinding {

    @NonNull
    public final RelativeLayout btnTitleBack;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final SlideCloseLayout slideCloseLayout;

    @NonNull
    public final TextView tvIndex;

    @NonNull
    public final HackyViewPager vpImage;

    private PreviewImageActBinding(@NonNull FrameLayout frameLayout, @NonNull RelativeLayout relativeLayout, @NonNull ImageView imageView, @NonNull SlideCloseLayout slideCloseLayout, @NonNull TextView textView, @NonNull HackyViewPager hackyViewPager) {
        this.rootView = frameLayout;
        this.btnTitleBack = relativeLayout;
        this.ivTitleLeftIcon = imageView;
        this.slideCloseLayout = slideCloseLayout;
        this.tvIndex = textView;
        this.vpImage = hackyViewPager;
    }

    @NonNull
    public static PreviewImageActBinding bind(@NonNull View view) {
        int i2 = R.id.btn_titleBack;
        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.btn_titleBack);
        if (relativeLayout != null) {
            i2 = R.id.iv_titleLeftIcon;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
            if (imageView != null) {
                i2 = R.id.slide_close_layout;
                SlideCloseLayout slideCloseLayout = (SlideCloseLayout) view.findViewById(R.id.slide_close_layout);
                if (slideCloseLayout != null) {
                    i2 = R.id.tv_index;
                    TextView textView = (TextView) view.findViewById(R.id.tv_index);
                    if (textView != null) {
                        i2 = R.id.vp_image;
                        HackyViewPager hackyViewPager = (HackyViewPager) view.findViewById(R.id.vp_image);
                        if (hackyViewPager != null) {
                            return new PreviewImageActBinding((FrameLayout) view, relativeLayout, imageView, slideCloseLayout, textView, hackyViewPager);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static PreviewImageActBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static PreviewImageActBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.preview_image_act, viewGroup, false);
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
