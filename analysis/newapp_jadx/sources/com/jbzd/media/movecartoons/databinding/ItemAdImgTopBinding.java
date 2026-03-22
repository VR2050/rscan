package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemAdImgTopBinding implements ViewBinding {

    @NonNull
    public final ImageView ivImgAd;

    @NonNull
    private final FrameLayout rootView;

    private ItemAdImgTopBinding(@NonNull FrameLayout frameLayout, @NonNull ImageView imageView) {
        this.rootView = frameLayout;
        this.ivImgAd = imageView;
    }

    @NonNull
    public static ItemAdImgTopBinding bind(@NonNull View view) {
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_img_ad);
        if (imageView != null) {
            return new ItemAdImgTopBinding((FrameLayout) view, imageView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.iv_img_ad)));
    }

    @NonNull
    public static ItemAdImgTopBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemAdImgTopBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_ad_img_top, viewGroup, false);
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
