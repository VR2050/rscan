package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemMovieDescImgBinding implements ViewBinding {

    @NonNull
    public final ImageView ivImg;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final ImageTextView tvTime;

    private ItemMovieDescImgBinding(@NonNull RelativeLayout relativeLayout, @NonNull ImageView imageView, @NonNull ImageTextView imageTextView) {
        this.rootView = relativeLayout;
        this.ivImg = imageView;
        this.tvTime = imageTextView;
    }

    @NonNull
    public static ItemMovieDescImgBinding bind(@NonNull View view) {
        int i2 = R.id.iv_img;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_img);
        if (imageView != null) {
            i2 = R.id.tv_time;
            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.tv_time);
            if (imageTextView != null) {
                return new ItemMovieDescImgBinding((RelativeLayout) view, imageView, imageTextView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemMovieDescImgBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemMovieDescImgBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_movie_desc_img, viewGroup, false);
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
