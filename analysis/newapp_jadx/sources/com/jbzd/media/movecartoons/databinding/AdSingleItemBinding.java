package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class AdSingleItemBinding implements ViewBinding {

    @NonNull
    public final ScaleRelativeLayout bannerParent;

    @NonNull
    public final ShapeableImageView ivImgBottom;

    @NonNull
    public final LinearLayout llAdParentBottom;

    @NonNull
    private final LinearLayout rootView;

    private AdSingleItemBinding(@NonNull LinearLayout linearLayout, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull LinearLayout linearLayout2) {
        this.rootView = linearLayout;
        this.bannerParent = scaleRelativeLayout;
        this.ivImgBottom = shapeableImageView;
        this.llAdParentBottom = linearLayout2;
    }

    @NonNull
    public static AdSingleItemBinding bind(@NonNull View view) {
        int i2 = R.id.banner_parent;
        ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.banner_parent);
        if (scaleRelativeLayout != null) {
            i2 = R.id.iv_img_bottom;
            ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_img_bottom);
            if (shapeableImageView != null) {
                LinearLayout linearLayout = (LinearLayout) view;
                return new AdSingleItemBinding(linearLayout, scaleRelativeLayout, shapeableImageView, linearLayout);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static AdSingleItemBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static AdSingleItemBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.ad_single_item, viewGroup, false);
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
