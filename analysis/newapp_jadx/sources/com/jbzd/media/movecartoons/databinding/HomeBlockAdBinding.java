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
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class HomeBlockAdBinding implements ViewBinding {

    @NonNull
    public final Banner banner;

    @NonNull
    public final ScaleRelativeLayout bannerParent;

    @NonNull
    public final ShapeableImageView ivImg;

    @NonNull
    public final LinearLayout llAdParentNew;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final View vListDivider;

    private HomeBlockAdBinding(@NonNull LinearLayout linearLayout, @NonNull Banner banner, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull LinearLayout linearLayout2, @NonNull View view) {
        this.rootView = linearLayout;
        this.banner = banner;
        this.bannerParent = scaleRelativeLayout;
        this.ivImg = shapeableImageView;
        this.llAdParentNew = linearLayout2;
        this.vListDivider = view;
    }

    @NonNull
    public static HomeBlockAdBinding bind(@NonNull View view) {
        int i2 = R.id.banner;
        Banner banner = (Banner) view.findViewById(R.id.banner);
        if (banner != null) {
            i2 = R.id.banner_parent;
            ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.banner_parent);
            if (scaleRelativeLayout != null) {
                i2 = R.id.iv_img;
                ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_img);
                if (shapeableImageView != null) {
                    LinearLayout linearLayout = (LinearLayout) view;
                    i2 = R.id.v_listDivider;
                    View findViewById = view.findViewById(R.id.v_listDivider);
                    if (findViewById != null) {
                        return new HomeBlockAdBinding(linearLayout, banner, scaleRelativeLayout, shapeableImageView, linearLayout, findViewById);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static HomeBlockAdBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static HomeBlockAdBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.home_block_ad, viewGroup, false);
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
