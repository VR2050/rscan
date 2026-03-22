package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class LayoutPostFileBinding implements ViewBinding {

    @NonNull
    public final ShapeableImageView imgCommunitySingle;

    @NonNull
    public final ImageView imgIconMoney;

    @NonNull
    public final ImageView ivPause;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView txtCount;

    @NonNull
    public final TextView txtPostVip;

    private LayoutPostFileBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = constraintLayout;
        this.imgCommunitySingle = shapeableImageView;
        this.imgIconMoney = imageView;
        this.ivPause = imageView2;
        this.txtCount = textView;
        this.txtPostVip = textView2;
    }

    @NonNull
    public static LayoutPostFileBinding bind(@NonNull View view) {
        int i2 = R.id.img_community_single;
        ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.img_community_single);
        if (shapeableImageView != null) {
            i2 = R.id.img_icon_money;
            ImageView imageView = (ImageView) view.findViewById(R.id.img_icon_money);
            if (imageView != null) {
                i2 = R.id.iv_pause;
                ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_pause);
                if (imageView2 != null) {
                    i2 = R.id.txt_count;
                    TextView textView = (TextView) view.findViewById(R.id.txt_count);
                    if (textView != null) {
                        i2 = R.id.txt_post_vip;
                        TextView textView2 = (TextView) view.findViewById(R.id.txt_post_vip);
                        if (textView2 != null) {
                            return new LayoutPostFileBinding((ConstraintLayout) view, shapeableImageView, imageView, imageView2, textView, textView2);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static LayoutPostFileBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LayoutPostFileBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.layout_post_file, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public ConstraintLayout getRoot() {
        return this.rootView;
    }
}
