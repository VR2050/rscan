package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemSetPortraitBinding implements ViewBinding {

    @NonNull
    public final ShapeableImageView ivCover;

    @NonNull
    public final ShapeableImageView ivMineAvatar;

    @NonNull
    private final ConstraintLayout rootView;

    private ItemSetPortraitBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull ShapeableImageView shapeableImageView2) {
        this.rootView = constraintLayout;
        this.ivCover = shapeableImageView;
        this.ivMineAvatar = shapeableImageView2;
    }

    @NonNull
    public static ItemSetPortraitBinding bind(@NonNull View view) {
        int i2 = R.id.iv_cover;
        ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_cover);
        if (shapeableImageView != null) {
            i2 = R.id.iv_mine_avatar;
            ShapeableImageView shapeableImageView2 = (ShapeableImageView) view.findViewById(R.id.iv_mine_avatar);
            if (shapeableImageView2 != null) {
                return new ItemSetPortraitBinding((ConstraintLayout) view, shapeableImageView, shapeableImageView2);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemSetPortraitBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemSetPortraitBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_set_portrait, viewGroup, false);
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
