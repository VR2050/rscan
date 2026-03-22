package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemPostdetailDiscussBinding implements ViewBinding {

    @NonNull
    public final CircleImageView ivUserfollowAvatar;

    @NonNull
    private final ConstraintLayout rootView;

    private ItemPostdetailDiscussBinding(@NonNull ConstraintLayout constraintLayout, @NonNull CircleImageView circleImageView) {
        this.rootView = constraintLayout;
        this.ivUserfollowAvatar = circleImageView;
    }

    @NonNull
    public static ItemPostdetailDiscussBinding bind(@NonNull View view) {
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.iv_userfollow_avatar);
        if (circleImageView != null) {
            return new ItemPostdetailDiscussBinding((ConstraintLayout) view, circleImageView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.iv_userfollow_avatar)));
    }

    @NonNull
    public static ItemPostdetailDiscussBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemPostdetailDiscussBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_postdetail_discuss, viewGroup, false);
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
