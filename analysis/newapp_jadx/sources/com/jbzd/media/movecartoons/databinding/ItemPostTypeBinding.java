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
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemPostTypeBinding implements ViewBinding {

    @NonNull
    public final ImageView ivPosttypeBottom;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView tvPosttypeName;

    @NonNull
    public final ConstraintLayout viewItemPosttype;

    private ItemPostTypeBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull ConstraintLayout constraintLayout2) {
        this.rootView = constraintLayout;
        this.ivPosttypeBottom = imageView;
        this.tvPosttypeName = textView;
        this.viewItemPosttype = constraintLayout2;
    }

    @NonNull
    public static ItemPostTypeBinding bind(@NonNull View view) {
        int i2 = R.id.iv_posttype_bottom;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_posttype_bottom);
        if (imageView != null) {
            i2 = R.id.tv_posttype_name;
            TextView textView = (TextView) view.findViewById(R.id.tv_posttype_name);
            if (textView != null) {
                ConstraintLayout constraintLayout = (ConstraintLayout) view;
                return new ItemPostTypeBinding(constraintLayout, imageView, textView, constraintLayout);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemPostTypeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemPostTypeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_post_type, viewGroup, false);
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
