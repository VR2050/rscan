package com.qunidayede.supportlibrary.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.qunidayede.supportlibrary.R$id;
import com.qunidayede.supportlibrary.R$layout;

/* loaded from: classes2.dex */
public final class LayoutEmptyBinding implements ViewBinding {

    @NonNull
    public final ImageView ivImg;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView tvTips;

    private LayoutEmptyBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ImageView imageView, @NonNull TextView textView) {
        this.rootView = constraintLayout;
        this.ivImg = imageView;
        this.tvTips = textView;
    }

    @NonNull
    public static LayoutEmptyBinding bind(@NonNull View view) {
        int i2 = R$id.iv_img;
        ImageView imageView = (ImageView) view.findViewById(i2);
        if (imageView != null) {
            i2 = R$id.tv_tips;
            TextView textView = (TextView) view.findViewById(i2);
            if (textView != null) {
                return new LayoutEmptyBinding((ConstraintLayout) view, imageView, textView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static LayoutEmptyBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LayoutEmptyBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R$layout.layout_empty, viewGroup, false);
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
