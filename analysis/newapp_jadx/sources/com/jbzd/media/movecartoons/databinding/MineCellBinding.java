package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class MineCellBinding implements ViewBinding {

    @NonNull
    public final ImageView ivLeft;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvRight;

    @NonNull
    public final TextView tvTitle;

    private MineCellBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.ivLeft = imageView;
        this.tvRight = textView;
        this.tvTitle = textView2;
    }

    @NonNull
    public static MineCellBinding bind(@NonNull View view) {
        int i2 = R.id.iv_left;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_left);
        if (imageView != null) {
            i2 = R.id.tv_right;
            TextView textView = (TextView) view.findViewById(R.id.tv_right);
            if (textView != null) {
                i2 = R.id.tv_title;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_title);
                if (textView2 != null) {
                    return new MineCellBinding((LinearLayout) view, imageView, textView, textView2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static MineCellBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static MineCellBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.mine_cell, viewGroup, false);
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
