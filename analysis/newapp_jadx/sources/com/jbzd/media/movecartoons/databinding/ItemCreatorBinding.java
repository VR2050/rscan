package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemCreatorBinding implements ViewBinding {

    @NonNull
    public final ImageView ivAdd;

    @NonNull
    public final CircleImageView ivHead;

    @NonNull
    public final RelativeLayout rlHeadBg;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvName;

    private ItemCreatorBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull CircleImageView circleImageView, @NonNull RelativeLayout relativeLayout, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.ivAdd = imageView;
        this.ivHead = circleImageView;
        this.rlHeadBg = relativeLayout;
        this.tvName = textView;
    }

    @NonNull
    public static ItemCreatorBinding bind(@NonNull View view) {
        int i2 = R.id.iv_add;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_add);
        if (imageView != null) {
            i2 = R.id.iv_head;
            CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.iv_head);
            if (circleImageView != null) {
                i2 = R.id.rl_headBg;
                RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_headBg);
                if (relativeLayout != null) {
                    i2 = R.id.tv_name;
                    TextView textView = (TextView) view.findViewById(R.id.tv_name);
                    if (textView != null) {
                        return new ItemCreatorBinding((LinearLayout) view, imageView, circleImageView, relativeLayout, textView);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemCreatorBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemCreatorBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_creator, viewGroup, false);
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
