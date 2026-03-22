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
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class LayoutVideoTypeBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvPrice;

    @NonNull
    public final ImageView ivAdFlag;

    @NonNull
    public final RelativeLayout rlPrice;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvFreeFlag;

    private LayoutVideoTypeBinding(@NonNull LinearLayout linearLayout, @NonNull ImageTextView imageTextView, @NonNull ImageView imageView, @NonNull RelativeLayout relativeLayout, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.itvPrice = imageTextView;
        this.ivAdFlag = imageView;
        this.rlPrice = relativeLayout;
        this.tvFreeFlag = textView;
    }

    @NonNull
    public static LayoutVideoTypeBinding bind(@NonNull View view) {
        int i2 = R.id.itv_price;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_price);
        if (imageTextView != null) {
            i2 = R.id.iv_adFlag;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_adFlag);
            if (imageView != null) {
                i2 = R.id.rl_price;
                RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_price);
                if (relativeLayout != null) {
                    i2 = R.id.tv_freeFlag;
                    TextView textView = (TextView) view.findViewById(R.id.tv_freeFlag);
                    if (textView != null) {
                        return new LayoutVideoTypeBinding((LinearLayout) view, imageTextView, imageView, relativeLayout, textView);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static LayoutVideoTypeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LayoutVideoTypeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.layout_video_type, viewGroup, false);
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
