package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogPostBuyVipBinding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton close;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvTips;

    @NonNull
    public final GradientRoundCornerButton vip;

    private DialogPostBuyVipBinding(@NonNull FrameLayout frameLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull TextView textView, @NonNull GradientRoundCornerButton gradientRoundCornerButton2) {
        this.rootView = frameLayout;
        this.close = gradientRoundCornerButton;
        this.tvTips = textView;
        this.vip = gradientRoundCornerButton2;
    }

    @NonNull
    public static DialogPostBuyVipBinding bind(@NonNull View view) {
        int i2 = R.id.close;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.close);
        if (gradientRoundCornerButton != null) {
            i2 = R.id.tvTips;
            TextView textView = (TextView) view.findViewById(R.id.tvTips);
            if (textView != null) {
                i2 = R.id.vip;
                GradientRoundCornerButton gradientRoundCornerButton2 = (GradientRoundCornerButton) view.findViewById(R.id.vip);
                if (gradientRoundCornerButton2 != null) {
                    return new DialogPostBuyVipBinding((FrameLayout) view, gradientRoundCornerButton, textView, gradientRoundCornerButton2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogPostBuyVipBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogPostBuyVipBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_post_buy_vip, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
