package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogMovieBuyVipBinding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton btn;

    @NonNull
    public final ImageView btnClose;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvTips;

    private DialogMovieBuyVipBinding(@NonNull FrameLayout frameLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull ImageView imageView, @NonNull TextView textView) {
        this.rootView = frameLayout;
        this.btn = gradientRoundCornerButton;
        this.btnClose = imageView;
        this.tvTips = textView;
    }

    @NonNull
    public static DialogMovieBuyVipBinding bind(@NonNull View view) {
        int i2 = R.id.btn;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.btn);
        if (gradientRoundCornerButton != null) {
            i2 = R.id.btnClose;
            ImageView imageView = (ImageView) view.findViewById(R.id.btnClose);
            if (imageView != null) {
                i2 = R.id.tvTips;
                TextView textView = (TextView) view.findViewById(R.id.tvTips);
                if (textView != null) {
                    return new DialogMovieBuyVipBinding((FrameLayout) view, gradientRoundCornerButton, imageView, textView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogMovieBuyVipBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogMovieBuyVipBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_movie_buy_vip, viewGroup, false);
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
