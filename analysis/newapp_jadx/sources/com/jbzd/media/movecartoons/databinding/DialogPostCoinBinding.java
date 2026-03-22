package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogPostCoinBinding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton btn;

    @NonNull
    public final ImageView btnClose;

    @NonNull
    public final TextView btnWallet;

    @NonNull
    public final AppCompatEditText etCoin;

    @NonNull
    public final AppCompatEditText etDoc;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvBalance;

    private DialogPostCoinBinding(@NonNull FrameLayout frameLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull AppCompatEditText appCompatEditText, @NonNull AppCompatEditText appCompatEditText2, @NonNull TextView textView2) {
        this.rootView = frameLayout;
        this.btn = gradientRoundCornerButton;
        this.btnClose = imageView;
        this.btnWallet = textView;
        this.etCoin = appCompatEditText;
        this.etDoc = appCompatEditText2;
        this.tvBalance = textView2;
    }

    @NonNull
    public static DialogPostCoinBinding bind(@NonNull View view) {
        int i2 = R.id.btn;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.btn);
        if (gradientRoundCornerButton != null) {
            i2 = R.id.btnClose;
            ImageView imageView = (ImageView) view.findViewById(R.id.btnClose);
            if (imageView != null) {
                i2 = R.id.btnWallet;
                TextView textView = (TextView) view.findViewById(R.id.btnWallet);
                if (textView != null) {
                    i2 = R.id.etCoin;
                    AppCompatEditText appCompatEditText = (AppCompatEditText) view.findViewById(R.id.etCoin);
                    if (appCompatEditText != null) {
                        i2 = R.id.etDoc;
                        AppCompatEditText appCompatEditText2 = (AppCompatEditText) view.findViewById(R.id.etDoc);
                        if (appCompatEditText2 != null) {
                            i2 = R.id.tvBalance;
                            TextView textView2 = (TextView) view.findViewById(R.id.tvBalance);
                            if (textView2 != null) {
                                return new DialogPostCoinBinding((FrameLayout) view, gradientRoundCornerButton, imageView, textView, appCompatEditText, appCompatEditText2, textView2);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogPostCoinBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogPostCoinBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_post_coin, viewGroup, false);
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
