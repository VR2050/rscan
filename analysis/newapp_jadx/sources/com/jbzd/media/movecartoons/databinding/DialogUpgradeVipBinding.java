package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;
import io.github.armcha.autolink.AutoLinkTextView;

/* loaded from: classes2.dex */
public final class DialogUpgradeVipBinding implements ViewBinding {

    @NonNull
    public final TextView btn;

    @NonNull
    public final ImageView ivClose;

    @NonNull
    public final LinearLayout linearLayout2;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final AutoLinkTextView tvTips;

    @NonNull
    public final TextView tvTitle;

    private DialogUpgradeVipBinding(@NonNull FrameLayout frameLayout, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout, @NonNull AutoLinkTextView autoLinkTextView, @NonNull TextView textView2) {
        this.rootView = frameLayout;
        this.btn = textView;
        this.ivClose = imageView;
        this.linearLayout2 = linearLayout;
        this.tvTips = autoLinkTextView;
        this.tvTitle = textView2;
    }

    @NonNull
    public static DialogUpgradeVipBinding bind(@NonNull View view) {
        int i2 = R.id.btn;
        TextView textView = (TextView) view.findViewById(R.id.btn);
        if (textView != null) {
            i2 = R.id.iv_close;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_close);
            if (imageView != null) {
                i2 = R.id.linearLayout2;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.linearLayout2);
                if (linearLayout != null) {
                    i2 = R.id.tv_tips;
                    AutoLinkTextView autoLinkTextView = (AutoLinkTextView) view.findViewById(R.id.tv_tips);
                    if (autoLinkTextView != null) {
                        i2 = R.id.tv_title;
                        TextView textView2 = (TextView) view.findViewById(R.id.tv_title);
                        if (textView2 != null) {
                            return new DialogUpgradeVipBinding((FrameLayout) view, textView, imageView, linearLayout, autoLinkTextView, textView2);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogUpgradeVipBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogUpgradeVipBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_upgrade_vip, viewGroup, false);
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
