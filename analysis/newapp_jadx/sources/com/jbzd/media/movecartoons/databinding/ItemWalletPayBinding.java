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
public final class ItemWalletPayBinding implements ViewBinding {

    @NonNull
    public final TextView ivCenterPlayicon;

    @NonNull
    public final ImageView ivIco;

    @NonNull
    public final ImageView ivPay;

    @NonNull
    private final LinearLayout rootView;

    private ItemWalletPayBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull ImageView imageView, @NonNull ImageView imageView2) {
        this.rootView = linearLayout;
        this.ivCenterPlayicon = textView;
        this.ivIco = imageView;
        this.ivPay = imageView2;
    }

    @NonNull
    public static ItemWalletPayBinding bind(@NonNull View view) {
        int i2 = R.id.iv_center_playicon;
        TextView textView = (TextView) view.findViewById(R.id.iv_center_playicon);
        if (textView != null) {
            i2 = R.id.ivIco;
            ImageView imageView = (ImageView) view.findViewById(R.id.ivIco);
            if (imageView != null) {
                i2 = R.id.ivPay;
                ImageView imageView2 = (ImageView) view.findViewById(R.id.ivPay);
                if (imageView2 != null) {
                    return new ItemWalletPayBinding((LinearLayout) view, textView, imageView, imageView2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemWalletPayBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemWalletPayBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_wallet_pay, viewGroup, false);
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
