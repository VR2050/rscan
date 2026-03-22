package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatCheckBox;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemVipPaymentBinding implements ViewBinding {

    @NonNull
    public final ImageView ivIcon;

    @NonNull
    public final AppCompatCheckBox ivSelect;

    @NonNull
    public final LinearLayout llGroup;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvName;

    private ItemVipPaymentBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull AppCompatCheckBox appCompatCheckBox, @NonNull LinearLayout linearLayout2, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.ivIcon = imageView;
        this.ivSelect = appCompatCheckBox;
        this.llGroup = linearLayout2;
        this.tvName = textView;
    }

    @NonNull
    public static ItemVipPaymentBinding bind(@NonNull View view) {
        int i2 = R.id.iv_icon;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_icon);
        if (imageView != null) {
            i2 = R.id.iv_select;
            AppCompatCheckBox appCompatCheckBox = (AppCompatCheckBox) view.findViewById(R.id.iv_select);
            if (appCompatCheckBox != null) {
                LinearLayout linearLayout = (LinearLayout) view;
                i2 = R.id.tv_name;
                TextView textView = (TextView) view.findViewById(R.id.tv_name);
                if (textView != null) {
                    return new ItemVipPaymentBinding(linearLayout, imageView, appCompatCheckBox, linearLayout, textView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemVipPaymentBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemVipPaymentBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_vip_payment, viewGroup, false);
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
