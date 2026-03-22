package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemCardVipBinding implements ViewBinding {

    @NonNull
    public final ImageView imgVipIcon;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView tvTimeVipcardCountdown;

    private ItemCardVipBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ImageView imageView, @NonNull TextView textView) {
        this.rootView = constraintLayout;
        this.imgVipIcon = imageView;
        this.tvTimeVipcardCountdown = textView;
    }

    @NonNull
    public static ItemCardVipBinding bind(@NonNull View view) {
        int i2 = R.id.img_vip_icon;
        ImageView imageView = (ImageView) view.findViewById(R.id.img_vip_icon);
        if (imageView != null) {
            i2 = R.id.tv_time_vipcard_countdown;
            TextView textView = (TextView) view.findViewById(R.id.tv_time_vipcard_countdown);
            if (textView != null) {
                return new ItemCardVipBinding((ConstraintLayout) view, imageView, textView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemCardVipBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemCardVipBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_card_vip, viewGroup, false);
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
