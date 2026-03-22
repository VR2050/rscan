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
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemBuyFansBinding implements ViewBinding {

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    public final ImageView ivIcon;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvIntimacy;

    @NonNull
    public final TextView tvName;

    private ItemBuyFansBinding(@NonNull LinearLayout linearLayout, @NonNull CircleImageView circleImageView, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.civHead = circleImageView;
        this.ivIcon = imageView;
        this.tvIntimacy = textView;
        this.tvName = textView2;
    }

    @NonNull
    public static ItemBuyFansBinding bind(@NonNull View view) {
        int i2 = R.id.civ_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
        if (circleImageView != null) {
            i2 = R.id.iv_icon;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_icon);
            if (imageView != null) {
                i2 = R.id.tv_intimacy;
                TextView textView = (TextView) view.findViewById(R.id.tv_intimacy);
                if (textView != null) {
                    i2 = R.id.tv_name;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_name);
                    if (textView2 != null) {
                        return new ItemBuyFansBinding((LinearLayout) view, circleImageView, imageView, textView, textView2);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemBuyFansBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemBuyFansBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_buy_fans, viewGroup, false);
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
