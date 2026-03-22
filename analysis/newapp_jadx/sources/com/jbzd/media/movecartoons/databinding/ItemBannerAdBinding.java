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
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemBannerAdBinding implements ViewBinding {

    @NonNull
    public final ImageView ivAd;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final BLTextView tvAd;

    @NonNull
    public final TextView tvAdTitle;

    private ItemBannerAdBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull BLTextView bLTextView, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.ivAd = imageView;
        this.tvAd = bLTextView;
        this.tvAdTitle = textView;
    }

    @NonNull
    public static ItemBannerAdBinding bind(@NonNull View view) {
        int i2 = R.id.iv_ad;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_ad);
        if (imageView != null) {
            i2 = R.id.tvAd;
            BLTextView bLTextView = (BLTextView) view.findViewById(R.id.tvAd);
            if (bLTextView != null) {
                i2 = R.id.tv_ad_title;
                TextView textView = (TextView) view.findViewById(R.id.tv_ad_title);
                if (textView != null) {
                    return new ItemBannerAdBinding((LinearLayout) view, imageView, bLTextView, textView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemBannerAdBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemBannerAdBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_banner_ad, viewGroup, false);
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
