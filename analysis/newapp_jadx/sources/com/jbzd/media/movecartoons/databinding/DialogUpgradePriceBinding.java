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
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import io.github.armcha.autolink.AutoLinkTextView;

/* loaded from: classes2.dex */
public final class DialogUpgradePriceBinding implements ViewBinding {

    @NonNull
    public final TextView btnLeft;

    @NonNull
    public final TextView btnRight;

    @NonNull
    public final ImageView ivClose;

    @NonNull
    public final LinearLayout linearLayout2;

    @NonNull
    public final LinearLayout llCoinBuy;

    @NonNull
    public final LinearLayout llVipBottom;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final ImageTextView tvBuyPrice;

    @NonNull
    public final ImageTextView tvBuyTips;

    @NonNull
    public final ImageTextView tvPrice;

    @NonNull
    public final AutoLinkTextView tvTips;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final TextView tvVipBuy;

    @NonNull
    public final TextView tvVipBuyCancel;

    private DialogUpgradePriceBinding(@NonNull FrameLayout frameLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull AutoLinkTextView autoLinkTextView, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5) {
        this.rootView = frameLayout;
        this.btnLeft = textView;
        this.btnRight = textView2;
        this.ivClose = imageView;
        this.linearLayout2 = linearLayout;
        this.llCoinBuy = linearLayout2;
        this.llVipBottom = linearLayout3;
        this.tvBuyPrice = imageTextView;
        this.tvBuyTips = imageTextView2;
        this.tvPrice = imageTextView3;
        this.tvTips = autoLinkTextView;
        this.tvTitle = textView3;
        this.tvVipBuy = textView4;
        this.tvVipBuyCancel = textView5;
    }

    @NonNull
    public static DialogUpgradePriceBinding bind(@NonNull View view) {
        int i2 = R.id.btn_left;
        TextView textView = (TextView) view.findViewById(R.id.btn_left);
        if (textView != null) {
            i2 = R.id.btn_right;
            TextView textView2 = (TextView) view.findViewById(R.id.btn_right);
            if (textView2 != null) {
                i2 = R.id.iv_close;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_close);
                if (imageView != null) {
                    i2 = R.id.linearLayout2;
                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.linearLayout2);
                    if (linearLayout != null) {
                        i2 = R.id.ll_coin_buy;
                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_coin_buy);
                        if (linearLayout2 != null) {
                            i2 = R.id.ll_vip_bottom;
                            LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_vip_bottom);
                            if (linearLayout3 != null) {
                                i2 = R.id.tv_buy_price;
                                ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.tv_buy_price);
                                if (imageTextView != null) {
                                    i2 = R.id.tv_buy_tips;
                                    ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.tv_buy_tips);
                                    if (imageTextView2 != null) {
                                        i2 = R.id.tv_price;
                                        ImageTextView imageTextView3 = (ImageTextView) view.findViewById(R.id.tv_price);
                                        if (imageTextView3 != null) {
                                            i2 = R.id.tv_tips;
                                            AutoLinkTextView autoLinkTextView = (AutoLinkTextView) view.findViewById(R.id.tv_tips);
                                            if (autoLinkTextView != null) {
                                                i2 = R.id.tv_title;
                                                TextView textView3 = (TextView) view.findViewById(R.id.tv_title);
                                                if (textView3 != null) {
                                                    i2 = R.id.tv_vip_buy;
                                                    TextView textView4 = (TextView) view.findViewById(R.id.tv_vip_buy);
                                                    if (textView4 != null) {
                                                        i2 = R.id.tv_vip_buy_cancel;
                                                        TextView textView5 = (TextView) view.findViewById(R.id.tv_vip_buy_cancel);
                                                        if (textView5 != null) {
                                                            return new DialogUpgradePriceBinding((FrameLayout) view, textView, textView2, imageView, linearLayout, linearLayout2, linearLayout3, imageTextView, imageTextView2, imageTextView3, autoLinkTextView, textView3, textView4, textView5);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogUpgradePriceBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogUpgradePriceBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_upgrade_price, viewGroup, false);
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
