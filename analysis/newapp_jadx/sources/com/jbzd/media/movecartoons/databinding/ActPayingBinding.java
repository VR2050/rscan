package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.ProgressButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActPayingBinding implements ViewBinding {

    @NonNull
    public final ImageView ivPaymentIcon;

    @NonNull
    public final RelativeLayout rlDays;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final ProgressButton submit;

    @NonNull
    public final TextView tvDays;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvOrderSn;

    @NonNull
    public final TextView tvPayTips;

    @NonNull
    public final TextView tvPayment;

    @NonNull
    public final TextView tvPrice;

    @NonNull
    public final TextView tvTime;

    private ActPayingBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull RelativeLayout relativeLayout, @NonNull ProgressButton progressButton, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7) {
        this.rootView = linearLayout;
        this.ivPaymentIcon = imageView;
        this.rlDays = relativeLayout;
        this.submit = progressButton;
        this.tvDays = textView;
        this.tvName = textView2;
        this.tvOrderSn = textView3;
        this.tvPayTips = textView4;
        this.tvPayment = textView5;
        this.tvPrice = textView6;
        this.tvTime = textView7;
    }

    @NonNull
    public static ActPayingBinding bind(@NonNull View view) {
        int i2 = R.id.iv_paymentIcon;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_paymentIcon);
        if (imageView != null) {
            i2 = R.id.rl_days;
            RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_days);
            if (relativeLayout != null) {
                i2 = R.id.submit;
                ProgressButton progressButton = (ProgressButton) view.findViewById(R.id.submit);
                if (progressButton != null) {
                    i2 = R.id.tv_days;
                    TextView textView = (TextView) view.findViewById(R.id.tv_days);
                    if (textView != null) {
                        i2 = R.id.tv_name;
                        TextView textView2 = (TextView) view.findViewById(R.id.tv_name);
                        if (textView2 != null) {
                            i2 = R.id.tv_orderSn;
                            TextView textView3 = (TextView) view.findViewById(R.id.tv_orderSn);
                            if (textView3 != null) {
                                i2 = R.id.tv_payTips;
                                TextView textView4 = (TextView) view.findViewById(R.id.tv_payTips);
                                if (textView4 != null) {
                                    i2 = R.id.tv_payment;
                                    TextView textView5 = (TextView) view.findViewById(R.id.tv_payment);
                                    if (textView5 != null) {
                                        i2 = R.id.tv_price;
                                        TextView textView6 = (TextView) view.findViewById(R.id.tv_price);
                                        if (textView6 != null) {
                                            i2 = R.id.tv_time;
                                            TextView textView7 = (TextView) view.findViewById(R.id.tv_time);
                                            if (textView7 != null) {
                                                return new ActPayingBinding((LinearLayout) view, imageView, relativeLayout, progressButton, textView, textView2, textView3, textView4, textView5, textView6, textView7);
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
    public static ActPayingBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActPayingBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_paying, viewGroup, false);
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
