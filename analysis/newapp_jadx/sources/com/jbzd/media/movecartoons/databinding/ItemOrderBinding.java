package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemOrderBinding implements ViewBinding {

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvDays;

    @NonNull
    public final TextView tvMoney;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvPayment;

    @NonNull
    public final TextView tvSn;

    @NonNull
    public final TextView tvStatus;

    @NonNull
    public final TextView tvTime;

    @NonNull
    public final TextView tvVipBuyTips;

    private ItemOrderBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8) {
        this.rootView = linearLayout;
        this.tvDays = textView;
        this.tvMoney = textView2;
        this.tvName = textView3;
        this.tvPayment = textView4;
        this.tvSn = textView5;
        this.tvStatus = textView6;
        this.tvTime = textView7;
        this.tvVipBuyTips = textView8;
    }

    @NonNull
    public static ItemOrderBinding bind(@NonNull View view) {
        int i2 = R.id.tv_days;
        TextView textView = (TextView) view.findViewById(R.id.tv_days);
        if (textView != null) {
            i2 = R.id.tv_money;
            TextView textView2 = (TextView) view.findViewById(R.id.tv_money);
            if (textView2 != null) {
                i2 = R.id.tv_name;
                TextView textView3 = (TextView) view.findViewById(R.id.tv_name);
                if (textView3 != null) {
                    i2 = R.id.tv_payment;
                    TextView textView4 = (TextView) view.findViewById(R.id.tv_payment);
                    if (textView4 != null) {
                        i2 = R.id.tv_sn;
                        TextView textView5 = (TextView) view.findViewById(R.id.tv_sn);
                        if (textView5 != null) {
                            i2 = R.id.tv_status;
                            TextView textView6 = (TextView) view.findViewById(R.id.tv_status);
                            if (textView6 != null) {
                                i2 = R.id.tv_time;
                                TextView textView7 = (TextView) view.findViewById(R.id.tv_time);
                                if (textView7 != null) {
                                    i2 = R.id.tv_vip_buy_tips;
                                    TextView textView8 = (TextView) view.findViewById(R.id.tv_vip_buy_tips);
                                    if (textView8 != null) {
                                        return new ItemOrderBinding((LinearLayout) view, textView, textView2, textView3, textView4, textView5, textView6, textView7, textView8);
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
    public static ItemOrderBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemOrderBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_order, viewGroup, false);
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
