package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.widget.NestedScrollView;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActivityRechargeBinding implements ViewBinding {

    @NonNull
    public final RecyclerView rechargeCoinList;

    @NonNull
    private final NestedScrollView rootView;

    @NonNull
    public final TextView tvAmount;

    @NonNull
    public final TextView tvService;

    @NonNull
    public final TextView txtConsumerDetails;

    private ActivityRechargeBinding(@NonNull NestedScrollView nestedScrollView, @NonNull RecyclerView recyclerView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = nestedScrollView;
        this.rechargeCoinList = recyclerView;
        this.tvAmount = textView;
        this.tvService = textView2;
        this.txtConsumerDetails = textView3;
    }

    @NonNull
    public static ActivityRechargeBinding bind(@NonNull View view) {
        int i2 = R.id.recharge_coin_list;
        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.recharge_coin_list);
        if (recyclerView != null) {
            i2 = R.id.tv_amount;
            TextView textView = (TextView) view.findViewById(R.id.tv_amount);
            if (textView != null) {
                i2 = R.id.tv_service;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_service);
                if (textView2 != null) {
                    i2 = R.id.txt_consumer_details;
                    TextView textView3 = (TextView) view.findViewById(R.id.txt_consumer_details);
                    if (textView3 != null) {
                        return new ActivityRechargeBinding((NestedScrollView) view, recyclerView, textView, textView2, textView3);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActivityRechargeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActivityRechargeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.activity_recharge, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public NestedScrollView getRoot() {
        return this.rootView;
    }
}
