package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogPayBottomBinding implements ViewBinding {

    @NonNull
    public final ImageView ivDismiss;

    @NonNull
    public final View outsideView;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvPayments;

    @NonNull
    public final TextView tvNamePrice;

    @NonNull
    public final TextView tvPay;

    @NonNull
    public final TextView tvService;

    @NonNull
    public final TextView txtNumClick;

    private DialogPayBottomBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull View view, @NonNull RecyclerView recyclerView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = linearLayout;
        this.ivDismiss = imageView;
        this.outsideView = view;
        this.rvPayments = recyclerView;
        this.tvNamePrice = textView;
        this.tvPay = textView2;
        this.tvService = textView3;
        this.txtNumClick = textView4;
    }

    @NonNull
    public static DialogPayBottomBinding bind(@NonNull View view) {
        int i2 = R.id.iv_dismiss;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_dismiss);
        if (imageView != null) {
            i2 = R.id.outside_view;
            View findViewById = view.findViewById(R.id.outside_view);
            if (findViewById != null) {
                i2 = R.id.rv_payments;
                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_payments);
                if (recyclerView != null) {
                    i2 = R.id.tv_name_price;
                    TextView textView = (TextView) view.findViewById(R.id.tv_name_price);
                    if (textView != null) {
                        i2 = R.id.tv_pay;
                        TextView textView2 = (TextView) view.findViewById(R.id.tv_pay);
                        if (textView2 != null) {
                            i2 = R.id.tv_service;
                            TextView textView3 = (TextView) view.findViewById(R.id.tv_service);
                            if (textView3 != null) {
                                i2 = R.id.txt_num_click;
                                TextView textView4 = (TextView) view.findViewById(R.id.txt_num_click);
                                if (textView4 != null) {
                                    return new DialogPayBottomBinding((LinearLayout) view, imageView, findViewById, recyclerView, textView, textView2, textView3, textView4);
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
    public static DialogPayBottomBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogPayBottomBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_pay_bottom, viewGroup, false);
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
