package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.ProgressButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogPayVipBinding implements ViewBinding {

    @NonNull
    public final ProgressButton btnPay;

    @NonNull
    public final TextView ivCenterPlayicon;

    @NonNull
    public final LinearLayout llCard;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvPay;

    @NonNull
    public final TextView tvPrice;

    private DialogPayVipBinding(@NonNull LinearLayout linearLayout, @NonNull ProgressButton progressButton, @NonNull TextView textView, @NonNull LinearLayout linearLayout2, @NonNull RecyclerView recyclerView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.btnPay = progressButton;
        this.ivCenterPlayicon = textView;
        this.llCard = linearLayout2;
        this.rvPay = recyclerView;
        this.tvPrice = textView2;
    }

    @NonNull
    public static DialogPayVipBinding bind(@NonNull View view) {
        int i2 = R.id.btnPay;
        ProgressButton progressButton = (ProgressButton) view.findViewById(R.id.btnPay);
        if (progressButton != null) {
            i2 = R.id.iv_center_playicon;
            TextView textView = (TextView) view.findViewById(R.id.iv_center_playicon);
            if (textView != null) {
                i2 = R.id.ll_card;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_card);
                if (linearLayout != null) {
                    i2 = R.id.rvPay;
                    RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rvPay);
                    if (recyclerView != null) {
                        i2 = R.id.tvPrice;
                        TextView textView2 = (TextView) view.findViewById(R.id.tvPrice);
                        if (textView2 != null) {
                            return new DialogPayVipBinding((LinearLayout) view, progressButton, textView, linearLayout, recyclerView, textView2);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogPayVipBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogPayVipBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_pay_vip, viewGroup, false);
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
