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
public final class OrderByTabViewBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llNew;

    @NonNull
    public final LinearLayout llOrders;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvNew;

    @NonNull
    public final TextView tvOrders;

    @NonNull
    public final View vLine1;

    @NonNull
    public final View vLine2;

    @NonNull
    public final View vLine3;

    private OrderByTabViewBinding(@NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull TextView textView, @NonNull TextView textView2, @NonNull View view, @NonNull View view2, @NonNull View view3) {
        this.rootView = linearLayout;
        this.llNew = linearLayout2;
        this.llOrders = linearLayout3;
        this.tvNew = textView;
        this.tvOrders = textView2;
        this.vLine1 = view;
        this.vLine2 = view2;
        this.vLine3 = view3;
    }

    @NonNull
    public static OrderByTabViewBinding bind(@NonNull View view) {
        int i2 = R.id.ll_new;
        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_new);
        if (linearLayout != null) {
            i2 = R.id.ll_orders;
            LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_orders);
            if (linearLayout2 != null) {
                i2 = R.id.tv_new;
                TextView textView = (TextView) view.findViewById(R.id.tv_new);
                if (textView != null) {
                    i2 = R.id.tv_orders;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_orders);
                    if (textView2 != null) {
                        i2 = R.id.v_line1;
                        View findViewById = view.findViewById(R.id.v_line1);
                        if (findViewById != null) {
                            i2 = R.id.v_line2;
                            View findViewById2 = view.findViewById(R.id.v_line2);
                            if (findViewById2 != null) {
                                i2 = R.id.v_line3;
                                View findViewById3 = view.findViewById(R.id.v_line3);
                                if (findViewById3 != null) {
                                    return new OrderByTabViewBinding((LinearLayout) view, linearLayout, linearLayout2, textView, textView2, findViewById, findViewById2, findViewById3);
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
    public static OrderByTabViewBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static OrderByTabViewBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.order_by_tab_view, viewGroup, false);
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
