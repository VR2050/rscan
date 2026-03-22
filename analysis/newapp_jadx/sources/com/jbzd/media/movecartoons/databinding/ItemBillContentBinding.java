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
public final class ItemBillContentBinding implements ViewBinding {

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvNum;

    @NonNull
    public final TextView tvRemain;

    @NonNull
    public final TextView tvState;

    @NonNull
    public final TextView tvTime;

    @NonNull
    public final TextView tvType;

    private ItemBillContentBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5) {
        this.rootView = linearLayout;
        this.tvNum = textView;
        this.tvRemain = textView2;
        this.tvState = textView3;
        this.tvTime = textView4;
        this.tvType = textView5;
    }

    @NonNull
    public static ItemBillContentBinding bind(@NonNull View view) {
        int i2 = R.id.tvNum;
        TextView textView = (TextView) view.findViewById(R.id.tvNum);
        if (textView != null) {
            i2 = R.id.tvRemain;
            TextView textView2 = (TextView) view.findViewById(R.id.tvRemain);
            if (textView2 != null) {
                i2 = R.id.tvState;
                TextView textView3 = (TextView) view.findViewById(R.id.tvState);
                if (textView3 != null) {
                    i2 = R.id.tvTime;
                    TextView textView4 = (TextView) view.findViewById(R.id.tvTime);
                    if (textView4 != null) {
                        i2 = R.id.tvType;
                        TextView textView5 = (TextView) view.findViewById(R.id.tvType);
                        if (textView5 != null) {
                            return new ItemBillContentBinding((LinearLayout) view, textView, textView2, textView3, textView4, textView5);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemBillContentBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemBillContentBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_bill_content, viewGroup, false);
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
