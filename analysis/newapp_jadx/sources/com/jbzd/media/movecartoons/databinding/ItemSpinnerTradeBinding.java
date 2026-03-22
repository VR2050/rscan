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
public final class ItemSpinnerTradeBinding implements ViewBinding {

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final View viewDivider;

    private ItemSpinnerTradeBinding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull View view) {
        this.rootView = linearLayout;
        this.tvTitle = textView;
        this.viewDivider = view;
    }

    @NonNull
    public static ItemSpinnerTradeBinding bind(@NonNull View view) {
        int i2 = R.id.tv_title;
        TextView textView = (TextView) view.findViewById(R.id.tv_title);
        if (textView != null) {
            i2 = R.id.view_divider;
            View findViewById = view.findViewById(R.id.view_divider);
            if (findViewById != null) {
                return new ItemSpinnerTradeBinding((LinearLayout) view, textView, findViewById);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemSpinnerTradeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemSpinnerTradeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_spinner_trade, viewGroup, false);
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
