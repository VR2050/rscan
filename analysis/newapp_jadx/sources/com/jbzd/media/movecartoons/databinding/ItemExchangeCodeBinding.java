package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemExchangeCodeBinding implements ViewBinding {

    @NonNull
    public final ConstraintLayout llScoreChange;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView tvSignNow;

    @NonNull
    public final TextView tvTips;

    @NonNull
    public final TextView tvTitle;

    private ItemExchangeCodeBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ConstraintLayout constraintLayout2, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = constraintLayout;
        this.llScoreChange = constraintLayout2;
        this.tvSignNow = textView;
        this.tvTips = textView2;
        this.tvTitle = textView3;
    }

    @NonNull
    public static ItemExchangeCodeBinding bind(@NonNull View view) {
        int i2 = R.id.ll_score_change;
        ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.ll_score_change);
        if (constraintLayout != null) {
            i2 = R.id.tv_sign_now;
            TextView textView = (TextView) view.findViewById(R.id.tv_sign_now);
            if (textView != null) {
                i2 = R.id.tvTips;
                TextView textView2 = (TextView) view.findViewById(R.id.tvTips);
                if (textView2 != null) {
                    i2 = R.id.tvTitle;
                    TextView textView3 = (TextView) view.findViewById(R.id.tvTitle);
                    if (textView3 != null) {
                        return new ItemExchangeCodeBinding((ConstraintLayout) view, constraintLayout, textView, textView2, textView3);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemExchangeCodeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemExchangeCodeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_exchange_code, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public ConstraintLayout getRoot() {
        return this.rootView;
    }
}
