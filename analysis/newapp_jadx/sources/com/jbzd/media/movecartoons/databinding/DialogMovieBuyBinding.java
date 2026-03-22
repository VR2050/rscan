package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogMovieBuyBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llBuy;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvBuyPrice;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvGoRecharge;

    private DialogMovieBuyBinding(@NonNull FrameLayout frameLayout, @NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = frameLayout;
        this.llBuy = linearLayout;
        this.tvBuyPrice = textView;
        this.tvDesc = textView2;
        this.tvGoRecharge = textView3;
    }

    @NonNull
    public static DialogMovieBuyBinding bind(@NonNull View view) {
        int i2 = R.id.ll_buy;
        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_buy);
        if (linearLayout != null) {
            i2 = R.id.tv_buyPrice;
            TextView textView = (TextView) view.findViewById(R.id.tv_buyPrice);
            if (textView != null) {
                i2 = R.id.tv_desc;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_desc);
                if (textView2 != null) {
                    i2 = R.id.tv_goRecharge;
                    TextView textView3 = (TextView) view.findViewById(R.id.tv_goRecharge);
                    if (textView3 != null) {
                        return new DialogMovieBuyBinding((FrameLayout) view, linearLayout, textView, textView2, textView3);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogMovieBuyBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogMovieBuyBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_movie_buy, viewGroup, false);
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
