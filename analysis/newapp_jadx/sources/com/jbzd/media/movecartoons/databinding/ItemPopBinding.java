package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemPopBinding implements ViewBinding {

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final RecyclerView rvSpinner;

    @NonNull
    public final TextView tvCancelChooseline;

    private ItemPopBinding(@NonNull RelativeLayout relativeLayout, @NonNull RecyclerView recyclerView, @NonNull TextView textView) {
        this.rootView = relativeLayout;
        this.rvSpinner = recyclerView;
        this.tvCancelChooseline = textView;
    }

    @NonNull
    public static ItemPopBinding bind(@NonNull View view) {
        int i2 = R.id.rv_spinner;
        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_spinner);
        if (recyclerView != null) {
            i2 = R.id.tv_cancel_chooseline;
            TextView textView = (TextView) view.findViewById(R.id.tv_cancel_chooseline);
            if (textView != null) {
                return new ItemPopBinding((RelativeLayout) view, recyclerView, textView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemPopBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemPopBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_pop, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RelativeLayout getRoot() {
        return this.rootView;
    }
}
