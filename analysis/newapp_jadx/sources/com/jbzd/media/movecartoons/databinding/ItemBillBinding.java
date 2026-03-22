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
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemBillBinding implements ViewBinding {

    @NonNull
    public final RecyclerView fragContent;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvDate;

    private ItemBillBinding(@NonNull LinearLayout linearLayout, @NonNull RecyclerView recyclerView, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.fragContent = recyclerView;
        this.tvDate = textView;
    }

    @NonNull
    public static ItemBillBinding bind(@NonNull View view) {
        int i2 = R.id.frag_content;
        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.frag_content);
        if (recyclerView != null) {
            i2 = R.id.tvDate;
            TextView textView = (TextView) view.findViewById(R.id.tvDate);
            if (textView != null) {
                return new ItemBillBinding((LinearLayout) view, recyclerView, textView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemBillBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemBillBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_bill, viewGroup, false);
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
