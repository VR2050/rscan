package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class BlockStyleModuleDoubleBinding implements ViewBinding {

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvList;

    @NonNull
    public final RecyclerView rvList1;

    private BlockStyleModuleDoubleBinding(@NonNull LinearLayout linearLayout, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2) {
        this.rootView = linearLayout;
        this.rvList = recyclerView;
        this.rvList1 = recyclerView2;
    }

    @NonNull
    public static BlockStyleModuleDoubleBinding bind(@NonNull View view) {
        int i2 = R.id.rv_list;
        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_list);
        if (recyclerView != null) {
            i2 = R.id.rv_list1;
            RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_list1);
            if (recyclerView2 != null) {
                return new BlockStyleModuleDoubleBinding((LinearLayout) view, recyclerView, recyclerView2);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static BlockStyleModuleDoubleBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static BlockStyleModuleDoubleBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.block_style_module_double, viewGroup, false);
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
