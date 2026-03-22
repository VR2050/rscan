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
public final class BlockStyleModuleLandscapeHorBinding implements ViewBinding {

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvList;

    @NonNull
    public final View vListDivider;

    private BlockStyleModuleLandscapeHorBinding(@NonNull LinearLayout linearLayout, @NonNull RecyclerView recyclerView, @NonNull View view) {
        this.rootView = linearLayout;
        this.rvList = recyclerView;
        this.vListDivider = view;
    }

    @NonNull
    public static BlockStyleModuleLandscapeHorBinding bind(@NonNull View view) {
        int i2 = R.id.rv_list;
        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_list);
        if (recyclerView != null) {
            i2 = R.id.v_listDivider;
            View findViewById = view.findViewById(R.id.v_listDivider);
            if (findViewById != null) {
                return new BlockStyleModuleLandscapeHorBinding((LinearLayout) view, recyclerView, findViewById);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static BlockStyleModuleLandscapeHorBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static BlockStyleModuleLandscapeHorBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.block_style_module_landscape_hor, viewGroup, false);
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
