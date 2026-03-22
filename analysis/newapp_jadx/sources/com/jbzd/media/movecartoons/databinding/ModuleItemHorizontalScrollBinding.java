package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ModuleItemHorizontalScrollBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llHotlistVideo;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final RecyclerView rvList;

    private ModuleItemHorizontalScrollBinding(@NonNull ConstraintLayout constraintLayout, @NonNull LinearLayout linearLayout, @NonNull RecyclerView recyclerView) {
        this.rootView = constraintLayout;
        this.llHotlistVideo = linearLayout;
        this.rvList = recyclerView;
    }

    @NonNull
    public static ModuleItemHorizontalScrollBinding bind(@NonNull View view) {
        int i2 = R.id.ll_hotlist_video;
        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_hotlist_video);
        if (linearLayout != null) {
            i2 = R.id.rv_list;
            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_list);
            if (recyclerView != null) {
                return new ModuleItemHorizontalScrollBinding((ConstraintLayout) view, linearLayout, recyclerView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ModuleItemHorizontalScrollBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ModuleItemHorizontalScrollBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.module_item_horizontal_scroll, viewGroup, false);
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
