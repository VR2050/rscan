package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragHistoryVideoBinding implements ViewBinding {

    @NonNull
    public final FrameLayout fragVideo;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvOrders;

    private FragHistoryVideoBinding(@NonNull LinearLayout linearLayout, @NonNull FrameLayout frameLayout, @NonNull RecyclerView recyclerView) {
        this.rootView = linearLayout;
        this.fragVideo = frameLayout;
        this.rvOrders = recyclerView;
    }

    @NonNull
    public static FragHistoryVideoBinding bind(@NonNull View view) {
        int i2 = R.id.frag_video;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_video);
        if (frameLayout != null) {
            i2 = R.id.rv_orders;
            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_orders);
            if (recyclerView != null) {
                return new FragHistoryVideoBinding((LinearLayout) view, frameLayout, recyclerView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragHistoryVideoBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragHistoryVideoBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_history_video, viewGroup, false);
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
