package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ListSearchFragBinding implements ViewBinding {

    @NonNull
    public final CoordinatorLayout layoutSearchEmpty;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final RecyclerView rvContent;

    @NonNull
    public final SwipeRefreshLayout swipeLayout;

    @NonNull
    public final FrameLayout videoListContainer;

    private ListSearchFragBinding(@NonNull FrameLayout frameLayout, @NonNull CoordinatorLayout coordinatorLayout, @NonNull RecyclerView recyclerView, @NonNull SwipeRefreshLayout swipeRefreshLayout, @NonNull FrameLayout frameLayout2) {
        this.rootView = frameLayout;
        this.layoutSearchEmpty = coordinatorLayout;
        this.rvContent = recyclerView;
        this.swipeLayout = swipeRefreshLayout;
        this.videoListContainer = frameLayout2;
    }

    @NonNull
    public static ListSearchFragBinding bind(@NonNull View view) {
        int i2 = R.id.layout_search_empty;
        CoordinatorLayout coordinatorLayout = (CoordinatorLayout) view.findViewById(R.id.layout_search_empty);
        if (coordinatorLayout != null) {
            i2 = R.id.rv_content;
            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_content);
            if (recyclerView != null) {
                i2 = R.id.swipeLayout;
                SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) view.findViewById(R.id.swipeLayout);
                if (swipeRefreshLayout != null) {
                    FrameLayout frameLayout = (FrameLayout) view;
                    return new ListSearchFragBinding(frameLayout, coordinatorLayout, recyclerView, swipeRefreshLayout, frameLayout);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ListSearchFragBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ListSearchFragBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.list_search_frag, viewGroup, false);
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
