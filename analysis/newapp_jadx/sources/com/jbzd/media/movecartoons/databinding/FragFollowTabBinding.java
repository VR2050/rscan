package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragFollowTabBinding implements ViewBinding {

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final RecyclerView rvContent;

    @NonNull
    public final SwipeRefreshLayout swipeLayout;

    @NonNull
    public final TextView tvRecommended;

    @NonNull
    public final FrameLayout videoListContainer;

    private FragFollowTabBinding(@NonNull FrameLayout frameLayout, @NonNull RecyclerView recyclerView, @NonNull SwipeRefreshLayout swipeRefreshLayout, @NonNull TextView textView, @NonNull FrameLayout frameLayout2) {
        this.rootView = frameLayout;
        this.rvContent = recyclerView;
        this.swipeLayout = swipeRefreshLayout;
        this.tvRecommended = textView;
        this.videoListContainer = frameLayout2;
    }

    @NonNull
    public static FragFollowTabBinding bind(@NonNull View view) {
        int i2 = R.id.rv_content;
        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_content);
        if (recyclerView != null) {
            i2 = R.id.swipeLayout;
            SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) view.findViewById(R.id.swipeLayout);
            if (swipeRefreshLayout != null) {
                i2 = R.id.tv_recommended;
                TextView textView = (TextView) view.findViewById(R.id.tv_recommended);
                if (textView != null) {
                    FrameLayout frameLayout = (FrameLayout) view;
                    return new FragFollowTabBinding(frameLayout, recyclerView, swipeRefreshLayout, textView, frameLayout);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragFollowTabBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragFollowTabBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_follow_tab, viewGroup, false);
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
