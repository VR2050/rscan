package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.appbar.AppBarLayout;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class FragShowTabBinding implements ViewBinding {

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    public final Banner banner;

    @NonNull
    public final ScaleRelativeLayout bannerParent;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final RecyclerView rvFilter;

    @NonNull
    public final SwipeRefreshLayout swipeLayout;

    private FragShowTabBinding(@NonNull RelativeLayout relativeLayout, @NonNull AppBarLayout appBarLayout, @NonNull Banner banner, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull FrameLayout frameLayout, @NonNull RecyclerView recyclerView, @NonNull SwipeRefreshLayout swipeRefreshLayout) {
        this.rootView = relativeLayout;
        this.appBarLayout = appBarLayout;
        this.banner = banner;
        this.bannerParent = scaleRelativeLayout;
        this.fragContent = frameLayout;
        this.rvFilter = recyclerView;
        this.swipeLayout = swipeRefreshLayout;
    }

    @NonNull
    public static FragShowTabBinding bind(@NonNull View view) {
        int i2 = R.id.app_bar_layout;
        AppBarLayout appBarLayout = (AppBarLayout) view.findViewById(R.id.app_bar_layout);
        if (appBarLayout != null) {
            i2 = R.id.banner;
            Banner banner = (Banner) view.findViewById(R.id.banner);
            if (banner != null) {
                i2 = R.id.banner_parent;
                ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.banner_parent);
                if (scaleRelativeLayout != null) {
                    i2 = R.id.frag_content;
                    FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
                    if (frameLayout != null) {
                        i2 = R.id.rv_filter;
                        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_filter);
                        if (recyclerView != null) {
                            i2 = R.id.swipeLayout;
                            SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) view.findViewById(R.id.swipeLayout);
                            if (swipeRefreshLayout != null) {
                                return new FragShowTabBinding((RelativeLayout) view, appBarLayout, banner, scaleRelativeLayout, frameLayout, recyclerView, swipeRefreshLayout);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragShowTabBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragShowTabBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_show_tab, viewGroup, false);
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
