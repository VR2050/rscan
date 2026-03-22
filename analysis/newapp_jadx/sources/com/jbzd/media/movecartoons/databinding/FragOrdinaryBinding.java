package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.appbar.AppBarLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragOrdinaryBinding implements ViewBinding {

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    public final SwipeRefreshLayout flavorSwipeLayout;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    public final LinearLayout llOrderBy;

    @NonNull
    public final LinearLayout llTag;

    @NonNull
    public final RelativeLayout rlParent;

    @NonNull
    public final RelativeLayout rlTagLayoutClick;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final RecyclerView rvFlavor;

    @NonNull
    public final TextView tvOrderByName;

    private FragOrdinaryBinding(@NonNull RelativeLayout relativeLayout, @NonNull AppBarLayout appBarLayout, @NonNull SwipeRefreshLayout swipeRefreshLayout, @NonNull FrameLayout frameLayout, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull RelativeLayout relativeLayout2, @NonNull RelativeLayout relativeLayout3, @NonNull RecyclerView recyclerView, @NonNull TextView textView) {
        this.rootView = relativeLayout;
        this.appBarLayout = appBarLayout;
        this.flavorSwipeLayout = swipeRefreshLayout;
        this.fragContent = frameLayout;
        this.llOrderBy = linearLayout;
        this.llTag = linearLayout2;
        this.rlParent = relativeLayout2;
        this.rlTagLayoutClick = relativeLayout3;
        this.rvFlavor = recyclerView;
        this.tvOrderByName = textView;
    }

    @NonNull
    public static FragOrdinaryBinding bind(@NonNull View view) {
        int i2 = R.id.app_bar_layout;
        AppBarLayout appBarLayout = (AppBarLayout) view.findViewById(R.id.app_bar_layout);
        if (appBarLayout != null) {
            i2 = R.id.flavorSwipeLayout;
            SwipeRefreshLayout swipeRefreshLayout = (SwipeRefreshLayout) view.findViewById(R.id.flavorSwipeLayout);
            if (swipeRefreshLayout != null) {
                i2 = R.id.frag_content;
                FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
                if (frameLayout != null) {
                    i2 = R.id.ll_orderBy;
                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_orderBy);
                    if (linearLayout != null) {
                        i2 = R.id.ll_tag;
                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_tag);
                        if (linearLayout2 != null) {
                            i2 = R.id.rl_parent;
                            RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_parent);
                            if (relativeLayout != null) {
                                i2 = R.id.rl_tagLayoutClick;
                                RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.rl_tagLayoutClick);
                                if (relativeLayout2 != null) {
                                    i2 = R.id.rv_flavor;
                                    RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_flavor);
                                    if (recyclerView != null) {
                                        i2 = R.id.tv_orderByName;
                                        TextView textView = (TextView) view.findViewById(R.id.tv_orderByName);
                                        if (textView != null) {
                                            return new FragOrdinaryBinding((RelativeLayout) view, appBarLayout, swipeRefreshLayout, frameLayout, linearLayout, linearLayout2, relativeLayout, relativeLayout2, recyclerView, textView);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragOrdinaryBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragOrdinaryBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_ordinary, viewGroup, false);
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
