package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.appbar.AppBarLayout;
import com.jbzd.media.movecartoons.p396ui.search.recyclerview.SearchView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragSearchVideostocksBinding implements ViewBinding {

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    public final FrameLayout fragmentContainer;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SearchView rvType1;

    @NonNull
    public final SearchView rvType2;

    @NonNull
    public final SearchView rvType3;

    @NonNull
    public final SearchView rvType4;

    @NonNull
    public final SearchView rvType5;

    private FragSearchVideostocksBinding(@NonNull LinearLayout linearLayout, @NonNull AppBarLayout appBarLayout, @NonNull FrameLayout frameLayout, @NonNull SearchView searchView, @NonNull SearchView searchView2, @NonNull SearchView searchView3, @NonNull SearchView searchView4, @NonNull SearchView searchView5) {
        this.rootView = linearLayout;
        this.appBarLayout = appBarLayout;
        this.fragmentContainer = frameLayout;
        this.rvType1 = searchView;
        this.rvType2 = searchView2;
        this.rvType3 = searchView3;
        this.rvType4 = searchView4;
        this.rvType5 = searchView5;
    }

    @NonNull
    public static FragSearchVideostocksBinding bind(@NonNull View view) {
        int i2 = R.id.app_bar_layout;
        AppBarLayout appBarLayout = (AppBarLayout) view.findViewById(R.id.app_bar_layout);
        if (appBarLayout != null) {
            i2 = R.id.fragment_container;
            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.fragment_container);
            if (frameLayout != null) {
                i2 = R.id.rv_type_1;
                SearchView searchView = (SearchView) view.findViewById(R.id.rv_type_1);
                if (searchView != null) {
                    i2 = R.id.rv_type_2;
                    SearchView searchView2 = (SearchView) view.findViewById(R.id.rv_type_2);
                    if (searchView2 != null) {
                        i2 = R.id.rv_type_3;
                        SearchView searchView3 = (SearchView) view.findViewById(R.id.rv_type_3);
                        if (searchView3 != null) {
                            i2 = R.id.rv_type_4;
                            SearchView searchView4 = (SearchView) view.findViewById(R.id.rv_type_4);
                            if (searchView4 != null) {
                                i2 = R.id.rv_type_5;
                                SearchView searchView5 = (SearchView) view.findViewById(R.id.rv_type_5);
                                if (searchView5 != null) {
                                    return new FragSearchVideostocksBinding((LinearLayout) view, appBarLayout, frameLayout, searchView, searchView2, searchView3, searchView4, searchView5);
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
    public static FragSearchVideostocksBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragSearchVideostocksBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_search_videostocks, viewGroup, false);
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
