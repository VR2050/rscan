package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.p396ui.search.recyclerview.SearchView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class LayoutFilterBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llPostFilter;

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

    private LayoutFilterBinding(@NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull SearchView searchView, @NonNull SearchView searchView2, @NonNull SearchView searchView3, @NonNull SearchView searchView4) {
        this.rootView = linearLayout;
        this.llPostFilter = linearLayout2;
        this.rvType1 = searchView;
        this.rvType2 = searchView2;
        this.rvType3 = searchView3;
        this.rvType4 = searchView4;
    }

    @NonNull
    public static LayoutFilterBinding bind(@NonNull View view) {
        LinearLayout linearLayout = (LinearLayout) view;
        int i2 = R.id.rv_type_1;
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
                        return new LayoutFilterBinding((LinearLayout) view, linearLayout, searchView, searchView2, searchView3, searchView4);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static LayoutFilterBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LayoutFilterBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.layout_filter, viewGroup, false);
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
