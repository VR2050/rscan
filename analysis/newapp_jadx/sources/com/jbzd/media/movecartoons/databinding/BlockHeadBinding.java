package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.RecyclerViewAtViewPager2;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class BlockHeadBinding implements ViewBinding {

    @NonNull
    public final RecyclerViewAtViewPager2 banner2;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerViewAtViewPager2 rvAds;

    private BlockHeadBinding(@NonNull LinearLayout linearLayout, @NonNull RecyclerViewAtViewPager2 recyclerViewAtViewPager2, @NonNull RecyclerViewAtViewPager2 recyclerViewAtViewPager22) {
        this.rootView = linearLayout;
        this.banner2 = recyclerViewAtViewPager2;
        this.rvAds = recyclerViewAtViewPager22;
    }

    @NonNull
    public static BlockHeadBinding bind(@NonNull View view) {
        int i2 = R.id.banner2;
        RecyclerViewAtViewPager2 recyclerViewAtViewPager2 = (RecyclerViewAtViewPager2) view.findViewById(R.id.banner2);
        if (recyclerViewAtViewPager2 != null) {
            i2 = R.id.rv_ads;
            RecyclerViewAtViewPager2 recyclerViewAtViewPager22 = (RecyclerViewAtViewPager2) view.findViewById(R.id.rv_ads);
            if (recyclerViewAtViewPager22 != null) {
                return new BlockHeadBinding((LinearLayout) view, recyclerViewAtViewPager2, recyclerViewAtViewPager22);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static BlockHeadBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static BlockHeadBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.block_head, viewGroup, false);
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
