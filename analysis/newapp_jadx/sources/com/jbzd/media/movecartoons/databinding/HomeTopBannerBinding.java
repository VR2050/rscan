package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.RecyclerViewAtViewPager2;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class HomeTopBannerBinding implements ViewBinding {

    @NonNull
    public final Banner banner;

    @NonNull
    public final RecyclerViewAtViewPager2 bannerNew;

    @NonNull
    public final ScaleRelativeLayout bannerParent;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvAdName;

    private HomeTopBannerBinding(@NonNull LinearLayout linearLayout, @NonNull Banner banner, @NonNull RecyclerViewAtViewPager2 recyclerViewAtViewPager2, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.banner = banner;
        this.bannerNew = recyclerViewAtViewPager2;
        this.bannerParent = scaleRelativeLayout;
        this.tvAdName = textView;
    }

    @NonNull
    public static HomeTopBannerBinding bind(@NonNull View view) {
        int i2 = R.id.banner;
        Banner banner = (Banner) view.findViewById(R.id.banner);
        if (banner != null) {
            i2 = R.id.bannerNew;
            RecyclerViewAtViewPager2 recyclerViewAtViewPager2 = (RecyclerViewAtViewPager2) view.findViewById(R.id.bannerNew);
            if (recyclerViewAtViewPager2 != null) {
                i2 = R.id.banner_parent;
                ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.banner_parent);
                if (scaleRelativeLayout != null) {
                    i2 = R.id.tv_adName;
                    TextView textView = (TextView) view.findViewById(R.id.tv_adName);
                    if (textView != null) {
                        return new HomeTopBannerBinding((LinearLayout) view, banner, recyclerViewAtViewPager2, scaleRelativeLayout, textView);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static HomeTopBannerBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static HomeTopBannerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.home_top_banner, viewGroup, false);
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
