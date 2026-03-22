package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class HomeBigBannerBinding implements ViewBinding {

    @NonNull
    public final Banner banner;

    @NonNull
    public final ScaleRelativeLayout bannerParent;

    @NonNull
    private final ScaleRelativeLayout rootView;

    private HomeBigBannerBinding(@NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull Banner banner, @NonNull ScaleRelativeLayout scaleRelativeLayout2) {
        this.rootView = scaleRelativeLayout;
        this.banner = banner;
        this.bannerParent = scaleRelativeLayout2;
    }

    @NonNull
    public static HomeBigBannerBinding bind(@NonNull View view) {
        Banner banner = (Banner) view.findViewById(R.id.banner);
        if (banner == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.banner)));
        }
        ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view;
        return new HomeBigBannerBinding(scaleRelativeLayout, banner, scaleRelativeLayout);
    }

    @NonNull
    public static HomeBigBannerBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static HomeBigBannerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.home_big_banner, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public ScaleRelativeLayout getRoot() {
        return this.rootView;
    }
}
