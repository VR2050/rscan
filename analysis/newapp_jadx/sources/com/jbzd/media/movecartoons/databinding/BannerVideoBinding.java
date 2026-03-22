package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.video.BannerPlayerView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class BannerVideoBinding implements ViewBinding {

    @NonNull
    public final BannerPlayerView bannerPlayer;

    @NonNull
    private final FrameLayout rootView;

    private BannerVideoBinding(@NonNull FrameLayout frameLayout, @NonNull BannerPlayerView bannerPlayerView) {
        this.rootView = frameLayout;
        this.bannerPlayer = bannerPlayerView;
    }

    @NonNull
    public static BannerVideoBinding bind(@NonNull View view) {
        BannerPlayerView bannerPlayerView = (BannerPlayerView) view.findViewById(R.id.banner_player);
        if (bannerPlayerView != null) {
            return new BannerVideoBinding((FrameLayout) view, bannerPlayerView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.banner_player)));
    }

    @NonNull
    public static BannerVideoBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static BannerVideoBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.banner_video, viewGroup, false);
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
