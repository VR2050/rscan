package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.github.mmin18.widget.RealtimeBlurView;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class ViewFullscreenAdMaskBinding implements ViewBinding {

    @NonNull
    public final ConstraintLayout bannerAd;

    @NonNull
    public final CardView bannerClip;

    @NonNull
    public final Banner bannerSplash;

    @NonNull
    public final RealtimeBlurView blurView;

    @NonNull
    public final BLTextView btnMain;

    @NonNull
    public final BLTextView btnVip;

    @NonNull
    public final ConstraintLayout root;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView tvCountdown;

    private ViewFullscreenAdMaskBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ConstraintLayout constraintLayout2, @NonNull CardView cardView, @NonNull Banner banner, @NonNull RealtimeBlurView realtimeBlurView, @NonNull BLTextView bLTextView, @NonNull BLTextView bLTextView2, @NonNull ConstraintLayout constraintLayout3, @NonNull TextView textView) {
        this.rootView = constraintLayout;
        this.bannerAd = constraintLayout2;
        this.bannerClip = cardView;
        this.bannerSplash = banner;
        this.blurView = realtimeBlurView;
        this.btnMain = bLTextView;
        this.btnVip = bLTextView2;
        this.root = constraintLayout3;
        this.tvCountdown = textView;
    }

    @NonNull
    public static ViewFullscreenAdMaskBinding bind(@NonNull View view) {
        int i2 = R.id.banner_ad;
        ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.banner_ad);
        if (constraintLayout != null) {
            i2 = R.id.bannerClip;
            CardView cardView = (CardView) view.findViewById(R.id.bannerClip);
            if (cardView != null) {
                i2 = R.id.banner_splash;
                Banner banner = (Banner) view.findViewById(R.id.banner_splash);
                if (banner != null) {
                    i2 = R.id.blurView;
                    RealtimeBlurView realtimeBlurView = (RealtimeBlurView) view.findViewById(R.id.blurView);
                    if (realtimeBlurView != null) {
                        i2 = R.id.btnMain;
                        BLTextView bLTextView = (BLTextView) view.findViewById(R.id.btnMain);
                        if (bLTextView != null) {
                            i2 = R.id.btnVip;
                            BLTextView bLTextView2 = (BLTextView) view.findViewById(R.id.btnVip);
                            if (bLTextView2 != null) {
                                ConstraintLayout constraintLayout2 = (ConstraintLayout) view;
                                i2 = R.id.tvCountdown;
                                TextView textView = (TextView) view.findViewById(R.id.tvCountdown);
                                if (textView != null) {
                                    return new ViewFullscreenAdMaskBinding(constraintLayout2, constraintLayout, cardView, banner, realtimeBlurView, bLTextView, bLTextView2, constraintLayout2, textView);
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
    public static ViewFullscreenAdMaskBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ViewFullscreenAdMaskBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.view_fullscreen_ad_mask, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public ConstraintLayout getRoot() {
        return this.rootView;
    }
}
