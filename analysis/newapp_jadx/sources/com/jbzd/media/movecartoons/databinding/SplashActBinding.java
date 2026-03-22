package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class SplashActBinding implements ViewBinding {

    @NonNull
    public final LinearLayout bannerParentSplash;

    @NonNull
    public final Banner bannerSplash;

    @NonNull
    public final ImageView ivADImg;

    @NonNull
    public final ImageView ivStartImg;

    @NonNull
    public final LinearLayout llLineChecking;

    @NonNull
    public final FrameLayout offLineLayout;

    @NonNull
    private final RelativeLayout rootView;

    /* renamed from: rv */
    @NonNull
    public final RecyclerView f10061rv;

    @NonNull
    public final TextView tvAdTime;

    @NonNull
    public final BLTextView tvEmail;

    @NonNull
    public final TextView tvLineState;

    private SplashActBinding(@NonNull RelativeLayout relativeLayout, @NonNull LinearLayout linearLayout, @NonNull Banner banner, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull LinearLayout linearLayout2, @NonNull FrameLayout frameLayout, @NonNull RecyclerView recyclerView, @NonNull TextView textView, @NonNull BLTextView bLTextView, @NonNull TextView textView2) {
        this.rootView = relativeLayout;
        this.bannerParentSplash = linearLayout;
        this.bannerSplash = banner;
        this.ivADImg = imageView;
        this.ivStartImg = imageView2;
        this.llLineChecking = linearLayout2;
        this.offLineLayout = frameLayout;
        this.f10061rv = recyclerView;
        this.tvAdTime = textView;
        this.tvEmail = bLTextView;
        this.tvLineState = textView2;
    }

    @NonNull
    public static SplashActBinding bind(@NonNull View view) {
        int i2 = R.id.banner_parent_splash;
        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.banner_parent_splash);
        if (linearLayout != null) {
            i2 = R.id.banner_splash;
            Banner banner = (Banner) view.findViewById(R.id.banner_splash);
            if (banner != null) {
                i2 = R.id.iv_ADImg;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_ADImg);
                if (imageView != null) {
                    i2 = R.id.iv_startImg;
                    ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_startImg);
                    if (imageView2 != null) {
                        i2 = R.id.ll_line_checking;
                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_line_checking);
                        if (linearLayout2 != null) {
                            i2 = R.id.off_line_layout;
                            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.off_line_layout);
                            if (frameLayout != null) {
                                i2 = R.id.f13003rv;
                                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.f13003rv);
                                if (recyclerView != null) {
                                    i2 = R.id.tv_adTime;
                                    TextView textView = (TextView) view.findViewById(R.id.tv_adTime);
                                    if (textView != null) {
                                        i2 = R.id.tv_email;
                                        BLTextView bLTextView = (BLTextView) view.findViewById(R.id.tv_email);
                                        if (bLTextView != null) {
                                            i2 = R.id.tv_line_state;
                                            TextView textView2 = (TextView) view.findViewById(R.id.tv_line_state);
                                            if (textView2 != null) {
                                                return new SplashActBinding((RelativeLayout) view, linearLayout, banner, imageView, imageView2, linearLayout2, frameLayout, recyclerView, textView, bLTextView, textView2);
                                            }
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
    public static SplashActBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static SplashActBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.splash_act, viewGroup, false);
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
