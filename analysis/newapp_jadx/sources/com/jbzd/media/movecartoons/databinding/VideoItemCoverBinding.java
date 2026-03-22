package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientTextView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoItemCoverBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvClicks;

    @NonNull
    public final ImageTextView itvLove;

    @NonNull
    public final ImageTextView itvPrice;

    @NonNull
    public final ImageTextView itvZhiding;

    @NonNull
    public final RelativeLayout llBottomCover;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final GradientTextView textPriceType;

    @NonNull
    public final TextView tvDuration;

    private VideoItemCoverBinding(@NonNull RelativeLayout relativeLayout, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull ImageTextView imageTextView4, @NonNull RelativeLayout relativeLayout2, @NonNull GradientTextView gradientTextView, @NonNull TextView textView) {
        this.rootView = relativeLayout;
        this.itvClicks = imageTextView;
        this.itvLove = imageTextView2;
        this.itvPrice = imageTextView3;
        this.itvZhiding = imageTextView4;
        this.llBottomCover = relativeLayout2;
        this.textPriceType = gradientTextView;
        this.tvDuration = textView;
    }

    @NonNull
    public static VideoItemCoverBinding bind(@NonNull View view) {
        int i2 = R.id.itv_clicks;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_clicks);
        if (imageTextView != null) {
            i2 = R.id.itv_love;
            ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_love);
            if (imageTextView2 != null) {
                i2 = R.id.itv_price;
                ImageTextView imageTextView3 = (ImageTextView) view.findViewById(R.id.itv_price);
                if (imageTextView3 != null) {
                    i2 = R.id.itv_zhiding;
                    ImageTextView imageTextView4 = (ImageTextView) view.findViewById(R.id.itv_zhiding);
                    if (imageTextView4 != null) {
                        i2 = R.id.ll_bottom_cover;
                        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.ll_bottom_cover);
                        if (relativeLayout != null) {
                            i2 = R.id.text_price_type;
                            GradientTextView gradientTextView = (GradientTextView) view.findViewById(R.id.text_price_type);
                            if (gradientTextView != null) {
                                i2 = R.id.tv_duration;
                                TextView textView = (TextView) view.findViewById(R.id.tv_duration);
                                if (textView != null) {
                                    return new VideoItemCoverBinding((RelativeLayout) view, imageTextView, imageTextView2, imageTextView3, imageTextView4, relativeLayout, gradientTextView, textView);
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
    public static VideoItemCoverBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoItemCoverBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_item_cover, viewGroup, false);
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
