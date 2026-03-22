package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientTextView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoItemCoverHotBinding implements ViewBinding {

    @NonNull
    public final TextView itvAd;

    @NonNull
    public final ImageTextView itvClicks;

    @NonNull
    public final ImageTextView itvLove;

    @NonNull
    public final ImageTextView itvPrice;

    @NonNull
    public final ImageTextView itvZhiding;

    @NonNull
    public final ImageView ivIcoType;

    @NonNull
    public final ImageView ivNovelAudio;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final GradientTextView textPriceType;

    @NonNull
    public final TextView textView;

    @NonNull
    public final TextView tvAdNewNovel;

    @NonNull
    public final TextView tvDuration;

    private VideoItemCoverHotBinding(@NonNull RelativeLayout relativeLayout, @NonNull TextView textView, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull ImageTextView imageTextView4, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull GradientTextView gradientTextView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = relativeLayout;
        this.itvAd = textView;
        this.itvClicks = imageTextView;
        this.itvLove = imageTextView2;
        this.itvPrice = imageTextView3;
        this.itvZhiding = imageTextView4;
        this.ivIcoType = imageView;
        this.ivNovelAudio = imageView2;
        this.textPriceType = gradientTextView;
        this.textView = textView2;
        this.tvAdNewNovel = textView3;
        this.tvDuration = textView4;
    }

    @NonNull
    public static VideoItemCoverHotBinding bind(@NonNull View view) {
        int i2 = R.id.itv_ad;
        TextView textView = (TextView) view.findViewById(R.id.itv_ad);
        if (textView != null) {
            i2 = R.id.itv_clicks;
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
                            i2 = R.id.iv_ico_type;
                            ImageView imageView = (ImageView) view.findViewById(R.id.iv_ico_type);
                            if (imageView != null) {
                                i2 = R.id.iv_novel_audio;
                                ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_novel_audio);
                                if (imageView2 != null) {
                                    i2 = R.id.text_price_type;
                                    GradientTextView gradientTextView = (GradientTextView) view.findViewById(R.id.text_price_type);
                                    if (gradientTextView != null) {
                                        i2 = R.id.textView;
                                        TextView textView2 = (TextView) view.findViewById(R.id.textView);
                                        if (textView2 != null) {
                                            i2 = R.id.tv_ad_new_novel;
                                            TextView textView3 = (TextView) view.findViewById(R.id.tv_ad_new_novel);
                                            if (textView3 != null) {
                                                i2 = R.id.tv_duration;
                                                TextView textView4 = (TextView) view.findViewById(R.id.tv_duration);
                                                if (textView4 != null) {
                                                    return new VideoItemCoverHotBinding((RelativeLayout) view, textView, imageTextView, imageTextView2, imageTextView3, imageTextView4, imageView, imageView2, gradientTextView, textView2, textView3, textView4);
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
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static VideoItemCoverHotBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoItemCoverHotBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_item_cover_hot, viewGroup, false);
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
