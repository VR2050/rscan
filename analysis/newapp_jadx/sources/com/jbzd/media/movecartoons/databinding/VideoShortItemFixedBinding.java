package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.view.GradientTextView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoShortItemFixedBinding implements ViewBinding {

    @NonNull
    public final RelativeLayout itemMore;

    @NonNull
    public final RelativeLayout itemParent;

    @NonNull
    public final TextView itvAd;

    @NonNull
    public final ImageTextView itvIconMoney;

    @NonNull
    public final ImageTextView itvPrice;

    @NonNull
    public final ImageTextView itvType;

    @NonNull
    public final ImageTextView itvZhiding;

    @NonNull
    public final ImageView ivIcoType;

    @NonNull
    public final ShapeableImageView ivVideo;

    @NonNull
    public final LinearLayout llMoneyVip;

    @NonNull
    public final LinearLayout llName;

    @NonNull
    public final LinearLayout rlCoverOption;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView spaceLeft;

    @NonNull
    public final GradientTextView textPriceType;

    @NonNull
    public final ImageTextView tvCount;

    @NonNull
    public final TextView tvDuration;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvVideoClick;

    @NonNull
    public final TextView tvVideoType;

    private VideoShortItemFixedBinding(@NonNull LinearLayout linearLayout, @NonNull RelativeLayout relativeLayout, @NonNull RelativeLayout relativeLayout2, @NonNull TextView textView, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull ImageTextView imageTextView4, @NonNull ImageView imageView, @NonNull ShapeableImageView shapeableImageView, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull TextView textView2, @NonNull GradientTextView gradientTextView, @NonNull ImageTextView imageTextView5, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6) {
        this.rootView = linearLayout;
        this.itemMore = relativeLayout;
        this.itemParent = relativeLayout2;
        this.itvAd = textView;
        this.itvIconMoney = imageTextView;
        this.itvPrice = imageTextView2;
        this.itvType = imageTextView3;
        this.itvZhiding = imageTextView4;
        this.ivIcoType = imageView;
        this.ivVideo = shapeableImageView;
        this.llMoneyVip = linearLayout2;
        this.llName = linearLayout3;
        this.rlCoverOption = linearLayout4;
        this.spaceLeft = textView2;
        this.textPriceType = gradientTextView;
        this.tvCount = imageTextView5;
        this.tvDuration = textView3;
        this.tvName = textView4;
        this.tvVideoClick = textView5;
        this.tvVideoType = textView6;
    }

    @NonNull
    public static VideoShortItemFixedBinding bind(@NonNull View view) {
        int i2 = R.id.item_more;
        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.item_more);
        if (relativeLayout != null) {
            i2 = R.id.item_parent;
            RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.item_parent);
            if (relativeLayout2 != null) {
                i2 = R.id.itv_ad;
                TextView textView = (TextView) view.findViewById(R.id.itv_ad);
                if (textView != null) {
                    i2 = R.id.itv_icon_money;
                    ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_icon_money);
                    if (imageTextView != null) {
                        i2 = R.id.itv_price;
                        ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_price);
                        if (imageTextView2 != null) {
                            i2 = R.id.itv_type;
                            ImageTextView imageTextView3 = (ImageTextView) view.findViewById(R.id.itv_type);
                            if (imageTextView3 != null) {
                                i2 = R.id.itv_zhiding;
                                ImageTextView imageTextView4 = (ImageTextView) view.findViewById(R.id.itv_zhiding);
                                if (imageTextView4 != null) {
                                    i2 = R.id.iv_ico_type;
                                    ImageView imageView = (ImageView) view.findViewById(R.id.iv_ico_type);
                                    if (imageView != null) {
                                        i2 = R.id.iv_video;
                                        ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_video);
                                        if (shapeableImageView != null) {
                                            i2 = R.id.ll_money_vip;
                                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_money_vip);
                                            if (linearLayout != null) {
                                                i2 = R.id.ll_name;
                                                LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_name);
                                                if (linearLayout2 != null) {
                                                    i2 = R.id.rl_coverOption;
                                                    LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.rl_coverOption);
                                                    if (linearLayout3 != null) {
                                                        i2 = R.id.space_left;
                                                        TextView textView2 = (TextView) view.findViewById(R.id.space_left);
                                                        if (textView2 != null) {
                                                            i2 = R.id.text_price_type;
                                                            GradientTextView gradientTextView = (GradientTextView) view.findViewById(R.id.text_price_type);
                                                            if (gradientTextView != null) {
                                                                i2 = R.id.tv_count;
                                                                ImageTextView imageTextView5 = (ImageTextView) view.findViewById(R.id.tv_count);
                                                                if (imageTextView5 != null) {
                                                                    i2 = R.id.tv_duration;
                                                                    TextView textView3 = (TextView) view.findViewById(R.id.tv_duration);
                                                                    if (textView3 != null) {
                                                                        i2 = R.id.tv_name;
                                                                        TextView textView4 = (TextView) view.findViewById(R.id.tv_name);
                                                                        if (textView4 != null) {
                                                                            i2 = R.id.tv_video_click;
                                                                            TextView textView5 = (TextView) view.findViewById(R.id.tv_video_click);
                                                                            if (textView5 != null) {
                                                                                i2 = R.id.tv_video_type;
                                                                                TextView textView6 = (TextView) view.findViewById(R.id.tv_video_type);
                                                                                if (textView6 != null) {
                                                                                    return new VideoShortItemFixedBinding((LinearLayout) view, relativeLayout, relativeLayout2, textView, imageTextView, imageTextView2, imageTextView3, imageTextView4, imageView, shapeableImageView, linearLayout, linearLayout2, linearLayout3, textView2, gradientTextView, imageTextView5, textView3, textView4, textView5, textView6);
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
    public static VideoShortItemFixedBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoShortItemFixedBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_short_item_fixed, viewGroup, false);
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
