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
public final class ItemNovelLayoutVerticalBinding implements ViewBinding {

    @NonNull
    public final ShapeableImageView imgCover;

    @NonNull
    public final RelativeLayout itemMore;

    @NonNull
    public final RelativeLayout itemParent;

    @NonNull
    public final TextView itvAd;

    @NonNull
    public final ImageTextView itvClicks;

    @NonNull
    public final ImageTextView itvLove;

    @NonNull
    public final ImageTextView itvPrice;

    @NonNull
    public final ImageTextView itvType;

    @NonNull
    public final ImageTextView itvZhiding;

    @NonNull
    public final ImageView ivIcoType;

    @NonNull
    public final ImageView ivNovelAudio;

    @NonNull
    public final RelativeLayout llBottomCover;

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
    public final TextView tvDuration;

    @NonNull
    public final TextView tvNovelCategorySubtitle;

    @NonNull
    public final TextView tvNovelName;

    @NonNull
    public final TextView tvSlideMore;

    private ItemNovelLayoutVerticalBinding(@NonNull LinearLayout linearLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull RelativeLayout relativeLayout, @NonNull RelativeLayout relativeLayout2, @NonNull TextView textView, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull ImageTextView imageTextView4, @NonNull ImageTextView imageTextView5, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull RelativeLayout relativeLayout3, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull TextView textView2, @NonNull GradientTextView gradientTextView, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6) {
        this.rootView = linearLayout;
        this.imgCover = shapeableImageView;
        this.itemMore = relativeLayout;
        this.itemParent = relativeLayout2;
        this.itvAd = textView;
        this.itvClicks = imageTextView;
        this.itvLove = imageTextView2;
        this.itvPrice = imageTextView3;
        this.itvType = imageTextView4;
        this.itvZhiding = imageTextView5;
        this.ivIcoType = imageView;
        this.ivNovelAudio = imageView2;
        this.llBottomCover = relativeLayout3;
        this.llName = linearLayout2;
        this.rlCoverOption = linearLayout3;
        this.spaceLeft = textView2;
        this.textPriceType = gradientTextView;
        this.tvDuration = textView3;
        this.tvNovelCategorySubtitle = textView4;
        this.tvNovelName = textView5;
        this.tvSlideMore = textView6;
    }

    @NonNull
    public static ItemNovelLayoutVerticalBinding bind(@NonNull View view) {
        int i2 = R.id.img_cover;
        ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.img_cover);
        if (shapeableImageView != null) {
            i2 = R.id.item_more;
            RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.item_more);
            if (relativeLayout != null) {
                i2 = R.id.item_parent;
                RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.item_parent);
                if (relativeLayout2 != null) {
                    i2 = R.id.itv_ad;
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
                                    i2 = R.id.itv_type;
                                    ImageTextView imageTextView4 = (ImageTextView) view.findViewById(R.id.itv_type);
                                    if (imageTextView4 != null) {
                                        i2 = R.id.itv_zhiding;
                                        ImageTextView imageTextView5 = (ImageTextView) view.findViewById(R.id.itv_zhiding);
                                        if (imageTextView5 != null) {
                                            i2 = R.id.iv_ico_type;
                                            ImageView imageView = (ImageView) view.findViewById(R.id.iv_ico_type);
                                            if (imageView != null) {
                                                i2 = R.id.iv_novel_audio;
                                                ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_novel_audio);
                                                if (imageView2 != null) {
                                                    i2 = R.id.ll_bottom_cover;
                                                    RelativeLayout relativeLayout3 = (RelativeLayout) view.findViewById(R.id.ll_bottom_cover);
                                                    if (relativeLayout3 != null) {
                                                        i2 = R.id.ll_name;
                                                        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_name);
                                                        if (linearLayout != null) {
                                                            i2 = R.id.rl_coverOption;
                                                            LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.rl_coverOption);
                                                            if (linearLayout2 != null) {
                                                                i2 = R.id.space_left;
                                                                TextView textView2 = (TextView) view.findViewById(R.id.space_left);
                                                                if (textView2 != null) {
                                                                    i2 = R.id.text_price_type;
                                                                    GradientTextView gradientTextView = (GradientTextView) view.findViewById(R.id.text_price_type);
                                                                    if (gradientTextView != null) {
                                                                        i2 = R.id.tv_duration;
                                                                        TextView textView3 = (TextView) view.findViewById(R.id.tv_duration);
                                                                        if (textView3 != null) {
                                                                            i2 = R.id.tv_novel_category_subtitle;
                                                                            TextView textView4 = (TextView) view.findViewById(R.id.tv_novel_category_subtitle);
                                                                            if (textView4 != null) {
                                                                                i2 = R.id.tv_novel_name;
                                                                                TextView textView5 = (TextView) view.findViewById(R.id.tv_novel_name);
                                                                                if (textView5 != null) {
                                                                                    i2 = R.id.tv_slide_more;
                                                                                    TextView textView6 = (TextView) view.findViewById(R.id.tv_slide_more);
                                                                                    if (textView6 != null) {
                                                                                        return new ItemNovelLayoutVerticalBinding((LinearLayout) view, shapeableImageView, relativeLayout, relativeLayout2, textView, imageTextView, imageTextView2, imageTextView3, imageTextView4, imageTextView5, imageView, imageView2, relativeLayout3, linearLayout, linearLayout2, textView2, gradientTextView, textView3, textView4, textView5, textView6);
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
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemNovelLayoutVerticalBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemNovelLayoutVerticalBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_novel_layout_vertical, viewGroup, false);
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
