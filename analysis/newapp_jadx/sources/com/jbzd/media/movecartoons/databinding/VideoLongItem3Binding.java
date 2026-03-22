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
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoLongItem3Binding implements ViewBinding {

    @NonNull
    public final TextView itvAdNew;

    @NonNull
    public final ImageTextView itvIconMoney;

    @NonNull
    public final ImageTextView ivCoinVideo;

    @NonNull
    public final ImageView ivIcoType;

    @NonNull
    public final ShapeableImageView ivVideo;

    @NonNull
    public final ShapeableImageView ivVideoVertical;

    @NonNull
    public final RelativeLayout llAdNew;

    @NonNull
    public final LinearLayout llMoneyVip;

    @NonNull
    public final LinearLayout llName;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final ScaleRelativeLayout srlCoverParentImg;

    @NonNull
    public final ScaleRelativeLayout srlCoverParentVertical;

    @NonNull
    public final TextView tvDuration;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvVideoClick;

    @NonNull
    public final TextView tvVideoType;

    private VideoLongItem3Binding(@NonNull LinearLayout linearLayout, @NonNull TextView textView, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageView imageView, @NonNull ShapeableImageView shapeableImageView, @NonNull ShapeableImageView shapeableImageView2, @NonNull RelativeLayout relativeLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull ScaleRelativeLayout scaleRelativeLayout2, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5) {
        this.rootView = linearLayout;
        this.itvAdNew = textView;
        this.itvIconMoney = imageTextView;
        this.ivCoinVideo = imageTextView2;
        this.ivIcoType = imageView;
        this.ivVideo = shapeableImageView;
        this.ivVideoVertical = shapeableImageView2;
        this.llAdNew = relativeLayout;
        this.llMoneyVip = linearLayout2;
        this.llName = linearLayout3;
        this.srlCoverParentImg = scaleRelativeLayout;
        this.srlCoverParentVertical = scaleRelativeLayout2;
        this.tvDuration = textView2;
        this.tvName = textView3;
        this.tvVideoClick = textView4;
        this.tvVideoType = textView5;
    }

    @NonNull
    public static VideoLongItem3Binding bind(@NonNull View view) {
        int i2 = R.id.itv_ad_new;
        TextView textView = (TextView) view.findViewById(R.id.itv_ad_new);
        if (textView != null) {
            i2 = R.id.itv_icon_money;
            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_icon_money);
            if (imageTextView != null) {
                i2 = R.id.iv_coin_video;
                ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.iv_coin_video);
                if (imageTextView2 != null) {
                    i2 = R.id.iv_ico_type;
                    ImageView imageView = (ImageView) view.findViewById(R.id.iv_ico_type);
                    if (imageView != null) {
                        i2 = R.id.iv_video;
                        ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_video);
                        if (shapeableImageView != null) {
                            i2 = R.id.iv_video_vertical;
                            ShapeableImageView shapeableImageView2 = (ShapeableImageView) view.findViewById(R.id.iv_video_vertical);
                            if (shapeableImageView2 != null) {
                                i2 = R.id.ll_ad_new;
                                RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.ll_ad_new);
                                if (relativeLayout != null) {
                                    i2 = R.id.ll_money_vip;
                                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_money_vip);
                                    if (linearLayout != null) {
                                        i2 = R.id.ll_name;
                                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_name);
                                        if (linearLayout2 != null) {
                                            i2 = R.id.srl_coverParent_img;
                                            ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.srl_coverParent_img);
                                            if (scaleRelativeLayout != null) {
                                                i2 = R.id.srl_coverParent_vertical;
                                                ScaleRelativeLayout scaleRelativeLayout2 = (ScaleRelativeLayout) view.findViewById(R.id.srl_coverParent_vertical);
                                                if (scaleRelativeLayout2 != null) {
                                                    i2 = R.id.tv_duration;
                                                    TextView textView2 = (TextView) view.findViewById(R.id.tv_duration);
                                                    if (textView2 != null) {
                                                        i2 = R.id.tv_name;
                                                        TextView textView3 = (TextView) view.findViewById(R.id.tv_name);
                                                        if (textView3 != null) {
                                                            i2 = R.id.tv_video_click;
                                                            TextView textView4 = (TextView) view.findViewById(R.id.tv_video_click);
                                                            if (textView4 != null) {
                                                                i2 = R.id.tv_video_type;
                                                                TextView textView5 = (TextView) view.findViewById(R.id.tv_video_type);
                                                                if (textView5 != null) {
                                                                    return new VideoLongItem3Binding((LinearLayout) view, textView, imageTextView, imageTextView2, imageView, shapeableImageView, shapeableImageView2, relativeLayout, linearLayout, linearLayout2, scaleRelativeLayout, scaleRelativeLayout2, textView2, textView3, textView4, textView5);
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
    public static VideoLongItem3Binding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoLongItem3Binding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_long_item3, viewGroup, false);
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
