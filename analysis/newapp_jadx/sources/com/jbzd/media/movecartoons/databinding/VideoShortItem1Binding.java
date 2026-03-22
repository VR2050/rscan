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
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoShortItem1Binding implements ViewBinding {

    @NonNull
    public final RelativeLayout itemMore;

    @NonNull
    public final RelativeLayout itemParent;

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
    public final LinearLayout llAdNew;

    @NonNull
    public final LinearLayout llMoneyVip;

    @NonNull
    public final LinearLayout llName;

    @NonNull
    public final RelativeLayout rlCoverOption;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvVideoClick;

    @NonNull
    public final TextView tvVideoType;

    private VideoShortItem1Binding(@NonNull LinearLayout linearLayout, @NonNull RelativeLayout relativeLayout, @NonNull RelativeLayout relativeLayout2, @NonNull TextView textView, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageView imageView, @NonNull ShapeableImageView shapeableImageView, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull RelativeLayout relativeLayout3, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = linearLayout;
        this.itemMore = relativeLayout;
        this.itemParent = relativeLayout2;
        this.itvAdNew = textView;
        this.itvIconMoney = imageTextView;
        this.ivCoinVideo = imageTextView2;
        this.ivIcoType = imageView;
        this.ivVideo = shapeableImageView;
        this.llAdNew = linearLayout2;
        this.llMoneyVip = linearLayout3;
        this.llName = linearLayout4;
        this.rlCoverOption = relativeLayout3;
        this.tvName = textView2;
        this.tvVideoClick = textView3;
        this.tvVideoType = textView4;
    }

    @NonNull
    public static VideoShortItem1Binding bind(@NonNull View view) {
        int i2 = R.id.item_more;
        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.item_more);
        if (relativeLayout != null) {
            i2 = R.id.item_parent;
            RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.item_parent);
            if (relativeLayout2 != null) {
                i2 = R.id.itv_ad_new;
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
                                    i2 = R.id.ll_ad_new;
                                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_ad_new);
                                    if (linearLayout != null) {
                                        i2 = R.id.ll_money_vip;
                                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_money_vip);
                                        if (linearLayout2 != null) {
                                            i2 = R.id.ll_name;
                                            LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_name);
                                            if (linearLayout3 != null) {
                                                i2 = R.id.rl_coverOption;
                                                RelativeLayout relativeLayout3 = (RelativeLayout) view.findViewById(R.id.rl_coverOption);
                                                if (relativeLayout3 != null) {
                                                    i2 = R.id.tv_name;
                                                    TextView textView2 = (TextView) view.findViewById(R.id.tv_name);
                                                    if (textView2 != null) {
                                                        i2 = R.id.tv_video_click;
                                                        TextView textView3 = (TextView) view.findViewById(R.id.tv_video_click);
                                                        if (textView3 != null) {
                                                            i2 = R.id.tv_video_type;
                                                            TextView textView4 = (TextView) view.findViewById(R.id.tv_video_type);
                                                            if (textView4 != null) {
                                                                return new VideoShortItem1Binding((LinearLayout) view, relativeLayout, relativeLayout2, textView, imageTextView, imageTextView2, imageView, shapeableImageView, linearLayout, linearLayout2, linearLayout3, relativeLayout3, textView2, textView3, textView4);
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
    public static VideoShortItem1Binding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoShortItem1Binding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_short_item1, viewGroup, false);
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
