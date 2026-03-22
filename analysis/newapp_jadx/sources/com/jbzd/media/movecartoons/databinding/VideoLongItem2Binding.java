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
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoLongItem2Binding implements ViewBinding {

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    public final RelativeLayout itemParent;

    @NonNull
    public final ImageView ivOption;

    @NonNull
    public final ShapeableImageView ivVideo;

    @NonNull
    public final ImageView ivVideoOption;

    @NonNull
    public final LinearLayout llItem;

    @NonNull
    public final LinearLayout llName;

    @NonNull
    public final LinearLayout llUpper;

    @NonNull
    public final RelativeLayout rlCoverOption;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvCreatorName;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvHisDesc;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvTitle;

    private VideoLongItem2Binding(@NonNull LinearLayout linearLayout, @NonNull CircleImageView circleImageView, @NonNull RelativeLayout relativeLayout, @NonNull ImageView imageView, @NonNull ShapeableImageView shapeableImageView, @NonNull ImageView imageView2, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull RelativeLayout relativeLayout2, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5) {
        this.rootView = linearLayout;
        this.civHead = circleImageView;
        this.itemParent = relativeLayout;
        this.ivOption = imageView;
        this.ivVideo = shapeableImageView;
        this.ivVideoOption = imageView2;
        this.llItem = linearLayout2;
        this.llName = linearLayout3;
        this.llUpper = linearLayout4;
        this.rlCoverOption = relativeLayout2;
        this.tvCreatorName = textView;
        this.tvDesc = textView2;
        this.tvHisDesc = textView3;
        this.tvName = textView4;
        this.tvTitle = textView5;
    }

    @NonNull
    public static VideoLongItem2Binding bind(@NonNull View view) {
        int i2 = R.id.civ_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
        if (circleImageView != null) {
            i2 = R.id.item_parent;
            RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.item_parent);
            if (relativeLayout != null) {
                i2 = R.id.iv_option;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_option);
                if (imageView != null) {
                    i2 = R.id.iv_video;
                    ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_video);
                    if (shapeableImageView != null) {
                        i2 = R.id.iv_videoOption;
                        ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_videoOption);
                        if (imageView2 != null) {
                            LinearLayout linearLayout = (LinearLayout) view;
                            i2 = R.id.ll_name;
                            LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_name);
                            if (linearLayout2 != null) {
                                i2 = R.id.ll_upper;
                                LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_upper);
                                if (linearLayout3 != null) {
                                    i2 = R.id.rl_coverOption;
                                    RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.rl_coverOption);
                                    if (relativeLayout2 != null) {
                                        i2 = R.id.tv_creatorName;
                                        TextView textView = (TextView) view.findViewById(R.id.tv_creatorName);
                                        if (textView != null) {
                                            i2 = R.id.tv_desc;
                                            TextView textView2 = (TextView) view.findViewById(R.id.tv_desc);
                                            if (textView2 != null) {
                                                i2 = R.id.tv_hisDesc;
                                                TextView textView3 = (TextView) view.findViewById(R.id.tv_hisDesc);
                                                if (textView3 != null) {
                                                    i2 = R.id.tv_name;
                                                    TextView textView4 = (TextView) view.findViewById(R.id.tv_name);
                                                    if (textView4 != null) {
                                                        i2 = R.id.tv_title;
                                                        TextView textView5 = (TextView) view.findViewById(R.id.tv_title);
                                                        if (textView5 != null) {
                                                            return new VideoLongItem2Binding(linearLayout, circleImageView, relativeLayout, imageView, shapeableImageView, imageView2, linearLayout, linearLayout2, linearLayout3, relativeLayout2, textView, textView2, textView3, textView4, textView5);
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
    public static VideoLongItem2Binding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoLongItem2Binding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_long_item2, viewGroup, false);
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
