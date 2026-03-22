package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoUnlockItemShortBinding implements ViewBinding {

    @NonNull
    public final ScaleRelativeLayout itemParent;

    @NonNull
    public final ImageTextView itvPrice;

    @NonNull
    public final ShapeableImageView ivVideo;

    @NonNull
    public final LinearLayout layoutItemBottomInfo;

    @NonNull
    public final LinearLayout llName;

    @NonNull
    public final RelativeLayout rlCoverOption;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView tvGood;

    @NonNull
    public final TextView tvIsPlaying;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvTag;

    private VideoUnlockItemShortBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull ImageTextView imageTextView, @NonNull ShapeableImageView shapeableImageView, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull RelativeLayout relativeLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = constraintLayout;
        this.itemParent = scaleRelativeLayout;
        this.itvPrice = imageTextView;
        this.ivVideo = shapeableImageView;
        this.layoutItemBottomInfo = linearLayout;
        this.llName = linearLayout2;
        this.rlCoverOption = relativeLayout;
        this.tvGood = textView;
        this.tvIsPlaying = textView2;
        this.tvName = textView3;
        this.tvTag = textView4;
    }

    @NonNull
    public static VideoUnlockItemShortBinding bind(@NonNull View view) {
        int i2 = R.id.item_parent;
        ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.item_parent);
        if (scaleRelativeLayout != null) {
            i2 = R.id.itv_price;
            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_price);
            if (imageTextView != null) {
                i2 = R.id.iv_video;
                ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_video);
                if (shapeableImageView != null) {
                    i2 = R.id.layout_item_bottom_info;
                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.layout_item_bottom_info);
                    if (linearLayout != null) {
                        i2 = R.id.ll_name;
                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_name);
                        if (linearLayout2 != null) {
                            i2 = R.id.rl_coverOption;
                            RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_coverOption);
                            if (relativeLayout != null) {
                                i2 = R.id.tv_good;
                                TextView textView = (TextView) view.findViewById(R.id.tv_good);
                                if (textView != null) {
                                    i2 = R.id.tv_isPlaying;
                                    TextView textView2 = (TextView) view.findViewById(R.id.tv_isPlaying);
                                    if (textView2 != null) {
                                        i2 = R.id.tv_name;
                                        TextView textView3 = (TextView) view.findViewById(R.id.tv_name);
                                        if (textView3 != null) {
                                            i2 = R.id.tv_tag;
                                            TextView textView4 = (TextView) view.findViewById(R.id.tv_tag);
                                            if (textView4 != null) {
                                                return new VideoUnlockItemShortBinding((ConstraintLayout) view, scaleRelativeLayout, imageTextView, shapeableImageView, linearLayout, linearLayout2, relativeLayout, textView, textView2, textView3, textView4);
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
    public static VideoUnlockItemShortBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoUnlockItemShortBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_unlock_item_short, viewGroup, false);
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
