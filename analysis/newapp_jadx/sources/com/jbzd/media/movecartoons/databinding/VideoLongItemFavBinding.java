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
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoLongItemFavBinding implements ViewBinding {

    @NonNull
    public final ImageView checkboxDel;

    @NonNull
    public final ScaleRelativeLayout itemParent;

    @NonNull
    public final ShapeableImageView ivVideo;

    @NonNull
    public final ImageView ivVideoOption;

    @NonNull
    public final TextView like;

    @NonNull
    public final LinearLayout llAnchor;

    @NonNull
    public final LinearLayout llItemVideo;

    @NonNull
    public final LinearLayout llName;

    @NonNull
    public final LinearLayout llUpper;

    @NonNull
    public final RelativeLayout rlCoverOption;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvIsPlaying;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final ConstraintLayout videoCheckView;

    private VideoLongItemFavBinding(@NonNull LinearLayout linearLayout, @NonNull ImageView imageView, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull ImageView imageView2, @NonNull TextView textView, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull RelativeLayout relativeLayout, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull ConstraintLayout constraintLayout) {
        this.rootView = linearLayout;
        this.checkboxDel = imageView;
        this.itemParent = scaleRelativeLayout;
        this.ivVideo = shapeableImageView;
        this.ivVideoOption = imageView2;
        this.like = textView;
        this.llAnchor = linearLayout2;
        this.llItemVideo = linearLayout3;
        this.llName = linearLayout4;
        this.llUpper = linearLayout5;
        this.rlCoverOption = relativeLayout;
        this.tvDesc = textView2;
        this.tvIsPlaying = textView3;
        this.tvName = textView4;
        this.tvTitle = textView5;
        this.videoCheckView = constraintLayout;
    }

    @NonNull
    public static VideoLongItemFavBinding bind(@NonNull View view) {
        int i2 = R.id.checkbox_del;
        ImageView imageView = (ImageView) view.findViewById(R.id.checkbox_del);
        if (imageView != null) {
            i2 = R.id.item_parent;
            ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.item_parent);
            if (scaleRelativeLayout != null) {
                i2 = R.id.iv_video;
                ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_video);
                if (shapeableImageView != null) {
                    i2 = R.id.iv_videoOption;
                    ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_videoOption);
                    if (imageView2 != null) {
                        i2 = R.id.like;
                        TextView textView = (TextView) view.findViewById(R.id.like);
                        if (textView != null) {
                            i2 = R.id.ll_anchor;
                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_anchor);
                            if (linearLayout != null) {
                                LinearLayout linearLayout2 = (LinearLayout) view;
                                i2 = R.id.ll_name;
                                LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_name);
                                if (linearLayout3 != null) {
                                    i2 = R.id.ll_upper;
                                    LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_upper);
                                    if (linearLayout4 != null) {
                                        i2 = R.id.rl_coverOption;
                                        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_coverOption);
                                        if (relativeLayout != null) {
                                            i2 = R.id.tv_desc;
                                            TextView textView2 = (TextView) view.findViewById(R.id.tv_desc);
                                            if (textView2 != null) {
                                                i2 = R.id.tv_isPlaying;
                                                TextView textView3 = (TextView) view.findViewById(R.id.tv_isPlaying);
                                                if (textView3 != null) {
                                                    i2 = R.id.tv_name;
                                                    TextView textView4 = (TextView) view.findViewById(R.id.tv_name);
                                                    if (textView4 != null) {
                                                        i2 = R.id.tv_title;
                                                        TextView textView5 = (TextView) view.findViewById(R.id.tv_title);
                                                        if (textView5 != null) {
                                                            i2 = R.id.video_check_view;
                                                            ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.video_check_view);
                                                            if (constraintLayout != null) {
                                                                return new VideoLongItemFavBinding(linearLayout2, imageView, scaleRelativeLayout, shapeableImageView, imageView2, textView, linearLayout, linearLayout2, linearLayout3, linearLayout4, relativeLayout, textView2, textView3, textView4, textView5, constraintLayout);
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
    public static VideoLongItemFavBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoLongItemFavBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_long_item_fav, viewGroup, false);
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
