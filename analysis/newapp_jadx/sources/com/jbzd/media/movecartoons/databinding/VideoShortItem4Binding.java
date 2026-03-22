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
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoShortItem4Binding implements ViewBinding {

    @NonNull
    public final ScaleRelativeLayout itemParent;

    @NonNull
    public final ImageView ivOption;

    @NonNull
    public final ShapeableImageView ivVideo;

    @NonNull
    public final LinearLayout llName;

    @NonNull
    public final RelativeLayout rlCoverOption;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvName;

    private VideoShortItem4Binding(@NonNull LinearLayout linearLayout, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull ImageView imageView, @NonNull ShapeableImageView shapeableImageView, @NonNull LinearLayout linearLayout2, @NonNull RelativeLayout relativeLayout, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.itemParent = scaleRelativeLayout;
        this.ivOption = imageView;
        this.ivVideo = shapeableImageView;
        this.llName = linearLayout2;
        this.rlCoverOption = relativeLayout;
        this.tvName = textView;
    }

    @NonNull
    public static VideoShortItem4Binding bind(@NonNull View view) {
        int i2 = R.id.item_parent;
        ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.item_parent);
        if (scaleRelativeLayout != null) {
            i2 = R.id.iv_option;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_option);
            if (imageView != null) {
                i2 = R.id.iv_video;
                ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_video);
                if (shapeableImageView != null) {
                    i2 = R.id.ll_name;
                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_name);
                    if (linearLayout != null) {
                        i2 = R.id.rl_coverOption;
                        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_coverOption);
                        if (relativeLayout != null) {
                            i2 = R.id.tv_name;
                            TextView textView = (TextView) view.findViewById(R.id.tv_name);
                            if (textView != null) {
                                return new VideoShortItem4Binding((LinearLayout) view, scaleRelativeLayout, imageView, shapeableImageView, linearLayout, relativeLayout, textView);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static VideoShortItem4Binding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoShortItem4Binding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_short_item4, viewGroup, false);
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
