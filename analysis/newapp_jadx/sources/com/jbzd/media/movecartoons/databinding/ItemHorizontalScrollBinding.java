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
public final class ItemHorizontalScrollBinding implements ViewBinding {

    @NonNull
    public final ScaleRelativeLayout itemParent;

    @NonNull
    public final ImageView ivNovelAudio;

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

    @NonNull
    public final TextView tvVideoClick;

    private ItemHorizontalScrollBinding(@NonNull LinearLayout linearLayout, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull ImageView imageView, @NonNull ShapeableImageView shapeableImageView, @NonNull LinearLayout linearLayout2, @NonNull RelativeLayout relativeLayout, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.itemParent = scaleRelativeLayout;
        this.ivNovelAudio = imageView;
        this.ivVideo = shapeableImageView;
        this.llName = linearLayout2;
        this.rlCoverOption = relativeLayout;
        this.tvName = textView;
        this.tvVideoClick = textView2;
    }

    @NonNull
    public static ItemHorizontalScrollBinding bind(@NonNull View view) {
        int i2 = R.id.item_parent;
        ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.item_parent);
        if (scaleRelativeLayout != null) {
            i2 = R.id.iv_novel_audio;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_novel_audio);
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
                                i2 = R.id.tv_video_click;
                                TextView textView2 = (TextView) view.findViewById(R.id.tv_video_click);
                                if (textView2 != null) {
                                    return new ItemHorizontalScrollBinding((LinearLayout) view, scaleRelativeLayout, imageView, shapeableImageView, linearLayout, relativeLayout, textView, textView2);
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
    public static ItemHorizontalScrollBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemHorizontalScrollBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_horizontal_scroll, viewGroup, false);
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
