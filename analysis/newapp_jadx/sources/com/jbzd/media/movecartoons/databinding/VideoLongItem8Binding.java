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
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoLongItem8Binding implements ViewBinding {

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    public final RelativeLayout itemParent;

    @NonNull
    public final ImageTextView itvLike;

    @NonNull
    public final ImageView ivOption;

    @NonNull
    public final ShapeableImageView ivVideo;

    @NonNull
    public final LinearLayout llItem;

    @NonNull
    public final LinearLayout llUpper;

    @NonNull
    public final RelativeLayout rlCoverOption;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvTag;

    @NonNull
    public final LinearLayout sml;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvTitle;

    private VideoLongItem8Binding(@NonNull LinearLayout linearLayout, @NonNull CircleImageView circleImageView, @NonNull RelativeLayout relativeLayout, @NonNull ImageTextView imageTextView, @NonNull ImageView imageView, @NonNull ShapeableImageView shapeableImageView, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull RelativeLayout relativeLayout2, @NonNull RecyclerView recyclerView, @NonNull LinearLayout linearLayout4, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = linearLayout;
        this.civHead = circleImageView;
        this.itemParent = relativeLayout;
        this.itvLike = imageTextView;
        this.ivOption = imageView;
        this.ivVideo = shapeableImageView;
        this.llItem = linearLayout2;
        this.llUpper = linearLayout3;
        this.rlCoverOption = relativeLayout2;
        this.rvTag = recyclerView;
        this.sml = linearLayout4;
        this.tvDesc = textView;
        this.tvName = textView2;
        this.tvTitle = textView3;
    }

    @NonNull
    public static VideoLongItem8Binding bind(@NonNull View view) {
        int i2 = R.id.civ_head;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
        if (circleImageView != null) {
            i2 = R.id.item_parent;
            RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.item_parent);
            if (relativeLayout != null) {
                i2 = R.id.itv_like;
                ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_like);
                if (imageTextView != null) {
                    i2 = R.id.iv_option;
                    ImageView imageView = (ImageView) view.findViewById(R.id.iv_option);
                    if (imageView != null) {
                        i2 = R.id.iv_video;
                        ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_video);
                        if (shapeableImageView != null) {
                            i2 = R.id.ll_item;
                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_item);
                            if (linearLayout != null) {
                                i2 = R.id.ll_upper;
                                LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_upper);
                                if (linearLayout2 != null) {
                                    i2 = R.id.rl_coverOption;
                                    RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.rl_coverOption);
                                    if (relativeLayout2 != null) {
                                        i2 = R.id.rv_tag;
                                        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_tag);
                                        if (recyclerView != null) {
                                            LinearLayout linearLayout3 = (LinearLayout) view;
                                            i2 = R.id.tv_desc;
                                            TextView textView = (TextView) view.findViewById(R.id.tv_desc);
                                            if (textView != null) {
                                                i2 = R.id.tv_name;
                                                TextView textView2 = (TextView) view.findViewById(R.id.tv_name);
                                                if (textView2 != null) {
                                                    i2 = R.id.tv_title;
                                                    TextView textView3 = (TextView) view.findViewById(R.id.tv_title);
                                                    if (textView3 != null) {
                                                        return new VideoLongItem8Binding(linearLayout3, circleImageView, relativeLayout, imageTextView, imageView, shapeableImageView, linearLayout, linearLayout2, relativeLayout2, recyclerView, linearLayout3, textView, textView2, textView3);
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
    public static VideoLongItem8Binding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoLongItem8Binding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_long_item8, viewGroup, false);
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
