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
import com.android.p394db.swipemenulayout.SwipeMenuLayout;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class VideoLongItemRemoveCacheBinding implements ViewBinding {

    @NonNull
    public final TextView btn;

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    public final ImageView iconDelete;

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
    public final ConstraintLayout rightItem;

    @NonNull
    public final RelativeLayout rlCoverOption;

    @NonNull
    private final SwipeMenuLayout rootView;

    @NonNull
    public final SwipeMenuLayout sml;

    @NonNull
    public final LinearLayout tagContainer;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvDownload;

    @NonNull
    public final TextView tvDownloadSpeed;

    @NonNull
    public final TextView tvName;

    @NonNull
    public final TextView tvTitle;

    private VideoLongItemRemoveCacheBinding(@NonNull SwipeMenuLayout swipeMenuLayout, @NonNull TextView textView, @NonNull CircleImageView circleImageView, @NonNull ImageView imageView, @NonNull RelativeLayout relativeLayout, @NonNull ImageView imageView2, @NonNull ShapeableImageView shapeableImageView, @NonNull ImageView imageView3, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull ConstraintLayout constraintLayout, @NonNull RelativeLayout relativeLayout2, @NonNull SwipeMenuLayout swipeMenuLayout2, @NonNull LinearLayout linearLayout4, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6) {
        this.rootView = swipeMenuLayout;
        this.btn = textView;
        this.civHead = circleImageView;
        this.iconDelete = imageView;
        this.itemParent = relativeLayout;
        this.ivOption = imageView2;
        this.ivVideo = shapeableImageView;
        this.ivVideoOption = imageView3;
        this.llItem = linearLayout;
        this.llName = linearLayout2;
        this.llUpper = linearLayout3;
        this.rightItem = constraintLayout;
        this.rlCoverOption = relativeLayout2;
        this.sml = swipeMenuLayout2;
        this.tagContainer = linearLayout4;
        this.tvDesc = textView2;
        this.tvDownload = textView3;
        this.tvDownloadSpeed = textView4;
        this.tvName = textView5;
        this.tvTitle = textView6;
    }

    @NonNull
    public static VideoLongItemRemoveCacheBinding bind(@NonNull View view) {
        int i2 = R.id.btn;
        TextView textView = (TextView) view.findViewById(R.id.btn);
        if (textView != null) {
            i2 = R.id.civ_head;
            CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
            if (circleImageView != null) {
                i2 = R.id.icon_delete;
                ImageView imageView = (ImageView) view.findViewById(R.id.icon_delete);
                if (imageView != null) {
                    i2 = R.id.item_parent;
                    RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.item_parent);
                    if (relativeLayout != null) {
                        i2 = R.id.iv_option;
                        ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_option);
                        if (imageView2 != null) {
                            i2 = R.id.iv_video;
                            ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_video);
                            if (shapeableImageView != null) {
                                i2 = R.id.iv_videoOption;
                                ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_videoOption);
                                if (imageView3 != null) {
                                    i2 = R.id.ll_item;
                                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_item);
                                    if (linearLayout != null) {
                                        i2 = R.id.ll_name;
                                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_name);
                                        if (linearLayout2 != null) {
                                            i2 = R.id.ll_upper;
                                            LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_upper);
                                            if (linearLayout3 != null) {
                                                i2 = R.id.right_item;
                                                ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.right_item);
                                                if (constraintLayout != null) {
                                                    i2 = R.id.rl_coverOption;
                                                    RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.rl_coverOption);
                                                    if (relativeLayout2 != null) {
                                                        SwipeMenuLayout swipeMenuLayout = (SwipeMenuLayout) view;
                                                        i2 = R.id.tag_container;
                                                        LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.tag_container);
                                                        if (linearLayout4 != null) {
                                                            i2 = R.id.tv_desc;
                                                            TextView textView2 = (TextView) view.findViewById(R.id.tv_desc);
                                                            if (textView2 != null) {
                                                                i2 = R.id.tvDownload;
                                                                TextView textView3 = (TextView) view.findViewById(R.id.tvDownload);
                                                                if (textView3 != null) {
                                                                    i2 = R.id.tvDownload_speed;
                                                                    TextView textView4 = (TextView) view.findViewById(R.id.tvDownload_speed);
                                                                    if (textView4 != null) {
                                                                        i2 = R.id.tv_name;
                                                                        TextView textView5 = (TextView) view.findViewById(R.id.tv_name);
                                                                        if (textView5 != null) {
                                                                            i2 = R.id.tv_title;
                                                                            TextView textView6 = (TextView) view.findViewById(R.id.tv_title);
                                                                            if (textView6 != null) {
                                                                                return new VideoLongItemRemoveCacheBinding(swipeMenuLayout, textView, circleImageView, imageView, relativeLayout, imageView2, shapeableImageView, imageView3, linearLayout, linearLayout2, linearLayout3, constraintLayout, relativeLayout2, swipeMenuLayout, linearLayout4, textView2, textView3, textView4, textView5, textView6);
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
    public static VideoLongItemRemoveCacheBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoLongItemRemoveCacheBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_long_item_remove_cache, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public SwipeMenuLayout getRoot() {
        return this.rootView;
    }
}
