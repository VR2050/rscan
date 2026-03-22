package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
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
public final class VideoUnlockWidthItemBinding implements ViewBinding {

    @NonNull
    public final RelativeLayout itemParent;

    @NonNull
    public final ShapeableImageView ivVideo;

    @NonNull
    public final LinearLayout llItem;

    @NonNull
    public final LinearLayout llName;

    @NonNull
    public final RelativeLayout rlCoverOption;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvContact;

    @NonNull
    public final ImageTextView tvDate;

    @NonNull
    public final ImageTextView tvName;

    @NonNull
    public final ImageTextView tvPrice;

    @NonNull
    public final ImageTextView tvService;

    private VideoUnlockWidthItemBinding(@NonNull LinearLayout linearLayout, @NonNull RelativeLayout relativeLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull RelativeLayout relativeLayout2, @NonNull TextView textView, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull ImageTextView imageTextView4) {
        this.rootView = linearLayout;
        this.itemParent = relativeLayout;
        this.ivVideo = shapeableImageView;
        this.llItem = linearLayout2;
        this.llName = linearLayout3;
        this.rlCoverOption = relativeLayout2;
        this.tvContact = textView;
        this.tvDate = imageTextView;
        this.tvName = imageTextView2;
        this.tvPrice = imageTextView3;
        this.tvService = imageTextView4;
    }

    @NonNull
    public static VideoUnlockWidthItemBinding bind(@NonNull View view) {
        int i2 = R.id.item_parent;
        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.item_parent);
        if (relativeLayout != null) {
            i2 = R.id.iv_video;
            ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_video);
            if (shapeableImageView != null) {
                LinearLayout linearLayout = (LinearLayout) view;
                i2 = R.id.ll_name;
                LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_name);
                if (linearLayout2 != null) {
                    i2 = R.id.rl_coverOption;
                    RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.rl_coverOption);
                    if (relativeLayout2 != null) {
                        i2 = R.id.tv_contact;
                        TextView textView = (TextView) view.findViewById(R.id.tv_contact);
                        if (textView != null) {
                            i2 = R.id.tv_date;
                            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.tv_date);
                            if (imageTextView != null) {
                                i2 = R.id.tv_name;
                                ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.tv_name);
                                if (imageTextView2 != null) {
                                    i2 = R.id.tv_price;
                                    ImageTextView imageTextView3 = (ImageTextView) view.findViewById(R.id.tv_price);
                                    if (imageTextView3 != null) {
                                        i2 = R.id.tv_service;
                                        ImageTextView imageTextView4 = (ImageTextView) view.findViewById(R.id.tv_service);
                                        if (imageTextView4 != null) {
                                            return new VideoUnlockWidthItemBinding(linearLayout, relativeLayout, shapeableImageView, linearLayout, linearLayout2, relativeLayout2, textView, imageTextView, imageTextView2, imageTextView3, imageTextView4);
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
    public static VideoUnlockWidthItemBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static VideoUnlockWidthItemBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.video_unlock_width_item, viewGroup, false);
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
