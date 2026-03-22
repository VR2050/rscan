package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Guideline;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.qnmd.adnnm.da0yzo.R;
import io.github.armcha.autolink.AutoLinkTextView;

/* loaded from: classes2.dex */
public final class ItemChatLogSystemBinding implements ViewBinding {

    @NonNull
    public final Guideline guideLine;

    @NonNull
    public final ImageView ivContentImage;

    @NonNull
    public final ShapeableImageView ivPortrait;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final AutoLinkTextView tvContent;

    @NonNull
    public final TextView tvTime;

    private ItemChatLogSystemBinding(@NonNull ConstraintLayout constraintLayout, @NonNull Guideline guideline, @NonNull ImageView imageView, @NonNull ShapeableImageView shapeableImageView, @NonNull AutoLinkTextView autoLinkTextView, @NonNull TextView textView) {
        this.rootView = constraintLayout;
        this.guideLine = guideline;
        this.ivContentImage = imageView;
        this.ivPortrait = shapeableImageView;
        this.tvContent = autoLinkTextView;
        this.tvTime = textView;
    }

    @NonNull
    public static ItemChatLogSystemBinding bind(@NonNull View view) {
        int i2 = R.id.guideLine;
        Guideline guideline = (Guideline) view.findViewById(R.id.guideLine);
        if (guideline != null) {
            i2 = R.id.iv_content_image;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_content_image);
            if (imageView != null) {
                i2 = R.id.iv_portrait;
                ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_portrait);
                if (shapeableImageView != null) {
                    i2 = R.id.tv_content;
                    AutoLinkTextView autoLinkTextView = (AutoLinkTextView) view.findViewById(R.id.tv_content);
                    if (autoLinkTextView != null) {
                        i2 = R.id.tv_time;
                        TextView textView = (TextView) view.findViewById(R.id.tv_time);
                        if (textView != null) {
                            return new ItemChatLogSystemBinding((ConstraintLayout) view, guideline, imageView, shapeableImageView, autoLinkTextView, textView);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemChatLogSystemBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemChatLogSystemBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_chat_log_system, viewGroup, false);
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
