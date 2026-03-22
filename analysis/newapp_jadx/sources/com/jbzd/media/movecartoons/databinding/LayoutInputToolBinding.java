package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatEditText;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class LayoutInputToolBinding implements ViewBinding {

    @NonNull
    public final ImageView ivCommentPost;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final RelativeLayout titleLayout;

    @NonNull
    public final AppCompatEditText tvInputComment;

    private LayoutInputToolBinding(@NonNull RelativeLayout relativeLayout, @NonNull ImageView imageView, @NonNull RelativeLayout relativeLayout2, @NonNull AppCompatEditText appCompatEditText) {
        this.rootView = relativeLayout;
        this.ivCommentPost = imageView;
        this.titleLayout = relativeLayout2;
        this.tvInputComment = appCompatEditText;
    }

    @NonNull
    public static LayoutInputToolBinding bind(@NonNull View view) {
        int i2 = R.id.iv_comment_post;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_comment_post);
        if (imageView != null) {
            RelativeLayout relativeLayout = (RelativeLayout) view;
            AppCompatEditText appCompatEditText = (AppCompatEditText) view.findViewById(R.id.tv_input_comment);
            if (appCompatEditText != null) {
                return new LayoutInputToolBinding(relativeLayout, imageView, relativeLayout, appCompatEditText);
            }
            i2 = R.id.tv_input_comment;
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static LayoutInputToolBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LayoutInputToolBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.layout_input_tool, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RelativeLayout getRoot() {
        return this.rootView;
    }
}
