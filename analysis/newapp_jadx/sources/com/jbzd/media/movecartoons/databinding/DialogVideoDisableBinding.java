package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;
import io.github.armcha.autolink.AutoLinkTextView;

/* loaded from: classes2.dex */
public final class DialogVideoDisableBinding implements ViewBinding {

    @NonNull
    public final TextView btnSubmitAichangefaceVideo;

    @NonNull
    public final FrameLayout flDialogDisable;

    @NonNull
    public final ImageView ivClose;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final AutoLinkTextView tvContent;

    @NonNull
    public final TextView tvTitle;

    private DialogVideoDisableBinding(@NonNull FrameLayout frameLayout, @NonNull TextView textView, @NonNull FrameLayout frameLayout2, @NonNull ImageView imageView, @NonNull AutoLinkTextView autoLinkTextView, @NonNull TextView textView2) {
        this.rootView = frameLayout;
        this.btnSubmitAichangefaceVideo = textView;
        this.flDialogDisable = frameLayout2;
        this.ivClose = imageView;
        this.tvContent = autoLinkTextView;
        this.tvTitle = textView2;
    }

    @NonNull
    public static DialogVideoDisableBinding bind(@NonNull View view) {
        int i2 = R.id.btn_submit_aichangeface_video;
        TextView textView = (TextView) view.findViewById(R.id.btn_submit_aichangeface_video);
        if (textView != null) {
            FrameLayout frameLayout = (FrameLayout) view;
            i2 = R.id.iv_close;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_close);
            if (imageView != null) {
                i2 = R.id.tv_content;
                AutoLinkTextView autoLinkTextView = (AutoLinkTextView) view.findViewById(R.id.tv_content);
                if (autoLinkTextView != null) {
                    i2 = R.id.tv_title;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_title);
                    if (textView2 != null) {
                        return new DialogVideoDisableBinding(frameLayout, textView, frameLayout, imageView, autoLinkTextView, textView2);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogVideoDisableBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogVideoDisableBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_video_disable, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
