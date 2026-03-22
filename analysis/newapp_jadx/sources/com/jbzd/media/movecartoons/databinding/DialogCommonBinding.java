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
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogCommonBinding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton btnSubmitAichangefaceVideo;

    @NonNull
    public final ImageView ivClose;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvContent;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final View view2;

    private DialogCommonBinding(@NonNull FrameLayout frameLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull TextView textView2, @NonNull View view) {
        this.rootView = frameLayout;
        this.btnSubmitAichangefaceVideo = gradientRoundCornerButton;
        this.ivClose = imageView;
        this.tvContent = textView;
        this.tvTitle = textView2;
        this.view2 = view;
    }

    @NonNull
    public static DialogCommonBinding bind(@NonNull View view) {
        int i2 = R.id.btn_submit_aichangeface_video;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.btn_submit_aichangeface_video);
        if (gradientRoundCornerButton != null) {
            i2 = R.id.iv_close;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_close);
            if (imageView != null) {
                i2 = R.id.tv_content;
                TextView textView = (TextView) view.findViewById(R.id.tv_content);
                if (textView != null) {
                    i2 = R.id.tv_title;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_title);
                    if (textView2 != null) {
                        i2 = R.id.view2;
                        View findViewById = view.findViewById(R.id.view2);
                        if (findViewById != null) {
                            return new DialogCommonBinding((FrameLayout) view, gradientRoundCornerButton, imageView, textView, textView2, findViewById);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogCommonBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogCommonBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_common, viewGroup, false);
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
