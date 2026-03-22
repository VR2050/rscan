package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.Guideline;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogCommon2Binding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton btnCancel;

    @NonNull
    public final GradientRoundCornerButton btnOk;

    @NonNull
    public final ImageView ivClose;

    @NonNull
    public final Guideline midGuideline;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final TextView tvContent;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final View view2;

    private DialogCommon2Binding(@NonNull FrameLayout frameLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull GradientRoundCornerButton gradientRoundCornerButton2, @NonNull ImageView imageView, @NonNull Guideline guideline, @NonNull TextView textView, @NonNull TextView textView2, @NonNull View view) {
        this.rootView = frameLayout;
        this.btnCancel = gradientRoundCornerButton;
        this.btnOk = gradientRoundCornerButton2;
        this.ivClose = imageView;
        this.midGuideline = guideline;
        this.tvContent = textView;
        this.tvTitle = textView2;
        this.view2 = view;
    }

    @NonNull
    public static DialogCommon2Binding bind(@NonNull View view) {
        int i2 = R.id.btn_cancel;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.btn_cancel);
        if (gradientRoundCornerButton != null) {
            i2 = R.id.btn_ok;
            GradientRoundCornerButton gradientRoundCornerButton2 = (GradientRoundCornerButton) view.findViewById(R.id.btn_ok);
            if (gradientRoundCornerButton2 != null) {
                i2 = R.id.iv_close;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_close);
                if (imageView != null) {
                    i2 = R.id.mid_guideline;
                    Guideline guideline = (Guideline) view.findViewById(R.id.mid_guideline);
                    if (guideline != null) {
                        i2 = R.id.tv_content;
                        TextView textView = (TextView) view.findViewById(R.id.tv_content);
                        if (textView != null) {
                            i2 = R.id.tv_title;
                            TextView textView2 = (TextView) view.findViewById(R.id.tv_title);
                            if (textView2 != null) {
                                i2 = R.id.view2;
                                View findViewById = view.findViewById(R.id.view2);
                                if (findViewById != null) {
                                    return new DialogCommon2Binding((FrameLayout) view, gradientRoundCornerButton, gradientRoundCornerButton2, imageView, guideline, textView, textView2, findViewById);
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
    public static DialogCommon2Binding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogCommon2Binding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_common2, viewGroup, false);
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
