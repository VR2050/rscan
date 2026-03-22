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
public final class DialogRefundBinding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton btnSubmitAichangefaceVideo;

    @NonNull
    public final ImageView close;

    @NonNull
    public final TextView itvNickname;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final View view2;

    private DialogRefundBinding(@NonNull FrameLayout frameLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull View view) {
        this.rootView = frameLayout;
        this.btnSubmitAichangefaceVideo = gradientRoundCornerButton;
        this.close = imageView;
        this.itvNickname = textView;
        this.view2 = view;
    }

    @NonNull
    public static DialogRefundBinding bind(@NonNull View view) {
        int i2 = R.id.btn_submit_aichangeface_video;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.btn_submit_aichangeface_video);
        if (gradientRoundCornerButton != null) {
            i2 = R.id.close;
            ImageView imageView = (ImageView) view.findViewById(R.id.close);
            if (imageView != null) {
                i2 = R.id.itv_nickname;
                TextView textView = (TextView) view.findViewById(R.id.itv_nickname);
                if (textView != null) {
                    i2 = R.id.view2;
                    View findViewById = view.findViewById(R.id.view2);
                    if (findViewById != null) {
                        return new DialogRefundBinding((FrameLayout) view, gradientRoundCornerButton, imageView, textView, findViewById);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogRefundBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogRefundBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_refund, viewGroup, false);
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
