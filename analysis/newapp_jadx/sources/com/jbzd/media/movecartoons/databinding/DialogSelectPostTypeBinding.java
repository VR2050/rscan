package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogSelectPostTypeBinding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton image;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final GradientRoundCornerButton video;

    private DialogSelectPostTypeBinding(@NonNull FrameLayout frameLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull GradientRoundCornerButton gradientRoundCornerButton2) {
        this.rootView = frameLayout;
        this.image = gradientRoundCornerButton;
        this.video = gradientRoundCornerButton2;
    }

    @NonNull
    public static DialogSelectPostTypeBinding bind(@NonNull View view) {
        int i2 = R.id.image;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.image);
        if (gradientRoundCornerButton != null) {
            i2 = R.id.video;
            GradientRoundCornerButton gradientRoundCornerButton2 = (GradientRoundCornerButton) view.findViewById(R.id.video);
            if (gradientRoundCornerButton2 != null) {
                return new DialogSelectPostTypeBinding((FrameLayout) view, gradientRoundCornerButton, gradientRoundCornerButton2);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogSelectPostTypeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogSelectPostTypeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_select_post_type, viewGroup, false);
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
