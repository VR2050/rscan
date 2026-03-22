package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.github.mmin18.widget.RealtimeBlurView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ViewRestrictedBinding implements ViewBinding {

    @NonNull
    public final RealtimeBlurView blurView;

    @NonNull
    public final ConstraintLayout clBlur;

    @NonNull
    public final ImageTextView itvBlur;

    @NonNull
    private final ConstraintLayout rootView;

    private ViewRestrictedBinding(@NonNull ConstraintLayout constraintLayout, @NonNull RealtimeBlurView realtimeBlurView, @NonNull ConstraintLayout constraintLayout2, @NonNull ImageTextView imageTextView) {
        this.rootView = constraintLayout;
        this.blurView = realtimeBlurView;
        this.clBlur = constraintLayout2;
        this.itvBlur = imageTextView;
    }

    @NonNull
    public static ViewRestrictedBinding bind(@NonNull View view) {
        int i2 = R.id.blur_view;
        RealtimeBlurView realtimeBlurView = (RealtimeBlurView) view.findViewById(R.id.blur_view);
        if (realtimeBlurView != null) {
            ConstraintLayout constraintLayout = (ConstraintLayout) view;
            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_blur);
            if (imageTextView != null) {
                return new ViewRestrictedBinding(constraintLayout, realtimeBlurView, constraintLayout, imageTextView);
            }
            i2 = R.id.itv_blur;
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ViewRestrictedBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ViewRestrictedBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.view_restricted, viewGroup, false);
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
