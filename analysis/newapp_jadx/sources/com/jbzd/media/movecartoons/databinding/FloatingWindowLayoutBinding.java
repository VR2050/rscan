package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.mikhaellopez.circularprogressbar.CircularProgressBar;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FloatingWindowLayoutBinding implements ViewBinding {

    @NonNull
    public final CircleImageView circleIvMusicCover;

    @NonNull
    public final FrameLayout frameLayout;

    @NonNull
    public final ImageView ivCoseButton;

    @NonNull
    public final ImageView ivPauseButton;

    @NonNull
    public final CircularProgressBar progressCircular;

    @NonNull
    private final ConstraintLayout rootView;

    private FloatingWindowLayoutBinding(@NonNull ConstraintLayout constraintLayout, @NonNull CircleImageView circleImageView, @NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull CircularProgressBar circularProgressBar) {
        this.rootView = constraintLayout;
        this.circleIvMusicCover = circleImageView;
        this.frameLayout = frameLayout;
        this.ivCoseButton = imageView;
        this.ivPauseButton = imageView2;
        this.progressCircular = circularProgressBar;
    }

    @NonNull
    public static FloatingWindowLayoutBinding bind(@NonNull View view) {
        int i2 = R.id.circle_iv_music_cover;
        CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.circle_iv_music_cover);
        if (circleImageView != null) {
            i2 = R.id.frame_layout;
            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frame_layout);
            if (frameLayout != null) {
                i2 = R.id.iv_cose_button;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_cose_button);
                if (imageView != null) {
                    i2 = R.id.iv_pause_button;
                    ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_pause_button);
                    if (imageView2 != null) {
                        i2 = R.id.progress_circular;
                        CircularProgressBar circularProgressBar = (CircularProgressBar) view.findViewById(R.id.progress_circular);
                        if (circularProgressBar != null) {
                            return new FloatingWindowLayoutBinding((ConstraintLayout) view, circleImageView, frameLayout, imageView, imageView2, circularProgressBar);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FloatingWindowLayoutBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FloatingWindowLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.floating_window_layout, viewGroup, false);
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
