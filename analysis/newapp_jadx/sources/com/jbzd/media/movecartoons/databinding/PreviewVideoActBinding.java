package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class PreviewVideoActBinding implements ViewBinding {

    @NonNull
    public final FullPlayerView fullPlayer;

    @NonNull
    private final FrameLayout rootView;

    private PreviewVideoActBinding(@NonNull FrameLayout frameLayout, @NonNull FullPlayerView fullPlayerView) {
        this.rootView = frameLayout;
        this.fullPlayer = fullPlayerView;
    }

    @NonNull
    public static PreviewVideoActBinding bind(@NonNull View view) {
        FullPlayerView fullPlayerView = (FullPlayerView) view.findViewById(R.id.full_player);
        if (fullPlayerView != null) {
            return new PreviewVideoActBinding((FrameLayout) view, fullPlayerView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.full_player)));
    }

    @NonNull
    public static PreviewVideoActBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static PreviewVideoActBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.preview_video_act, viewGroup, false);
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
