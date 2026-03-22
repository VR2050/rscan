package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActivityLocalPlayerBinding implements ViewBinding {

    @NonNull
    public final TextView btnReplay;

    @NonNull
    public final FrameLayout flReplay;

    @NonNull
    public final FullPlayerView fullPlayer;

    @NonNull
    private final FrameLayout rootView;

    private ActivityLocalPlayerBinding(@NonNull FrameLayout frameLayout, @NonNull TextView textView, @NonNull FrameLayout frameLayout2, @NonNull FullPlayerView fullPlayerView) {
        this.rootView = frameLayout;
        this.btnReplay = textView;
        this.flReplay = frameLayout2;
        this.fullPlayer = fullPlayerView;
    }

    @NonNull
    public static ActivityLocalPlayerBinding bind(@NonNull View view) {
        int i2 = R.id.btn_replay;
        TextView textView = (TextView) view.findViewById(R.id.btn_replay);
        if (textView != null) {
            i2 = R.id.fl_replay;
            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.fl_replay);
            if (frameLayout != null) {
                i2 = R.id.full_player;
                FullPlayerView fullPlayerView = (FullPlayerView) view.findViewById(R.id.full_player);
                if (fullPlayerView != null) {
                    return new ActivityLocalPlayerBinding((FrameLayout) view, textView, frameLayout, fullPlayerView);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActivityLocalPlayerBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActivityLocalPlayerBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.activity_local_player, viewGroup, false);
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
