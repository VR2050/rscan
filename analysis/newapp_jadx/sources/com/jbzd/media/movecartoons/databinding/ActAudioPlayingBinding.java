package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;

/* loaded from: classes2.dex */
public final class ActAudioPlayingBinding implements ViewBinding {

    @NonNull
    private final ConstraintLayout rootView;

    private ActAudioPlayingBinding(@NonNull ConstraintLayout constraintLayout) {
        this.rootView = constraintLayout;
    }

    @NonNull
    public static ActAudioPlayingBinding bind(@NonNull View view) {
        Objects.requireNonNull(view, "rootView");
        return new ActAudioPlayingBinding((ConstraintLayout) view);
    }

    @NonNull
    public static ActAudioPlayingBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActAudioPlayingBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_audio_playing, viewGroup, false);
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
