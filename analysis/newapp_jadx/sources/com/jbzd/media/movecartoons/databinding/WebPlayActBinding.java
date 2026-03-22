package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageButton;
import android.widget.ProgressBar;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class WebPlayActBinding implements ViewBinding {

    @NonNull
    public final ImageButton btnBack;

    @NonNull
    public final FrameLayout flVideoContainer;

    @NonNull
    public final ProgressBar progressBar2;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final FrameLayout webContainer;

    private WebPlayActBinding(@NonNull FrameLayout frameLayout, @NonNull ImageButton imageButton, @NonNull FrameLayout frameLayout2, @NonNull ProgressBar progressBar, @NonNull FrameLayout frameLayout3) {
        this.rootView = frameLayout;
        this.btnBack = imageButton;
        this.flVideoContainer = frameLayout2;
        this.progressBar2 = progressBar;
        this.webContainer = frameLayout3;
    }

    @NonNull
    public static WebPlayActBinding bind(@NonNull View view) {
        int i2 = R.id.btn_back;
        ImageButton imageButton = (ImageButton) view.findViewById(R.id.btn_back);
        if (imageButton != null) {
            i2 = R.id.flVideoContainer;
            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.flVideoContainer);
            if (frameLayout != null) {
                i2 = R.id.progressBar2;
                ProgressBar progressBar = (ProgressBar) view.findViewById(R.id.progressBar2);
                if (progressBar != null) {
                    i2 = R.id.web_container;
                    FrameLayout frameLayout2 = (FrameLayout) view.findViewById(R.id.web_container);
                    if (frameLayout2 != null) {
                        return new WebPlayActBinding((FrameLayout) view, imageButton, frameLayout, progressBar, frameLayout2);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static WebPlayActBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static WebPlayActBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.web_play_act, viewGroup, false);
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
