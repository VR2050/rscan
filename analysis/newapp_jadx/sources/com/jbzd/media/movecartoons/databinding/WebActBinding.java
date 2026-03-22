package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ProgressBar;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class WebActBinding implements ViewBinding {

    @NonNull
    public final ProgressBar progressBar2;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final FrameLayout webContainer;

    private WebActBinding(@NonNull FrameLayout frameLayout, @NonNull ProgressBar progressBar, @NonNull FrameLayout frameLayout2) {
        this.rootView = frameLayout;
        this.progressBar2 = progressBar;
        this.webContainer = frameLayout2;
    }

    @NonNull
    public static WebActBinding bind(@NonNull View view) {
        ProgressBar progressBar = (ProgressBar) view.findViewById(R.id.progressBar2);
        if (progressBar == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.progressBar2)));
        }
        FrameLayout frameLayout = (FrameLayout) view;
        return new WebActBinding(frameLayout, progressBar, frameLayout);
    }

    @NonNull
    public static WebActBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static WebActBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.web_act, viewGroup, false);
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
