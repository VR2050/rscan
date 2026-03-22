package com.qunidayede.supportlibrary.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qunidayede.supportlibrary.R$id;
import com.qunidayede.supportlibrary.R$layout;
import com.qunidayede.supportlibrary.widget.LoadingView;

/* loaded from: classes2.dex */
public final class LayoutLoadingBinding implements ViewBinding {

    @NonNull
    public final FrameLayout loadingFrame;

    @NonNull
    public final LoadingView loadingView;

    @NonNull
    private final FrameLayout rootView;

    private LayoutLoadingBinding(@NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull LoadingView loadingView) {
        this.rootView = frameLayout;
        this.loadingFrame = frameLayout2;
        this.loadingView = loadingView;
    }

    @NonNull
    public static LayoutLoadingBinding bind(@NonNull View view) {
        FrameLayout frameLayout = (FrameLayout) view;
        int i2 = R$id.loading_view;
        LoadingView loadingView = (LoadingView) view.findViewById(i2);
        if (loadingView != null) {
            return new LayoutLoadingBinding((FrameLayout) view, frameLayout, loadingView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static LayoutLoadingBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LayoutLoadingBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R$layout.layout_loading, viewGroup, false);
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
