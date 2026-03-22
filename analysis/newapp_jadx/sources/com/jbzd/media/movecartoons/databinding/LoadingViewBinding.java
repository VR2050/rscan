package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class LoadingViewBinding implements ViewBinding {

    @NonNull
    public final ProgressBar progressBar;

    @NonNull
    private final LinearLayout rootView;

    private LoadingViewBinding(@NonNull LinearLayout linearLayout, @NonNull ProgressBar progressBar) {
        this.rootView = linearLayout;
        this.progressBar = progressBar;
    }

    @NonNull
    public static LoadingViewBinding bind(@NonNull View view) {
        ProgressBar progressBar = (ProgressBar) view.findViewById(R.id.progressBar);
        if (progressBar != null) {
            return new LoadingViewBinding((LinearLayout) view, progressBar);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.progressBar)));
    }

    @NonNull
    public static LoadingViewBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static LoadingViewBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.loading_view, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public LinearLayout getRoot() {
        return this.rootView;
    }
}
