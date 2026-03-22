package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogPostReportBinding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton close;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final RecyclerView rvContent;

    @NonNull
    public final GradientRoundCornerButton vip;

    private DialogPostReportBinding(@NonNull FrameLayout frameLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull RecyclerView recyclerView, @NonNull GradientRoundCornerButton gradientRoundCornerButton2) {
        this.rootView = frameLayout;
        this.close = gradientRoundCornerButton;
        this.rvContent = recyclerView;
        this.vip = gradientRoundCornerButton2;
    }

    @NonNull
    public static DialogPostReportBinding bind(@NonNull View view) {
        int i2 = R.id.close;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.close);
        if (gradientRoundCornerButton != null) {
            i2 = R.id.rv_content;
            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_content);
            if (recyclerView != null) {
                i2 = R.id.vip;
                GradientRoundCornerButton gradientRoundCornerButton2 = (GradientRoundCornerButton) view.findViewById(R.id.vip);
                if (gradientRoundCornerButton2 != null) {
                    return new DialogPostReportBinding((FrameLayout) view, gradientRoundCornerButton, recyclerView, gradientRoundCornerButton2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogPostReportBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogPostReportBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_post_report, viewGroup, false);
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
