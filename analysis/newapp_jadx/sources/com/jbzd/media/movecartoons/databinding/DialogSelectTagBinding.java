package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.GradientRoundCornerButton;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class DialogSelectTagBinding implements ViewBinding {

    @NonNull
    public final GradientRoundCornerButton btnSave;

    @NonNull
    public final View outsideView;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvContent;

    @NonNull
    public final TextView tvTitle;

    private DialogSelectTagBinding(@NonNull LinearLayout linearLayout, @NonNull GradientRoundCornerButton gradientRoundCornerButton, @NonNull View view, @NonNull RecyclerView recyclerView, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.btnSave = gradientRoundCornerButton;
        this.outsideView = view;
        this.rvContent = recyclerView;
        this.tvTitle = textView;
    }

    @NonNull
    public static DialogSelectTagBinding bind(@NonNull View view) {
        int i2 = R.id.btnSave;
        GradientRoundCornerButton gradientRoundCornerButton = (GradientRoundCornerButton) view.findViewById(R.id.btnSave);
        if (gradientRoundCornerButton != null) {
            i2 = R.id.outside_view;
            View findViewById = view.findViewById(R.id.outside_view);
            if (findViewById != null) {
                i2 = R.id.rv_content;
                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_content);
                if (recyclerView != null) {
                    i2 = R.id.tvTitle;
                    TextView textView = (TextView) view.findViewById(R.id.tvTitle);
                    if (textView != null) {
                        return new DialogSelectTagBinding((LinearLayout) view, gradientRoundCornerButton, findViewById, recyclerView, textView);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static DialogSelectTagBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static DialogSelectTagBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.dialog_select_tag, viewGroup, false);
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
