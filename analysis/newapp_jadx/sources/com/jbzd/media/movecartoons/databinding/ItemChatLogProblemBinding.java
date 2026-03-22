package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemChatLogProblemBinding implements ViewBinding {

    @NonNull
    public final ShapeableImageView ivPortrait;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final RecyclerView rvProblems;

    @NonNull
    public final TextView tvTime;

    @NonNull
    public final TextView tvWelcome;

    private ItemChatLogProblemBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull RecyclerView recyclerView, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = constraintLayout;
        this.ivPortrait = shapeableImageView;
        this.rvProblems = recyclerView;
        this.tvTime = textView;
        this.tvWelcome = textView2;
    }

    @NonNull
    public static ItemChatLogProblemBinding bind(@NonNull View view) {
        int i2 = R.id.iv_portrait;
        ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_portrait);
        if (shapeableImageView != null) {
            i2 = R.id.rv_problems;
            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_problems);
            if (recyclerView != null) {
                i2 = R.id.tv_time;
                TextView textView = (TextView) view.findViewById(R.id.tv_time);
                if (textView != null) {
                    i2 = R.id.tv_welcome;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_welcome);
                    if (textView2 != null) {
                        return new ItemChatLogProblemBinding((ConstraintLayout) view, shapeableImageView, recyclerView, textView, textView2);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemChatLogProblemBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemChatLogProblemBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_chat_log_problem, viewGroup, false);
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
