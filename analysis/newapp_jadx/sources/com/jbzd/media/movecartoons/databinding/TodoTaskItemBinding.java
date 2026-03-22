package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class TodoTaskItemBinding implements ViewBinding {

    @NonNull
    public final ShapeableImageView ivTaskIcon;

    @NonNull
    public final ConstraintLayout layoutTaskEveryDay;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final BLTextView tvTaskActionState;

    @NonNull
    public final TextView tvTaskTitle;

    @NonNull
    public final TextView tvTaskTitleHint;

    private TodoTaskItemBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull ConstraintLayout constraintLayout2, @NonNull BLTextView bLTextView, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = constraintLayout;
        this.ivTaskIcon = shapeableImageView;
        this.layoutTaskEveryDay = constraintLayout2;
        this.tvTaskActionState = bLTextView;
        this.tvTaskTitle = textView;
        this.tvTaskTitleHint = textView2;
    }

    @NonNull
    public static TodoTaskItemBinding bind(@NonNull View view) {
        int i2 = R.id.iv_task_icon;
        ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_task_icon);
        if (shapeableImageView != null) {
            ConstraintLayout constraintLayout = (ConstraintLayout) view;
            i2 = R.id.tv_task_action_state;
            BLTextView bLTextView = (BLTextView) view.findViewById(R.id.tv_task_action_state);
            if (bLTextView != null) {
                i2 = R.id.tv_task_title;
                TextView textView = (TextView) view.findViewById(R.id.tv_task_title);
                if (textView != null) {
                    i2 = R.id.tv_task_title_hint;
                    TextView textView2 = (TextView) view.findViewById(R.id.tv_task_title_hint);
                    if (textView2 != null) {
                        return new TodoTaskItemBinding(constraintLayout, shapeableImageView, constraintLayout, bLTextView, textView, textView2);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static TodoTaskItemBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static TodoTaskItemBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.todo_task_item, viewGroup, false);
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
