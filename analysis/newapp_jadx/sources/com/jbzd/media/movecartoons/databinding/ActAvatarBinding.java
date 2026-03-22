package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.AppCompatButton;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Guideline;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActAvatarBinding implements ViewBinding {

    @NonNull
    public final LinearLayout bottomBtn;

    @NonNull
    public final AppCompatButton btnSubmit;

    @NonNull
    public final ShapeableImageView civHead;

    @NonNull
    public final Guideline guideLine;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final RecyclerView rvContent;

    private ActAvatarBinding(@NonNull ConstraintLayout constraintLayout, @NonNull LinearLayout linearLayout, @NonNull AppCompatButton appCompatButton, @NonNull ShapeableImageView shapeableImageView, @NonNull Guideline guideline, @NonNull RecyclerView recyclerView) {
        this.rootView = constraintLayout;
        this.bottomBtn = linearLayout;
        this.btnSubmit = appCompatButton;
        this.civHead = shapeableImageView;
        this.guideLine = guideline;
        this.rvContent = recyclerView;
    }

    @NonNull
    public static ActAvatarBinding bind(@NonNull View view) {
        int i2 = R.id.bottom_btn;
        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.bottom_btn);
        if (linearLayout != null) {
            i2 = R.id.btn_submit;
            AppCompatButton appCompatButton = (AppCompatButton) view.findViewById(R.id.btn_submit);
            if (appCompatButton != null) {
                i2 = R.id.civ_head;
                ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.civ_head);
                if (shapeableImageView != null) {
                    i2 = R.id.guideLine;
                    Guideline guideline = (Guideline) view.findViewById(R.id.guideLine);
                    if (guideline != null) {
                        i2 = R.id.rv_content;
                        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_content);
                        if (recyclerView != null) {
                            return new ActAvatarBinding((ConstraintLayout) view, linearLayout, appCompatButton, shapeableImageView, guideline, recyclerView);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActAvatarBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActAvatarBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_avatar, viewGroup, false);
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
