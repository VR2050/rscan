package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.Toolbar;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.appbar.CollapsingToolbarLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActTopTagDetailBinding implements ViewBinding {

    @NonNull
    public final CollapsingToolbarLayout ctlLayout;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    public final ImageView ivBack;

    @NonNull
    public final ImageView ivBg;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final RecyclerView rvType;

    @NonNull
    public final Toolbar toolbarTitle;

    private ActTopTagDetailBinding(@NonNull ConstraintLayout constraintLayout, @NonNull CollapsingToolbarLayout collapsingToolbarLayout, @NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull RecyclerView recyclerView, @NonNull Toolbar toolbar) {
        this.rootView = constraintLayout;
        this.ctlLayout = collapsingToolbarLayout;
        this.fragContent = frameLayout;
        this.ivBack = imageView;
        this.ivBg = imageView2;
        this.rvType = recyclerView;
        this.toolbarTitle = toolbar;
    }

    @NonNull
    public static ActTopTagDetailBinding bind(@NonNull View view) {
        int i2 = R.id.ctl_layout;
        CollapsingToolbarLayout collapsingToolbarLayout = (CollapsingToolbarLayout) view.findViewById(R.id.ctl_layout);
        if (collapsingToolbarLayout != null) {
            i2 = R.id.frag_content;
            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
            if (frameLayout != null) {
                i2 = R.id.iv_back;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_back);
                if (imageView != null) {
                    i2 = R.id.iv_bg;
                    ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_bg);
                    if (imageView2 != null) {
                        i2 = R.id.rv_type;
                        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_type);
                        if (recyclerView != null) {
                            i2 = R.id.toolbar_title;
                            Toolbar toolbar = (Toolbar) view.findViewById(R.id.toolbar_title);
                            if (toolbar != null) {
                                return new ActTopTagDetailBinding((ConstraintLayout) view, collapsingToolbarLayout, frameLayout, imageView, imageView2, recyclerView, toolbar);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActTopTagDetailBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActTopTagDetailBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_top_tag_detail, viewGroup, false);
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
