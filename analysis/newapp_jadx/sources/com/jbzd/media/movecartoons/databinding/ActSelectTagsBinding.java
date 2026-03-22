package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActSelectTagsBinding implements ViewBinding {

    @NonNull
    public final FrameLayout btnTitleBack;

    @NonNull
    public final FrameLayout btnTitleRight;

    @NonNull
    public final FrameLayout btnTitleRightIcon;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final ImageView ivTitleRightIcon;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final View titleDivider;

    @NonNull
    public final ConstraintLayout titleLayout;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final TextView tvTitleRight;

    private ActSelectTagsBinding(@NonNull LinearLayout linearLayout, @NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull FrameLayout frameLayout3, @NonNull FrameLayout frameLayout4, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull View view, @NonNull ConstraintLayout constraintLayout, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.btnTitleBack = frameLayout;
        this.btnTitleRight = frameLayout2;
        this.btnTitleRightIcon = frameLayout3;
        this.fragContent = frameLayout4;
        this.ivTitleLeftIcon = imageView;
        this.ivTitleRightIcon = imageView2;
        this.titleDivider = view;
        this.titleLayout = constraintLayout;
        this.tvTitle = textView;
        this.tvTitleRight = textView2;
    }

    @NonNull
    public static ActSelectTagsBinding bind(@NonNull View view) {
        int i2 = R.id.btn_titleBack;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.btn_titleBack);
        if (frameLayout != null) {
            i2 = R.id.btn_titleRight;
            FrameLayout frameLayout2 = (FrameLayout) view.findViewById(R.id.btn_titleRight);
            if (frameLayout2 != null) {
                i2 = R.id.btn_titleRightIcon;
                FrameLayout frameLayout3 = (FrameLayout) view.findViewById(R.id.btn_titleRightIcon);
                if (frameLayout3 != null) {
                    i2 = R.id.frag_content;
                    FrameLayout frameLayout4 = (FrameLayout) view.findViewById(R.id.frag_content);
                    if (frameLayout4 != null) {
                        i2 = R.id.iv_titleLeftIcon;
                        ImageView imageView = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
                        if (imageView != null) {
                            i2 = R.id.iv_titleRightIcon;
                            ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_titleRightIcon);
                            if (imageView2 != null) {
                                i2 = R.id.title_divider;
                                View findViewById = view.findViewById(R.id.title_divider);
                                if (findViewById != null) {
                                    i2 = R.id.title_layout;
                                    ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.title_layout);
                                    if (constraintLayout != null) {
                                        i2 = R.id.tv_title;
                                        TextView textView = (TextView) view.findViewById(R.id.tv_title);
                                        if (textView != null) {
                                            i2 = R.id.tv_titleRight;
                                            TextView textView2 = (TextView) view.findViewById(R.id.tv_titleRight);
                                            if (textView2 != null) {
                                                return new ActSelectTagsBinding((LinearLayout) view, frameLayout, frameLayout2, frameLayout3, frameLayout4, imageView, imageView2, findViewById, constraintLayout, textView, textView2);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActSelectTagsBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActSelectTagsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_select_tags, viewGroup, false);
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
