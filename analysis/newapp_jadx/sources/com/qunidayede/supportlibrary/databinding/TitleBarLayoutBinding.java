package com.qunidayede.supportlibrary.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.qunidayede.supportlibrary.R$id;
import com.qunidayede.supportlibrary.R$layout;

/* loaded from: classes2.dex */
public final class TitleBarLayoutBinding implements ViewBinding {

    @NonNull
    public final FrameLayout btnTitleBack;

    @NonNull
    public final FrameLayout btnTitleRight;

    @NonNull
    public final FrameLayout btnTitleRightIcon;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final ImageView ivTitleRightIcon;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final View titleDivider;

    @NonNull
    public final ConstraintLayout titleLayout;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final TextView tvTitleNew;

    @NonNull
    public final TextView tvTitleRight;

    private TitleBarLayoutBinding(@NonNull ConstraintLayout constraintLayout, @NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull FrameLayout frameLayout3, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull View view, @NonNull ConstraintLayout constraintLayout2, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3) {
        this.rootView = constraintLayout;
        this.btnTitleBack = frameLayout;
        this.btnTitleRight = frameLayout2;
        this.btnTitleRightIcon = frameLayout3;
        this.ivTitleLeftIcon = imageView;
        this.ivTitleRightIcon = imageView2;
        this.titleDivider = view;
        this.titleLayout = constraintLayout2;
        this.tvTitle = textView;
        this.tvTitleNew = textView2;
        this.tvTitleRight = textView3;
    }

    @NonNull
    public static TitleBarLayoutBinding bind(@NonNull View view) {
        View findViewById;
        int i2 = R$id.btn_titleBack;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(i2);
        if (frameLayout != null) {
            i2 = R$id.btn_titleRight;
            FrameLayout frameLayout2 = (FrameLayout) view.findViewById(i2);
            if (frameLayout2 != null) {
                i2 = R$id.btn_titleRightIcon;
                FrameLayout frameLayout3 = (FrameLayout) view.findViewById(i2);
                if (frameLayout3 != null) {
                    i2 = R$id.iv_titleLeftIcon;
                    ImageView imageView = (ImageView) view.findViewById(i2);
                    if (imageView != null) {
                        i2 = R$id.iv_titleRightIcon;
                        ImageView imageView2 = (ImageView) view.findViewById(i2);
                        if (imageView2 != null && (findViewById = view.findViewById((i2 = R$id.title_divider))) != null) {
                            ConstraintLayout constraintLayout = (ConstraintLayout) view;
                            i2 = R$id.tv_title;
                            TextView textView = (TextView) view.findViewById(i2);
                            if (textView != null) {
                                i2 = R$id.tv_title_new;
                                TextView textView2 = (TextView) view.findViewById(i2);
                                if (textView2 != null) {
                                    i2 = R$id.tv_titleRight;
                                    TextView textView3 = (TextView) view.findViewById(i2);
                                    if (textView3 != null) {
                                        return new TitleBarLayoutBinding(constraintLayout, frameLayout, frameLayout2, frameLayout3, imageView, imageView2, findViewById, constraintLayout, textView, textView2, textView3);
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
    public static TitleBarLayoutBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static TitleBarLayoutBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R$layout.title_bar_layout, viewGroup, false);
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
