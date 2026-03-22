package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActBillBinding implements ViewBinding {

    @NonNull
    public final RelativeLayout btnTitleBack;

    @NonNull
    public final RelativeLayout btnTitleRight;

    @NonNull
    public final RelativeLayout btnTitleRightIcon;

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
    public final RelativeLayout titleLayout;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final TextView tvTitleRight;

    private ActBillBinding(@NonNull LinearLayout linearLayout, @NonNull RelativeLayout relativeLayout, @NonNull RelativeLayout relativeLayout2, @NonNull RelativeLayout relativeLayout3, @NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull View view, @NonNull RelativeLayout relativeLayout4, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.btnTitleBack = relativeLayout;
        this.btnTitleRight = relativeLayout2;
        this.btnTitleRightIcon = relativeLayout3;
        this.fragContent = frameLayout;
        this.ivTitleLeftIcon = imageView;
        this.ivTitleRightIcon = imageView2;
        this.titleDivider = view;
        this.titleLayout = relativeLayout4;
        this.tvTitle = textView;
        this.tvTitleRight = textView2;
    }

    @NonNull
    public static ActBillBinding bind(@NonNull View view) {
        int i2 = R.id.btn_titleBack;
        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.btn_titleBack);
        if (relativeLayout != null) {
            i2 = R.id.btn_titleRight;
            RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.btn_titleRight);
            if (relativeLayout2 != null) {
                i2 = R.id.btn_titleRightIcon;
                RelativeLayout relativeLayout3 = (RelativeLayout) view.findViewById(R.id.btn_titleRightIcon);
                if (relativeLayout3 != null) {
                    i2 = R.id.frag_content;
                    FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
                    if (frameLayout != null) {
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
                                    RelativeLayout relativeLayout4 = (RelativeLayout) view.findViewById(R.id.title_layout);
                                    if (relativeLayout4 != null) {
                                        i2 = R.id.tv_title;
                                        TextView textView = (TextView) view.findViewById(R.id.tv_title);
                                        if (textView != null) {
                                            i2 = R.id.tv_titleRight;
                                            TextView textView2 = (TextView) view.findViewById(R.id.tv_titleRight);
                                            if (textView2 != null) {
                                                return new ActBillBinding((LinearLayout) view, relativeLayout, relativeLayout2, relativeLayout3, frameLayout, imageView, imageView2, findViewById, relativeLayout4, textView, textView2);
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
    public static ActBillBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActBillBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_bill, viewGroup, false);
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
