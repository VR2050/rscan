package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActPlayListBinding implements ViewBinding {

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    public final ImageView ivBack;

    @NonNull
    public final LinearLayout llFlavorLayout;

    @NonNull
    public final LinearLayout llGroupLayout;

    @NonNull
    public final RelativeLayout llTitle;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final View vFlavorEmpty;

    @NonNull
    public final View vGroupEmpty;

    private ActPlayListBinding(@NonNull RelativeLayout relativeLayout, @NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull RelativeLayout relativeLayout2, @NonNull View view, @NonNull View view2) {
        this.rootView = relativeLayout;
        this.fragContent = frameLayout;
        this.ivBack = imageView;
        this.llFlavorLayout = linearLayout;
        this.llGroupLayout = linearLayout2;
        this.llTitle = relativeLayout2;
        this.vFlavorEmpty = view;
        this.vGroupEmpty = view2;
    }

    @NonNull
    public static ActPlayListBinding bind(@NonNull View view) {
        int i2 = R.id.frag_content;
        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
        if (frameLayout != null) {
            i2 = R.id.iv_back;
            ImageView imageView = (ImageView) view.findViewById(R.id.iv_back);
            if (imageView != null) {
                i2 = R.id.ll_flavorLayout;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_flavorLayout);
                if (linearLayout != null) {
                    i2 = R.id.ll_groupLayout;
                    LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_groupLayout);
                    if (linearLayout2 != null) {
                        i2 = R.id.ll_title;
                        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.ll_title);
                        if (relativeLayout != null) {
                            i2 = R.id.v_flavorEmpty;
                            View findViewById = view.findViewById(R.id.v_flavorEmpty);
                            if (findViewById != null) {
                                i2 = R.id.v_groupEmpty;
                                View findViewById2 = view.findViewById(R.id.v_groupEmpty);
                                if (findViewById2 != null) {
                                    return new ActPlayListBinding((RelativeLayout) view, frameLayout, imageView, linearLayout, linearLayout2, relativeLayout, findViewById, findViewById2);
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
    public static ActPlayListBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActPlayListBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_play_list, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RelativeLayout getRoot() {
        return this.rootView;
    }
}
