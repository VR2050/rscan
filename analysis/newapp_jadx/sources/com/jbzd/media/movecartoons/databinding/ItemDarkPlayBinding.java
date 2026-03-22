package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemDarkPlayBinding implements ViewBinding {

    @NonNull
    public final ScaleRelativeLayout itemParent;

    @NonNull
    public final ShapeableImageView ivGirl;

    @NonNull
    public final RelativeLayout rlCoverOption;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvAction;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvInfo;

    @NonNull
    public final TextView tvLabel;

    @NonNull
    public final TextView tvTitle;

    private ItemDarkPlayBinding(@NonNull LinearLayout linearLayout, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull ShapeableImageView shapeableImageView, @NonNull RelativeLayout relativeLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5) {
        this.rootView = linearLayout;
        this.itemParent = scaleRelativeLayout;
        this.ivGirl = shapeableImageView;
        this.rlCoverOption = relativeLayout;
        this.tvAction = textView;
        this.tvDesc = textView2;
        this.tvInfo = textView3;
        this.tvLabel = textView4;
        this.tvTitle = textView5;
    }

    @NonNull
    public static ItemDarkPlayBinding bind(@NonNull View view) {
        int i2 = R.id.item_parent;
        ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.item_parent);
        if (scaleRelativeLayout != null) {
            i2 = R.id.iv_girl;
            ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_girl);
            if (shapeableImageView != null) {
                i2 = R.id.rl_coverOption;
                RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_coverOption);
                if (relativeLayout != null) {
                    i2 = R.id.tv_action;
                    TextView textView = (TextView) view.findViewById(R.id.tv_action);
                    if (textView != null) {
                        i2 = R.id.tv_desc;
                        TextView textView2 = (TextView) view.findViewById(R.id.tv_desc);
                        if (textView2 != null) {
                            i2 = R.id.tv_info;
                            TextView textView3 = (TextView) view.findViewById(R.id.tv_info);
                            if (textView3 != null) {
                                i2 = R.id.tv_label;
                                TextView textView4 = (TextView) view.findViewById(R.id.tv_label);
                                if (textView4 != null) {
                                    i2 = R.id.tv_title;
                                    TextView textView5 = (TextView) view.findViewById(R.id.tv_title);
                                    if (textView5 != null) {
                                        return new ItemDarkPlayBinding((LinearLayout) view, scaleRelativeLayout, shapeableImageView, relativeLayout, textView, textView2, textView3, textView4, textView5);
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
    public static ItemDarkPlayBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemDarkPlayBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_dark_play, viewGroup, false);
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
