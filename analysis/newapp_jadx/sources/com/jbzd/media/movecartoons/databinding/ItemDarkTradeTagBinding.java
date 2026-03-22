package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemDarkTradeTagBinding implements ViewBinding {

    @NonNull
    public final ImageView ivArrowDown;

    @NonNull
    public final TextView ivCenterPlayicon;

    @NonNull
    public final ImageView ivImg;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final ConstraintLayout rvTagLayout;

    @NonNull
    public final View view;

    @NonNull
    public final View viewUp;

    private ItemDarkTradeTagBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ImageView imageView, @NonNull TextView textView, @NonNull ImageView imageView2, @NonNull ConstraintLayout constraintLayout2, @NonNull View view, @NonNull View view2) {
        this.rootView = constraintLayout;
        this.ivArrowDown = imageView;
        this.ivCenterPlayicon = textView;
        this.ivImg = imageView2;
        this.rvTagLayout = constraintLayout2;
        this.view = view;
        this.viewUp = view2;
    }

    @NonNull
    public static ItemDarkTradeTagBinding bind(@NonNull View view) {
        int i2 = R.id.iv_arrow_down;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_arrow_down);
        if (imageView != null) {
            i2 = R.id.iv_center_playicon;
            TextView textView = (TextView) view.findViewById(R.id.iv_center_playicon);
            if (textView != null) {
                i2 = R.id.ivImg;
                ImageView imageView2 = (ImageView) view.findViewById(R.id.ivImg);
                if (imageView2 != null) {
                    ConstraintLayout constraintLayout = (ConstraintLayout) view;
                    i2 = R.id.view;
                    View findViewById = view.findViewById(R.id.view);
                    if (findViewById != null) {
                        i2 = R.id.view_up;
                        View findViewById2 = view.findViewById(R.id.view_up);
                        if (findViewById2 != null) {
                            return new ItemDarkTradeTagBinding(constraintLayout, imageView, textView, imageView2, constraintLayout, findViewById, findViewById2);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemDarkTradeTagBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemDarkTradeTagBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_dark_trade_tag, viewGroup, false);
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
