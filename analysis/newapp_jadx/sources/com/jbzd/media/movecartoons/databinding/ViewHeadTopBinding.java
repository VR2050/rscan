package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ViewHeadTopBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvFavorite;

    @NonNull
    public final ImageTextView itvSignin;

    @NonNull
    public final ImageTextView itvVipBuy;

    @NonNull
    public final FrameLayout llSearchLeft;

    @NonNull
    public final ConstraintLayout llSearchVipSign;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final BLTextView tvSearch;

    private ViewHeadTopBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull FrameLayout frameLayout, @NonNull ConstraintLayout constraintLayout2, @NonNull BLTextView bLTextView) {
        this.rootView = constraintLayout;
        this.itvFavorite = imageTextView;
        this.itvSignin = imageTextView2;
        this.itvVipBuy = imageTextView3;
        this.llSearchLeft = frameLayout;
        this.llSearchVipSign = constraintLayout2;
        this.tvSearch = bLTextView;
    }

    @NonNull
    public static ViewHeadTopBinding bind(@NonNull View view) {
        int i2 = R.id.itv_favorite;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_favorite);
        if (imageTextView != null) {
            i2 = R.id.itv_signin;
            ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_signin);
            if (imageTextView2 != null) {
                i2 = R.id.itv_vip_buy;
                ImageTextView imageTextView3 = (ImageTextView) view.findViewById(R.id.itv_vip_buy);
                if (imageTextView3 != null) {
                    i2 = R.id.ll_search_left;
                    FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.ll_search_left);
                    if (frameLayout != null) {
                        ConstraintLayout constraintLayout = (ConstraintLayout) view;
                        i2 = R.id.tv_search;
                        BLTextView bLTextView = (BLTextView) view.findViewById(R.id.tv_search);
                        if (bLTextView != null) {
                            return new ViewHeadTopBinding(constraintLayout, imageTextView, imageTextView2, imageTextView3, frameLayout, constraintLayout, bLTextView);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ViewHeadTopBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ViewHeadTopBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.view_head_top, viewGroup, false);
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
