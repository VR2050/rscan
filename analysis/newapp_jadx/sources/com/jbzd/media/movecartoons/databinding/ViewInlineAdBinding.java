package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.noober.background.view.BLTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class ViewInlineAdBinding implements ViewBinding {

    @NonNull
    public final Banner banner;

    @NonNull
    public final View bottomMask;

    @NonNull
    public final BLTextView btnVip;

    @NonNull
    public final CardView card;

    @NonNull
    public final ConstraintLayout root;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final View touchBlocker;

    @NonNull
    public final BLTextView tvCountdown;

    private ViewInlineAdBinding(@NonNull ConstraintLayout constraintLayout, @NonNull Banner banner, @NonNull View view, @NonNull BLTextView bLTextView, @NonNull CardView cardView, @NonNull ConstraintLayout constraintLayout2, @NonNull View view2, @NonNull BLTextView bLTextView2) {
        this.rootView = constraintLayout;
        this.banner = banner;
        this.bottomMask = view;
        this.btnVip = bLTextView;
        this.card = cardView;
        this.root = constraintLayout2;
        this.touchBlocker = view2;
        this.tvCountdown = bLTextView2;
    }

    @NonNull
    public static ViewInlineAdBinding bind(@NonNull View view) {
        int i2 = R.id.banner;
        Banner banner = (Banner) view.findViewById(R.id.banner);
        if (banner != null) {
            i2 = R.id.bottomMask;
            View findViewById = view.findViewById(R.id.bottomMask);
            if (findViewById != null) {
                i2 = R.id.btnVip;
                BLTextView bLTextView = (BLTextView) view.findViewById(R.id.btnVip);
                if (bLTextView != null) {
                    i2 = R.id.card;
                    CardView cardView = (CardView) view.findViewById(R.id.card);
                    if (cardView != null) {
                        ConstraintLayout constraintLayout = (ConstraintLayout) view;
                        i2 = R.id.touchBlocker;
                        View findViewById2 = view.findViewById(R.id.touchBlocker);
                        if (findViewById2 != null) {
                            i2 = R.id.tvCountdown;
                            BLTextView bLTextView2 = (BLTextView) view.findViewById(R.id.tvCountdown);
                            if (bLTextView2 != null) {
                                return new ViewInlineAdBinding(constraintLayout, banner, findViewById, bLTextView, cardView, constraintLayout, findViewById2, bLTextView2);
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ViewInlineAdBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ViewInlineAdBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.view_inline_ad, viewGroup, false);
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
