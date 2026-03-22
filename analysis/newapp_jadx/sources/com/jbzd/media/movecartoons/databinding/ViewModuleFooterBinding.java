package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.cardview.widget.CardView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.ProgressChangeButton;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ViewModuleFooterBinding implements ViewBinding {

    @NonNull
    public final ImageTextView itvFooterMore;

    @NonNull
    public final CardView llFooterChange;

    @NonNull
    public final LinearLayout llFooterMore;

    @NonNull
    public final LinearLayout llModuleFooter;

    @NonNull
    public final ProgressChangeButton pcbChange;

    @NonNull
    private final LinearLayout rootView;

    private ViewModuleFooterBinding(@NonNull LinearLayout linearLayout, @NonNull ImageTextView imageTextView, @NonNull CardView cardView, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull ProgressChangeButton progressChangeButton) {
        this.rootView = linearLayout;
        this.itvFooterMore = imageTextView;
        this.llFooterChange = cardView;
        this.llFooterMore = linearLayout2;
        this.llModuleFooter = linearLayout3;
        this.pcbChange = progressChangeButton;
    }

    @NonNull
    public static ViewModuleFooterBinding bind(@NonNull View view) {
        int i2 = R.id.itv_footer_more;
        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_footer_more);
        if (imageTextView != null) {
            i2 = R.id.ll_footer_change;
            CardView cardView = (CardView) view.findViewById(R.id.ll_footer_change);
            if (cardView != null) {
                i2 = R.id.ll_footer_more;
                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_footer_more);
                if (linearLayout != null) {
                    LinearLayout linearLayout2 = (LinearLayout) view;
                    i2 = R.id.pcb_change;
                    ProgressChangeButton progressChangeButton = (ProgressChangeButton) view.findViewById(R.id.pcb_change);
                    if (progressChangeButton != null) {
                        return new ViewModuleFooterBinding(linearLayout2, imageTextView, cardView, linearLayout, linearLayout2, progressChangeButton);
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ViewModuleFooterBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ViewModuleFooterBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.view_module_footer, viewGroup, false);
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
