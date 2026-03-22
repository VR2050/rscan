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
public final class ItemSignBinding implements ViewBinding {

    @NonNull
    public final ImageView ivSigniconDay;

    @NonNull
    public final ConstraintLayout llSignitemRoot;

    @NonNull
    private final ConstraintLayout rootView;

    @NonNull
    public final TextView tvSignnameDay;

    @NonNull
    public final TextView tvSignnumDay;

    private ItemSignBinding(@NonNull ConstraintLayout constraintLayout, @NonNull ImageView imageView, @NonNull ConstraintLayout constraintLayout2, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = constraintLayout;
        this.ivSigniconDay = imageView;
        this.llSignitemRoot = constraintLayout2;
        this.tvSignnameDay = textView;
        this.tvSignnumDay = textView2;
    }

    @NonNull
    public static ItemSignBinding bind(@NonNull View view) {
        int i2 = R.id.iv_signicon_day;
        ImageView imageView = (ImageView) view.findViewById(R.id.iv_signicon_day);
        if (imageView != null) {
            ConstraintLayout constraintLayout = (ConstraintLayout) view;
            i2 = R.id.tv_signname_day;
            TextView textView = (TextView) view.findViewById(R.id.tv_signname_day);
            if (textView != null) {
                i2 = R.id.tv_signnum_day;
                TextView textView2 = (TextView) view.findViewById(R.id.tv_signnum_day);
                if (textView2 != null) {
                    return new ItemSignBinding(constraintLayout, imageView, constraintLayout, textView, textView2);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemSignBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemSignBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_sign, viewGroup, false);
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
