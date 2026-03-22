package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemHomeFlavorHorBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llParent;

    @NonNull
    public final LinearLayout llUnderLinear;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final TextView tvName;

    private ItemHomeFlavorHorBinding(@NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.llParent = linearLayout2;
        this.llUnderLinear = linearLayout3;
        this.tvName = textView;
    }

    @NonNull
    public static ItemHomeFlavorHorBinding bind(@NonNull View view) {
        LinearLayout linearLayout = (LinearLayout) view;
        int i2 = R.id.ll_underLinear;
        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_underLinear);
        if (linearLayout2 != null) {
            i2 = R.id.tv_name;
            TextView textView = (TextView) view.findViewById(R.id.tv_name);
            if (textView != null) {
                return new ItemHomeFlavorHorBinding((LinearLayout) view, linearLayout, linearLayout2, textView);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ItemHomeFlavorHorBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemHomeFlavorHorBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_home_flavor_hor, viewGroup, false);
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
