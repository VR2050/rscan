package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.image.ScaleImageView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ItemSchoolBinding implements ViewBinding {

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final ScaleImageView sivImg;

    private ItemSchoolBinding(@NonNull LinearLayout linearLayout, @NonNull ScaleImageView scaleImageView) {
        this.rootView = linearLayout;
        this.sivImg = scaleImageView;
    }

    @NonNull
    public static ItemSchoolBinding bind(@NonNull View view) {
        ScaleImageView scaleImageView = (ScaleImageView) view.findViewById(R.id.siv_img);
        if (scaleImageView != null) {
            return new ItemSchoolBinding((LinearLayout) view, scaleImageView);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.siv_img)));
    }

    @NonNull
    public static ItemSchoolBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ItemSchoolBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.item_school, viewGroup, false);
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
