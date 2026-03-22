package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class FragVipCardBinding implements ViewBinding {

    @NonNull
    public final Banner banner;

    @NonNull
    private final ConstraintLayout rootView;

    private FragVipCardBinding(@NonNull ConstraintLayout constraintLayout, @NonNull Banner banner) {
        this.rootView = constraintLayout;
        this.banner = banner;
    }

    @NonNull
    public static FragVipCardBinding bind(@NonNull View view) {
        Banner banner = (Banner) view.findViewById(R.id.banner);
        if (banner != null) {
            return new FragVipCardBinding((ConstraintLayout) view, banner);
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(R.id.banner)));
    }

    @NonNull
    public static FragVipCardBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragVipCardBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_vip_card, viewGroup, false);
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
