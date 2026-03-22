package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class FragHomeTabBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final ViewPager vpContent;

    private FragHomeTabBinding(@NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.llTop = linearLayout2;
        this.vpContent = viewPager;
    }

    @NonNull
    public static FragHomeTabBinding bind(@NonNull View view) {
        int i2 = R.id.ll_top;
        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_top);
        if (linearLayout != null) {
            i2 = R.id.vp_content;
            ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
            if (viewPager != null) {
                return new FragHomeTabBinding((LinearLayout) view, linearLayout, viewPager);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static FragHomeTabBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragHomeTabBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_home_tab, viewGroup, false);
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
