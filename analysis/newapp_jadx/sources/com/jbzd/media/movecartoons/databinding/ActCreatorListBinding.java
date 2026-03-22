package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActCreatorListBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    public final RelativeLayout rlBack;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SlidingTabLayout tabLayout;

    @NonNull
    public final ViewPager vpContent;

    private ActCreatorListBinding(@NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull RelativeLayout relativeLayout, @NonNull SlidingTabLayout slidingTabLayout, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.llTop = linearLayout2;
        this.rlBack = relativeLayout;
        this.tabLayout = slidingTabLayout;
        this.vpContent = viewPager;
    }

    @NonNull
    public static ActCreatorListBinding bind(@NonNull View view) {
        LinearLayout linearLayout = (LinearLayout) view;
        int i2 = R.id.rl_back;
        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_back);
        if (relativeLayout != null) {
            i2 = R.id.tabLayout;
            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tabLayout);
            if (slidingTabLayout != null) {
                i2 = R.id.vp_content;
                ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
                if (viewPager != null) {
                    return new ActCreatorListBinding((LinearLayout) view, linearLayout, relativeLayout, slidingTabLayout, viewPager);
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActCreatorListBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActCreatorListBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_creator_list, viewGroup, false);
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
