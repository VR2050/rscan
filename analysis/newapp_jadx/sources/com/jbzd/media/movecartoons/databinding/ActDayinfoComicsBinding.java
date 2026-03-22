package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActDayinfoComicsBinding implements ViewBinding {

    @NonNull
    public final LinearLayout lLayoutBg;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SlidingTabLayout tabComicsDayinfo;

    @NonNull
    public final ViewPager vpComicsDayinfo;

    private ActDayinfoComicsBinding(@NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull SlidingTabLayout slidingTabLayout, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.lLayoutBg = linearLayout2;
        this.tabComicsDayinfo = slidingTabLayout;
        this.vpComicsDayinfo = viewPager;
    }

    @NonNull
    public static ActDayinfoComicsBinding bind(@NonNull View view) {
        LinearLayout linearLayout = (LinearLayout) view;
        int i2 = R.id.tab_comics_dayinfo;
        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tab_comics_dayinfo);
        if (slidingTabLayout != null) {
            i2 = R.id.vp_comics_dayinfo;
            ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_comics_dayinfo);
            if (viewPager != null) {
                return new ActDayinfoComicsBinding((LinearLayout) view, linearLayout, slidingTabLayout, viewPager);
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActDayinfoComicsBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActDayinfoComicsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_dayinfo_comics, viewGroup, false);
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
