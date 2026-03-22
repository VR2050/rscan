package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActAichangefaceBinding implements ViewBinding {

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    public final RelativeLayout rlGoBack;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SlidingTabLayout tabLayout;

    @NonNull
    public final TextView tvRightTitle;

    @NonNull
    public final ViewPager vpContent;

    private ActAichangefaceBinding(@NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull RelativeLayout relativeLayout, @NonNull SlidingTabLayout slidingTabLayout, @NonNull TextView textView, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.llTop = linearLayout2;
        this.rlGoBack = relativeLayout;
        this.tabLayout = slidingTabLayout;
        this.tvRightTitle = textView;
        this.vpContent = viewPager;
    }

    @NonNull
    public static ActAichangefaceBinding bind(@NonNull View view) {
        int i2 = R.id.ll_top;
        LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_top);
        if (linearLayout != null) {
            i2 = R.id.rl_goBack;
            RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_goBack);
            if (relativeLayout != null) {
                i2 = R.id.tabLayout;
                SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tabLayout);
                if (slidingTabLayout != null) {
                    i2 = R.id.tv_right_title;
                    TextView textView = (TextView) view.findViewById(R.id.tv_right_title);
                    if (textView != null) {
                        i2 = R.id.vp_content;
                        ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
                        if (viewPager != null) {
                            return new ActAichangefaceBinding((LinearLayout) view, linearLayout, relativeLayout, slidingTabLayout, textView, viewPager);
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActAichangefaceBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActAichangefaceBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_aichangeface, viewGroup, false);
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
