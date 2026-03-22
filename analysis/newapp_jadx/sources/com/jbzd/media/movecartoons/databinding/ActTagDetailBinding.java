package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.google.android.material.appbar.AppBarLayout;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.databinding.TitleBarLayoutBinding;

/* loaded from: classes2.dex */
public final class ActTagDetailBinding implements ViewBinding {

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    public final CircleImageView civHead;

    @NonNull
    public final TitleBarLayoutBinding include;

    @NonNull
    public final LinearLayout llBg;

    @NonNull
    public final ConstraintLayout llMineTop;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SlidingTabLayout sortingTabLayout;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvPostdetailNickname;

    @NonNull
    public final ViewPager vpContent;

    private ActTagDetailBinding(@NonNull LinearLayout linearLayout, @NonNull AppBarLayout appBarLayout, @NonNull CircleImageView circleImageView, @NonNull TitleBarLayoutBinding titleBarLayoutBinding, @NonNull LinearLayout linearLayout2, @NonNull ConstraintLayout constraintLayout, @NonNull SlidingTabLayout slidingTabLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.appBarLayout = appBarLayout;
        this.civHead = circleImageView;
        this.include = titleBarLayoutBinding;
        this.llBg = linearLayout2;
        this.llMineTop = constraintLayout;
        this.sortingTabLayout = slidingTabLayout;
        this.tvDesc = textView;
        this.tvPostdetailNickname = textView2;
        this.vpContent = viewPager;
    }

    @NonNull
    public static ActTagDetailBinding bind(@NonNull View view) {
        int i2 = R.id.app_bar_layout;
        AppBarLayout appBarLayout = (AppBarLayout) view.findViewById(R.id.app_bar_layout);
        if (appBarLayout != null) {
            i2 = R.id.civ_head;
            CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head);
            if (circleImageView != null) {
                i2 = R.id.include;
                View findViewById = view.findViewById(R.id.include);
                if (findViewById != null) {
                    TitleBarLayoutBinding bind = TitleBarLayoutBinding.bind(findViewById);
                    LinearLayout linearLayout = (LinearLayout) view;
                    i2 = R.id.ll_mineTop;
                    ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.ll_mineTop);
                    if (constraintLayout != null) {
                        i2 = R.id.sorting_tab_layout;
                        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.sorting_tab_layout);
                        if (slidingTabLayout != null) {
                            i2 = R.id.tv_desc;
                            TextView textView = (TextView) view.findViewById(R.id.tv_desc);
                            if (textView != null) {
                                i2 = R.id.tv_postdetail_nickname;
                                TextView textView2 = (TextView) view.findViewById(R.id.tv_postdetail_nickname);
                                if (textView2 != null) {
                                    i2 = R.id.vp_content;
                                    ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
                                    if (viewPager != null) {
                                        return new ActTagDetailBinding(linearLayout, appBarLayout, circleImageView, bind, linearLayout, constraintLayout, slidingTabLayout, textView, textView2, viewPager);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActTagDetailBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActTagDetailBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_tag_detail, viewGroup, false);
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
