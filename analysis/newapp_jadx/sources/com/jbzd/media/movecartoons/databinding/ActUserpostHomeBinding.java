package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.google.android.material.appbar.AppBarLayout;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActUserpostHomeBinding implements ViewBinding {

    @NonNull
    public final TextView accIdPosthome;

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    public final RelativeLayout btnTitleBack;

    @NonNull
    public final RelativeLayout btnTitleRight;

    @NonNull
    public final RelativeLayout btnTitleRightIcon;

    @NonNull
    public final CircleImageView civHeadPosthome;

    @NonNull
    public final TextView fansPosthome;

    @NonNull
    public final TextView followsPosthome;

    @NonNull
    public final ImageTextView ivIsposter;

    @NonNull
    public final ImageTextView ivIsposterVip;

    @NonNull
    public final ImageView ivSexPosthome;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final ImageView ivTitleRightIcon;

    @NonNull
    public final LinearLayout llMineInfo;

    @NonNull
    public final LinearLayout llMyTitle;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final ImageView srcSexLeftline;

    @NonNull
    public final SlidingTabLayout tablayoutUserhome;

    @NonNull
    public final View titleDivider;

    @NonNull
    public final RelativeLayout titleLayout;

    @NonNull
    public final TextView tvComicsdetailName;

    @NonNull
    public final FollowTextView tvFollowPosthome;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final TextView tvTitleRight;

    @NonNull
    public final ViewPager vpContentUserhome;

    private ActUserpostHomeBinding(@NonNull FrameLayout frameLayout, @NonNull TextView textView, @NonNull AppBarLayout appBarLayout, @NonNull RelativeLayout relativeLayout, @NonNull RelativeLayout relativeLayout2, @NonNull RelativeLayout relativeLayout3, @NonNull CircleImageView circleImageView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull ImageView imageView4, @NonNull SlidingTabLayout slidingTabLayout, @NonNull View view, @NonNull RelativeLayout relativeLayout4, @NonNull TextView textView4, @NonNull FollowTextView followTextView, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull ViewPager viewPager) {
        this.rootView = frameLayout;
        this.accIdPosthome = textView;
        this.appBarLayout = appBarLayout;
        this.btnTitleBack = relativeLayout;
        this.btnTitleRight = relativeLayout2;
        this.btnTitleRightIcon = relativeLayout3;
        this.civHeadPosthome = circleImageView;
        this.fansPosthome = textView2;
        this.followsPosthome = textView3;
        this.ivIsposter = imageTextView;
        this.ivIsposterVip = imageTextView2;
        this.ivSexPosthome = imageView;
        this.ivTitleLeftIcon = imageView2;
        this.ivTitleRightIcon = imageView3;
        this.llMineInfo = linearLayout;
        this.llMyTitle = linearLayout2;
        this.llTop = linearLayout3;
        this.srcSexLeftline = imageView4;
        this.tablayoutUserhome = slidingTabLayout;
        this.titleDivider = view;
        this.titleLayout = relativeLayout4;
        this.tvComicsdetailName = textView4;
        this.tvFollowPosthome = followTextView;
        this.tvTitle = textView5;
        this.tvTitleRight = textView6;
        this.vpContentUserhome = viewPager;
    }

    @NonNull
    public static ActUserpostHomeBinding bind(@NonNull View view) {
        int i2 = R.id.acc_id_posthome;
        TextView textView = (TextView) view.findViewById(R.id.acc_id_posthome);
        if (textView != null) {
            i2 = R.id.app_bar_layout;
            AppBarLayout appBarLayout = (AppBarLayout) view.findViewById(R.id.app_bar_layout);
            if (appBarLayout != null) {
                i2 = R.id.btn_titleBack;
                RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.btn_titleBack);
                if (relativeLayout != null) {
                    i2 = R.id.btn_titleRight;
                    RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.btn_titleRight);
                    if (relativeLayout2 != null) {
                        i2 = R.id.btn_titleRightIcon;
                        RelativeLayout relativeLayout3 = (RelativeLayout) view.findViewById(R.id.btn_titleRightIcon);
                        if (relativeLayout3 != null) {
                            i2 = R.id.civ_head_posthome;
                            CircleImageView circleImageView = (CircleImageView) view.findViewById(R.id.civ_head_posthome);
                            if (circleImageView != null) {
                                i2 = R.id.fans_posthome;
                                TextView textView2 = (TextView) view.findViewById(R.id.fans_posthome);
                                if (textView2 != null) {
                                    i2 = R.id.follows_posthome;
                                    TextView textView3 = (TextView) view.findViewById(R.id.follows_posthome);
                                    if (textView3 != null) {
                                        i2 = R.id.iv_isposter;
                                        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.iv_isposter);
                                        if (imageTextView != null) {
                                            i2 = R.id.iv_isposter_vip;
                                            ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.iv_isposter_vip);
                                            if (imageTextView2 != null) {
                                                i2 = R.id.iv_sex_posthome;
                                                ImageView imageView = (ImageView) view.findViewById(R.id.iv_sex_posthome);
                                                if (imageView != null) {
                                                    i2 = R.id.iv_titleLeftIcon;
                                                    ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
                                                    if (imageView2 != null) {
                                                        i2 = R.id.iv_titleRightIcon;
                                                        ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_titleRightIcon);
                                                        if (imageView3 != null) {
                                                            i2 = R.id.ll_mine_info;
                                                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_mine_info);
                                                            if (linearLayout != null) {
                                                                i2 = R.id.ll_my_title;
                                                                LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_my_title);
                                                                if (linearLayout2 != null) {
                                                                    i2 = R.id.ll_top;
                                                                    LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_top);
                                                                    if (linearLayout3 != null) {
                                                                        i2 = R.id.src_sex_leftline;
                                                                        ImageView imageView4 = (ImageView) view.findViewById(R.id.src_sex_leftline);
                                                                        if (imageView4 != null) {
                                                                            i2 = R.id.tablayout_userhome;
                                                                            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tablayout_userhome);
                                                                            if (slidingTabLayout != null) {
                                                                                i2 = R.id.title_divider;
                                                                                View findViewById = view.findViewById(R.id.title_divider);
                                                                                if (findViewById != null) {
                                                                                    i2 = R.id.title_layout;
                                                                                    RelativeLayout relativeLayout4 = (RelativeLayout) view.findViewById(R.id.title_layout);
                                                                                    if (relativeLayout4 != null) {
                                                                                        i2 = R.id.tv_comicsdetail_name;
                                                                                        TextView textView4 = (TextView) view.findViewById(R.id.tv_comicsdetail_name);
                                                                                        if (textView4 != null) {
                                                                                            i2 = R.id.tv_follow_posthome;
                                                                                            FollowTextView followTextView = (FollowTextView) view.findViewById(R.id.tv_follow_posthome);
                                                                                            if (followTextView != null) {
                                                                                                i2 = R.id.tv_title;
                                                                                                TextView textView5 = (TextView) view.findViewById(R.id.tv_title);
                                                                                                if (textView5 != null) {
                                                                                                    i2 = R.id.tv_titleRight;
                                                                                                    TextView textView6 = (TextView) view.findViewById(R.id.tv_titleRight);
                                                                                                    if (textView6 != null) {
                                                                                                        i2 = R.id.vp_content_userhome;
                                                                                                        ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content_userhome);
                                                                                                        if (viewPager != null) {
                                                                                                            return new ActUserpostHomeBinding((FrameLayout) view, textView, appBarLayout, relativeLayout, relativeLayout2, relativeLayout3, circleImageView, textView2, textView3, imageTextView, imageTextView2, imageView, imageView2, imageView3, linearLayout, linearLayout2, linearLayout3, imageView4, slidingTabLayout, findViewById, relativeLayout4, textView4, followTextView, textView5, textView6, viewPager);
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
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
    public static ActUserpostHomeBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActUserpostHomeBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_userpost_home, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public FrameLayout getRoot() {
        return this.rootView;
    }
}
