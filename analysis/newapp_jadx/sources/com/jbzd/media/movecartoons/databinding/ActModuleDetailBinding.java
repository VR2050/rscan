package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
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
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActModuleDetailBinding implements ViewBinding {

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    public final RelativeLayout btnTitleBack;

    @NonNull
    public final RelativeLayout btnTitleRight;

    @NonNull
    public final RelativeLayout btnTitleRightIcon;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final ImageView ivTitleRightIcon;

    @NonNull
    public final LinearLayout lLayoutBg;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SlidingTabLayout sortingTabLayout;

    @NonNull
    public final TextView textTypeHotest;

    @NonNull
    public final TextView textTypeNewest;

    @NonNull
    public final View titleDivider;

    @NonNull
    public final RelativeLayout titleLayout;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final TextView tvTitleRight;

    @NonNull
    public final ViewPager vpContent;

    private ActModuleDetailBinding(@NonNull LinearLayout linearLayout, @NonNull AppBarLayout appBarLayout, @NonNull RelativeLayout relativeLayout, @NonNull RelativeLayout relativeLayout2, @NonNull RelativeLayout relativeLayout3, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull LinearLayout linearLayout2, @NonNull SlidingTabLayout slidingTabLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull View view, @NonNull RelativeLayout relativeLayout4, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.appBarLayout = appBarLayout;
        this.btnTitleBack = relativeLayout;
        this.btnTitleRight = relativeLayout2;
        this.btnTitleRightIcon = relativeLayout3;
        this.ivTitleLeftIcon = imageView;
        this.ivTitleRightIcon = imageView2;
        this.lLayoutBg = linearLayout2;
        this.sortingTabLayout = slidingTabLayout;
        this.textTypeHotest = textView;
        this.textTypeNewest = textView2;
        this.titleDivider = view;
        this.titleLayout = relativeLayout4;
        this.tvTitle = textView3;
        this.tvTitleRight = textView4;
        this.vpContent = viewPager;
    }

    @NonNull
    public static ActModuleDetailBinding bind(@NonNull View view) {
        int i2 = R.id.app_bar_layout;
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
                        i2 = R.id.iv_titleLeftIcon;
                        ImageView imageView = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
                        if (imageView != null) {
                            i2 = R.id.iv_titleRightIcon;
                            ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_titleRightIcon);
                            if (imageView2 != null) {
                                LinearLayout linearLayout = (LinearLayout) view;
                                i2 = R.id.sorting_tab_layout;
                                SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.sorting_tab_layout);
                                if (slidingTabLayout != null) {
                                    i2 = R.id.text_type_hotest;
                                    TextView textView = (TextView) view.findViewById(R.id.text_type_hotest);
                                    if (textView != null) {
                                        i2 = R.id.text_type_newest;
                                        TextView textView2 = (TextView) view.findViewById(R.id.text_type_newest);
                                        if (textView2 != null) {
                                            i2 = R.id.title_divider;
                                            View findViewById = view.findViewById(R.id.title_divider);
                                            if (findViewById != null) {
                                                i2 = R.id.title_layout;
                                                RelativeLayout relativeLayout4 = (RelativeLayout) view.findViewById(R.id.title_layout);
                                                if (relativeLayout4 != null) {
                                                    i2 = R.id.tv_title;
                                                    TextView textView3 = (TextView) view.findViewById(R.id.tv_title);
                                                    if (textView3 != null) {
                                                        i2 = R.id.tv_titleRight;
                                                        TextView textView4 = (TextView) view.findViewById(R.id.tv_titleRight);
                                                        if (textView4 != null) {
                                                            i2 = R.id.vp_content;
                                                            ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
                                                            if (viewPager != null) {
                                                                return new ActModuleDetailBinding(linearLayout, appBarLayout, relativeLayout, relativeLayout2, relativeLayout3, imageView, imageView2, linearLayout, slidingTabLayout, textView, textView2, findViewById, relativeLayout4, textView3, textView4, viewPager);
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
    public static ActModuleDetailBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActModuleDetailBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_module_detail, viewGroup, false);
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
