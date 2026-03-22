package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Guideline;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.google.android.material.appbar.AppBarLayout;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActMypostListBinding implements ViewBinding {

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    public final FrameLayout btnTitleBack;

    @NonNull
    public final FrameLayout btnTitleRight;

    @NonNull
    public final FrameLayout btnTitleRightIcon;

    @NonNull
    public final Guideline guideLine;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final ImageView ivTitleRightIcon;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final SlidingTabLayout tablayoutPostChild;

    @NonNull
    public final View titleDivider;

    @NonNull
    public final ConstraintLayout titleLayout;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final TextView tvTitleRight;

    @NonNull
    public final TextView tvWalletBalance;

    @NonNull
    public final TextView tvWalletIncome;

    @NonNull
    public final TextView tvWalletIncomedetail;

    @NonNull
    public final TextView tvWalletWithdraw;

    @NonNull
    public final TextView txtCurrentBalance;

    @NonNull
    public final TextView txtTotalCount;

    @NonNull
    public final ViewPager vpContentPostchild;

    private ActMypostListBinding(@NonNull LinearLayout linearLayout, @NonNull AppBarLayout appBarLayout, @NonNull FrameLayout frameLayout, @NonNull FrameLayout frameLayout2, @NonNull FrameLayout frameLayout3, @NonNull Guideline guideline, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull LinearLayout linearLayout2, @NonNull SlidingTabLayout slidingTabLayout, @NonNull View view, @NonNull ConstraintLayout constraintLayout, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.appBarLayout = appBarLayout;
        this.btnTitleBack = frameLayout;
        this.btnTitleRight = frameLayout2;
        this.btnTitleRightIcon = frameLayout3;
        this.guideLine = guideline;
        this.ivTitleLeftIcon = imageView;
        this.ivTitleRightIcon = imageView2;
        this.llTop = linearLayout2;
        this.tablayoutPostChild = slidingTabLayout;
        this.titleDivider = view;
        this.titleLayout = constraintLayout;
        this.tvTitle = textView;
        this.tvTitleRight = textView2;
        this.tvWalletBalance = textView3;
        this.tvWalletIncome = textView4;
        this.tvWalletIncomedetail = textView5;
        this.tvWalletWithdraw = textView6;
        this.txtCurrentBalance = textView7;
        this.txtTotalCount = textView8;
        this.vpContentPostchild = viewPager;
    }

    @NonNull
    public static ActMypostListBinding bind(@NonNull View view) {
        int i2 = R.id.app_bar_layout;
        AppBarLayout appBarLayout = (AppBarLayout) view.findViewById(R.id.app_bar_layout);
        if (appBarLayout != null) {
            i2 = R.id.btn_titleBack;
            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.btn_titleBack);
            if (frameLayout != null) {
                i2 = R.id.btn_titleRight;
                FrameLayout frameLayout2 = (FrameLayout) view.findViewById(R.id.btn_titleRight);
                if (frameLayout2 != null) {
                    i2 = R.id.btn_titleRightIcon;
                    FrameLayout frameLayout3 = (FrameLayout) view.findViewById(R.id.btn_titleRightIcon);
                    if (frameLayout3 != null) {
                        i2 = R.id.guideLine;
                        Guideline guideline = (Guideline) view.findViewById(R.id.guideLine);
                        if (guideline != null) {
                            i2 = R.id.iv_titleLeftIcon;
                            ImageView imageView = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
                            if (imageView != null) {
                                i2 = R.id.iv_titleRightIcon;
                                ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_titleRightIcon);
                                if (imageView2 != null) {
                                    i2 = R.id.ll_top;
                                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_top);
                                    if (linearLayout != null) {
                                        i2 = R.id.tablayout_post_child;
                                        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tablayout_post_child);
                                        if (slidingTabLayout != null) {
                                            i2 = R.id.title_divider;
                                            View findViewById = view.findViewById(R.id.title_divider);
                                            if (findViewById != null) {
                                                i2 = R.id.title_layout;
                                                ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.title_layout);
                                                if (constraintLayout != null) {
                                                    i2 = R.id.tv_title;
                                                    TextView textView = (TextView) view.findViewById(R.id.tv_title);
                                                    if (textView != null) {
                                                        i2 = R.id.tv_titleRight;
                                                        TextView textView2 = (TextView) view.findViewById(R.id.tv_titleRight);
                                                        if (textView2 != null) {
                                                            i2 = R.id.tv_wallet_balance;
                                                            TextView textView3 = (TextView) view.findViewById(R.id.tv_wallet_balance);
                                                            if (textView3 != null) {
                                                                i2 = R.id.tv_wallet_income;
                                                                TextView textView4 = (TextView) view.findViewById(R.id.tv_wallet_income);
                                                                if (textView4 != null) {
                                                                    i2 = R.id.tv_wallet_incomedetail;
                                                                    TextView textView5 = (TextView) view.findViewById(R.id.tv_wallet_incomedetail);
                                                                    if (textView5 != null) {
                                                                        i2 = R.id.tv_wallet_withdraw;
                                                                        TextView textView6 = (TextView) view.findViewById(R.id.tv_wallet_withdraw);
                                                                        if (textView6 != null) {
                                                                            i2 = R.id.txt_current_balance;
                                                                            TextView textView7 = (TextView) view.findViewById(R.id.txt_current_balance);
                                                                            if (textView7 != null) {
                                                                                i2 = R.id.txt_total_count;
                                                                                TextView textView8 = (TextView) view.findViewById(R.id.txt_total_count);
                                                                                if (textView8 != null) {
                                                                                    i2 = R.id.vp_content_postchild;
                                                                                    ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content_postchild);
                                                                                    if (viewPager != null) {
                                                                                        return new ActMypostListBinding((LinearLayout) view, appBarLayout, frameLayout, frameLayout2, frameLayout3, guideline, imageView, imageView2, linearLayout, slidingTabLayout, findViewById, constraintLayout, textView, textView2, textView3, textView4, textView5, textView6, textView7, textView8, viewPager);
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
    public static ActMypostListBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActMypostListBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_mypost_list, viewGroup, false);
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
