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
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.google.android.material.appbar.AppBarLayout;
import com.jbzd.media.movecartoons.p396ui.index.view.BloodColorText;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActPostCategoryDetailBinding implements ViewBinding {

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    public final FrameLayout btnTitleBack;

    @NonNull
    public final FrameLayout btnTitleRight;

    @NonNull
    public final FrameLayout btnTitleRightIcon;

    @NonNull
    public final ImageTextView itvHeaderMore;

    @NonNull
    public final TextView itvMore;

    @NonNull
    public final FollowTextView itvPostuserFollow;

    @NonNull
    public final ImageView ivCategoryImg;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final ImageView ivTitleRightIcon;

    @NonNull
    public final LinearLayout llModuleHeaderPosthome;

    @NonNull
    public final LinearLayout llPosthomeCategories;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final FrameLayout rootView;

    @NonNull
    public final RecyclerView rvListCategories;

    @NonNull
    public final SlidingTabLayout tabCategorDetailOrder;

    @NonNull
    public final View titleDivider;

    @NonNull
    public final ConstraintLayout titleLayout;

    @NonNull
    public final ImageView tvModuleTitleBg;

    @NonNull
    public final TextView tvPostcategoryClick;

    @NonNull
    public final TextView tvPostcategoryCount;

    @NonNull
    public final TextView tvPostcategoryDescription;

    @NonNull
    public final TextView tvPostcategoryName;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final BloodColorText tvTitleBlock;

    @NonNull
    public final TextView tvTitleRight;

    @NonNull
    public final ViewPager vpBottomCategorDetail;

    private ActPostCategoryDetailBinding(@NonNull FrameLayout frameLayout, @NonNull AppBarLayout appBarLayout, @NonNull FrameLayout frameLayout2, @NonNull FrameLayout frameLayout3, @NonNull FrameLayout frameLayout4, @NonNull ImageTextView imageTextView, @NonNull TextView textView, @NonNull FollowTextView followTextView, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull RecyclerView recyclerView, @NonNull SlidingTabLayout slidingTabLayout, @NonNull View view, @NonNull ConstraintLayout constraintLayout, @NonNull ImageView imageView4, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull BloodColorText bloodColorText, @NonNull TextView textView7, @NonNull ViewPager viewPager) {
        this.rootView = frameLayout;
        this.appBarLayout = appBarLayout;
        this.btnTitleBack = frameLayout2;
        this.btnTitleRight = frameLayout3;
        this.btnTitleRightIcon = frameLayout4;
        this.itvHeaderMore = imageTextView;
        this.itvMore = textView;
        this.itvPostuserFollow = followTextView;
        this.ivCategoryImg = imageView;
        this.ivTitleLeftIcon = imageView2;
        this.ivTitleRightIcon = imageView3;
        this.llModuleHeaderPosthome = linearLayout;
        this.llPosthomeCategories = linearLayout2;
        this.llTop = linearLayout3;
        this.rvListCategories = recyclerView;
        this.tabCategorDetailOrder = slidingTabLayout;
        this.titleDivider = view;
        this.titleLayout = constraintLayout;
        this.tvModuleTitleBg = imageView4;
        this.tvPostcategoryClick = textView2;
        this.tvPostcategoryCount = textView3;
        this.tvPostcategoryDescription = textView4;
        this.tvPostcategoryName = textView5;
        this.tvTitle = textView6;
        this.tvTitleBlock = bloodColorText;
        this.tvTitleRight = textView7;
        this.vpBottomCategorDetail = viewPager;
    }

    @NonNull
    public static ActPostCategoryDetailBinding bind(@NonNull View view) {
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
                        i2 = R.id.itv_header_more;
                        ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_header_more);
                        if (imageTextView != null) {
                            i2 = R.id.itv_more;
                            TextView textView = (TextView) view.findViewById(R.id.itv_more);
                            if (textView != null) {
                                i2 = R.id.itv_postuser_follow;
                                FollowTextView followTextView = (FollowTextView) view.findViewById(R.id.itv_postuser_follow);
                                if (followTextView != null) {
                                    i2 = R.id.iv_category_img;
                                    ImageView imageView = (ImageView) view.findViewById(R.id.iv_category_img);
                                    if (imageView != null) {
                                        i2 = R.id.iv_titleLeftIcon;
                                        ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
                                        if (imageView2 != null) {
                                            i2 = R.id.iv_titleRightIcon;
                                            ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_titleRightIcon);
                                            if (imageView3 != null) {
                                                i2 = R.id.ll_module_header_posthome;
                                                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_module_header_posthome);
                                                if (linearLayout != null) {
                                                    i2 = R.id.ll_posthome_categories;
                                                    LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_posthome_categories);
                                                    if (linearLayout2 != null) {
                                                        i2 = R.id.ll_top;
                                                        LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_top);
                                                        if (linearLayout3 != null) {
                                                            i2 = R.id.rv_list_categories;
                                                            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_list_categories);
                                                            if (recyclerView != null) {
                                                                i2 = R.id.tab_categor_detail_order;
                                                                SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tab_categor_detail_order);
                                                                if (slidingTabLayout != null) {
                                                                    i2 = R.id.title_divider;
                                                                    View findViewById = view.findViewById(R.id.title_divider);
                                                                    if (findViewById != null) {
                                                                        i2 = R.id.title_layout;
                                                                        ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.title_layout);
                                                                        if (constraintLayout != null) {
                                                                            i2 = R.id.tv_moduleTitle_bg;
                                                                            ImageView imageView4 = (ImageView) view.findViewById(R.id.tv_moduleTitle_bg);
                                                                            if (imageView4 != null) {
                                                                                i2 = R.id.tv_postcategory_click;
                                                                                TextView textView2 = (TextView) view.findViewById(R.id.tv_postcategory_click);
                                                                                if (textView2 != null) {
                                                                                    i2 = R.id.tv_postcategory_count;
                                                                                    TextView textView3 = (TextView) view.findViewById(R.id.tv_postcategory_count);
                                                                                    if (textView3 != null) {
                                                                                        i2 = R.id.tv_postcategory_description;
                                                                                        TextView textView4 = (TextView) view.findViewById(R.id.tv_postcategory_description);
                                                                                        if (textView4 != null) {
                                                                                            i2 = R.id.tv_postcategory_name;
                                                                                            TextView textView5 = (TextView) view.findViewById(R.id.tv_postcategory_name);
                                                                                            if (textView5 != null) {
                                                                                                i2 = R.id.tv_title;
                                                                                                TextView textView6 = (TextView) view.findViewById(R.id.tv_title);
                                                                                                if (textView6 != null) {
                                                                                                    i2 = R.id.tv_title_block;
                                                                                                    BloodColorText bloodColorText = (BloodColorText) view.findViewById(R.id.tv_title_block);
                                                                                                    if (bloodColorText != null) {
                                                                                                        i2 = R.id.tv_titleRight;
                                                                                                        TextView textView7 = (TextView) view.findViewById(R.id.tv_titleRight);
                                                                                                        if (textView7 != null) {
                                                                                                            i2 = R.id.vp_bottom_categor_detail;
                                                                                                            ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_bottom_categor_detail);
                                                                                                            if (viewPager != null) {
                                                                                                                return new ActPostCategoryDetailBinding((FrameLayout) view, appBarLayout, frameLayout, frameLayout2, frameLayout3, imageTextView, textView, followTextView, imageView, imageView2, imageView3, linearLayout, linearLayout2, linearLayout3, recyclerView, slidingTabLayout, findViewById, constraintLayout, imageView4, textView2, textView3, textView4, textView5, textView6, bloodColorText, textView7, viewPager);
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
        }
        throw new NullPointerException("Missing required view with ID: ".concat(view.getResources().getResourceName(i2)));
    }

    @NonNull
    public static ActPostCategoryDetailBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActPostCategoryDetailBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_post_category_detail, viewGroup, false);
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
