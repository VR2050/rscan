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
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.flyco.tablayout.SlidingTabLayout;
import com.google.android.material.appbar.AppBarLayout;
import com.jbzd.media.movecartoons.p396ui.index.view.BloodColorText;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.MarqueeTextView;

/* loaded from: classes2.dex */
public final class FragPostTabsingleBinding implements ViewBinding {

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    public final ImageTextView itvBloggerMore;

    @NonNull
    public final ImageTextView itvHeaderMore;

    @NonNull
    public final TextView itvMore;

    @NonNull
    public final LinearLayout llModuleHeaderPosthome;

    @NonNull
    public final LinearLayout llPostBloggerHot;

    @NonNull
    public final LinearLayout llPosthomeCategories;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvBloggers;

    @NonNull
    public final RecyclerView rvListCategories;

    @NonNull
    public final RecyclerView rvListType;

    @NonNull
    public final SlidingTabLayout tablayoutPostChild;

    @NonNull
    public final ImageView tvModuleTitleBg;

    @NonNull
    public final BloodColorText tvTitleBlock;

    @NonNull
    public final MarqueeTextView tvUserNewTips;

    private FragPostTabsingleBinding(@NonNull LinearLayout linearLayout, @NonNull AppBarLayout appBarLayout, @NonNull FrameLayout frameLayout, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull TextView textView, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2, @NonNull RecyclerView recyclerView3, @NonNull SlidingTabLayout slidingTabLayout, @NonNull ImageView imageView, @NonNull BloodColorText bloodColorText, @NonNull MarqueeTextView marqueeTextView) {
        this.rootView = linearLayout;
        this.appBarLayout = appBarLayout;
        this.fragContent = frameLayout;
        this.itvBloggerMore = imageTextView;
        this.itvHeaderMore = imageTextView2;
        this.itvMore = textView;
        this.llModuleHeaderPosthome = linearLayout2;
        this.llPostBloggerHot = linearLayout3;
        this.llPosthomeCategories = linearLayout4;
        this.llTop = linearLayout5;
        this.rvBloggers = recyclerView;
        this.rvListCategories = recyclerView2;
        this.rvListType = recyclerView3;
        this.tablayoutPostChild = slidingTabLayout;
        this.tvModuleTitleBg = imageView;
        this.tvTitleBlock = bloodColorText;
        this.tvUserNewTips = marqueeTextView;
    }

    @NonNull
    public static FragPostTabsingleBinding bind(@NonNull View view) {
        int i2 = R.id.app_bar_layout;
        AppBarLayout appBarLayout = (AppBarLayout) view.findViewById(R.id.app_bar_layout);
        if (appBarLayout != null) {
            i2 = R.id.frag_content;
            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
            if (frameLayout != null) {
                i2 = R.id.itv_bloggerMore;
                ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_bloggerMore);
                if (imageTextView != null) {
                    i2 = R.id.itv_header_more;
                    ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_header_more);
                    if (imageTextView2 != null) {
                        i2 = R.id.itv_more;
                        TextView textView = (TextView) view.findViewById(R.id.itv_more);
                        if (textView != null) {
                            i2 = R.id.ll_module_header_posthome;
                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_module_header_posthome);
                            if (linearLayout != null) {
                                i2 = R.id.ll_post_blogger_hot;
                                LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_post_blogger_hot);
                                if (linearLayout2 != null) {
                                    i2 = R.id.ll_posthome_categories;
                                    LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_posthome_categories);
                                    if (linearLayout3 != null) {
                                        i2 = R.id.ll_top;
                                        LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_top);
                                        if (linearLayout4 != null) {
                                            i2 = R.id.rv_bloggers;
                                            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_bloggers);
                                            if (recyclerView != null) {
                                                i2 = R.id.rv_list_categories;
                                                RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_list_categories);
                                                if (recyclerView2 != null) {
                                                    i2 = R.id.rv_list_type;
                                                    RecyclerView recyclerView3 = (RecyclerView) view.findViewById(R.id.rv_list_type);
                                                    if (recyclerView3 != null) {
                                                        i2 = R.id.tablayout_post_child;
                                                        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tablayout_post_child);
                                                        if (slidingTabLayout != null) {
                                                            i2 = R.id.tv_moduleTitle_bg;
                                                            ImageView imageView = (ImageView) view.findViewById(R.id.tv_moduleTitle_bg);
                                                            if (imageView != null) {
                                                                i2 = R.id.tv_title_block;
                                                                BloodColorText bloodColorText = (BloodColorText) view.findViewById(R.id.tv_title_block);
                                                                if (bloodColorText != null) {
                                                                    i2 = R.id.tv_user_new_tips;
                                                                    MarqueeTextView marqueeTextView = (MarqueeTextView) view.findViewById(R.id.tv_user_new_tips);
                                                                    if (marqueeTextView != null) {
                                                                        return new FragPostTabsingleBinding((LinearLayout) view, appBarLayout, frameLayout, imageTextView, imageTextView2, textView, linearLayout, linearLayout2, linearLayout3, linearLayout4, recyclerView, recyclerView2, recyclerView3, slidingTabLayout, imageView, bloodColorText, marqueeTextView);
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
    public static FragPostTabsingleBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragPostTabsingleBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_post_tabsingle, viewGroup, false);
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
