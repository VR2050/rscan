package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.appbar.AppBarLayout;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.ClearEditText;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class FragSearchHistoryBinding implements ViewBinding {

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    public final ScaleRelativeLayout bannerParentSearch;

    @NonNull
    public final Banner bannerSearch;

    @NonNull
    public final ClearEditText cetInput;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    public final LinearLayout llHot;

    @NonNull
    public final LinearLayout llHty;

    @NonNull
    public final LinearLayout llSearch;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvHotWords;

    @NonNull
    public final RecyclerView rvHotWordsPost;

    @NonNull
    public final RecyclerView rvHty;

    @NonNull
    public final LinearLayout searchLayoutBar;

    @NonNull
    public final TextView tvClearHistory;

    @NonNull
    public final TextView tvDoSearch;

    private FragSearchHistoryBinding(@NonNull LinearLayout linearLayout, @NonNull AppBarLayout appBarLayout, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull Banner banner, @NonNull ClearEditText clearEditText, @NonNull FrameLayout frameLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2, @NonNull RecyclerView recyclerView3, @NonNull LinearLayout linearLayout6, @NonNull TextView textView, @NonNull TextView textView2) {
        this.rootView = linearLayout;
        this.appBarLayout = appBarLayout;
        this.bannerParentSearch = scaleRelativeLayout;
        this.bannerSearch = banner;
        this.cetInput = clearEditText;
        this.fragContent = frameLayout;
        this.llHot = linearLayout2;
        this.llHty = linearLayout3;
        this.llSearch = linearLayout4;
        this.llTop = linearLayout5;
        this.rvHotWords = recyclerView;
        this.rvHotWordsPost = recyclerView2;
        this.rvHty = recyclerView3;
        this.searchLayoutBar = linearLayout6;
        this.tvClearHistory = textView;
        this.tvDoSearch = textView2;
    }

    @NonNull
    public static FragSearchHistoryBinding bind(@NonNull View view) {
        int i2 = R.id.app_bar_layout;
        AppBarLayout appBarLayout = (AppBarLayout) view.findViewById(R.id.app_bar_layout);
        if (appBarLayout != null) {
            i2 = R.id.banner_parent_search;
            ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.banner_parent_search);
            if (scaleRelativeLayout != null) {
                i2 = R.id.banner_search;
                Banner banner = (Banner) view.findViewById(R.id.banner_search);
                if (banner != null) {
                    i2 = R.id.cet_input;
                    ClearEditText clearEditText = (ClearEditText) view.findViewById(R.id.cet_input);
                    if (clearEditText != null) {
                        i2 = R.id.frag_content;
                        FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
                        if (frameLayout != null) {
                            i2 = R.id.ll_hot;
                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_hot);
                            if (linearLayout != null) {
                                i2 = R.id.ll_hty;
                                LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_hty);
                                if (linearLayout2 != null) {
                                    i2 = R.id.ll_search;
                                    LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_search);
                                    if (linearLayout3 != null) {
                                        i2 = R.id.ll_top;
                                        LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_top);
                                        if (linearLayout4 != null) {
                                            i2 = R.id.rv_hotWords;
                                            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_hotWords);
                                            if (recyclerView != null) {
                                                i2 = R.id.rv_hotWords_post;
                                                RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_hotWords_post);
                                                if (recyclerView2 != null) {
                                                    i2 = R.id.rv_hty;
                                                    RecyclerView recyclerView3 = (RecyclerView) view.findViewById(R.id.rv_hty);
                                                    if (recyclerView3 != null) {
                                                        i2 = R.id.search_layout_bar;
                                                        LinearLayout linearLayout5 = (LinearLayout) view.findViewById(R.id.search_layout_bar);
                                                        if (linearLayout5 != null) {
                                                            i2 = R.id.tv_clear_history;
                                                            TextView textView = (TextView) view.findViewById(R.id.tv_clear_history);
                                                            if (textView != null) {
                                                                i2 = R.id.tv_doSearch;
                                                                TextView textView2 = (TextView) view.findViewById(R.id.tv_doSearch);
                                                                if (textView2 != null) {
                                                                    return new FragSearchHistoryBinding((LinearLayout) view, appBarLayout, scaleRelativeLayout, banner, clearEditText, frameLayout, linearLayout, linearLayout2, linearLayout3, linearLayout4, recyclerView, recyclerView2, recyclerView3, linearLayout5, textView, textView2);
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
    public static FragSearchHistoryBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragSearchHistoryBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_search_history, viewGroup, false);
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
