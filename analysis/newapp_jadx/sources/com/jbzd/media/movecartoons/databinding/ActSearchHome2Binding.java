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
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.google.android.material.appbar.AppBarLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.ClearEditText;

/* loaded from: classes2.dex */
public final class ActSearchHome2Binding implements ViewBinding {

    @NonNull
    public final AppBarLayout appBarLayout;

    @NonNull
    public final RelativeLayout btnTitleBack;

    @NonNull
    public final ClearEditText cetInput;

    @NonNull
    public final FrameLayout fragContent;

    @NonNull
    public final ImageView ivDeleteHty;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final LinearLayout llHot;

    @NonNull
    public final LinearLayout llHty;

    @NonNull
    public final LinearLayout llSearch;

    @NonNull
    public final LinearLayout llTag;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final RecyclerView rvHotWords;

    @NonNull
    public final RecyclerView rvHty;

    @NonNull
    public final RecyclerView rvTags;

    @NonNull
    public final LinearLayout searchLayoutBar;

    @NonNull
    public final TextView tvDoSearch;

    private ActSearchHome2Binding(@NonNull LinearLayout linearLayout, @NonNull AppBarLayout appBarLayout, @NonNull RelativeLayout relativeLayout, @NonNull ClearEditText clearEditText, @NonNull FrameLayout frameLayout, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull LinearLayout linearLayout6, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2, @NonNull RecyclerView recyclerView3, @NonNull LinearLayout linearLayout7, @NonNull TextView textView) {
        this.rootView = linearLayout;
        this.appBarLayout = appBarLayout;
        this.btnTitleBack = relativeLayout;
        this.cetInput = clearEditText;
        this.fragContent = frameLayout;
        this.ivDeleteHty = imageView;
        this.ivTitleLeftIcon = imageView2;
        this.llHot = linearLayout2;
        this.llHty = linearLayout3;
        this.llSearch = linearLayout4;
        this.llTag = linearLayout5;
        this.llTop = linearLayout6;
        this.rvHotWords = recyclerView;
        this.rvHty = recyclerView2;
        this.rvTags = recyclerView3;
        this.searchLayoutBar = linearLayout7;
        this.tvDoSearch = textView;
    }

    @NonNull
    public static ActSearchHome2Binding bind(@NonNull View view) {
        int i2 = R.id.app_bar_layout;
        AppBarLayout appBarLayout = (AppBarLayout) view.findViewById(R.id.app_bar_layout);
        if (appBarLayout != null) {
            i2 = R.id.btn_titleBack;
            RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.btn_titleBack);
            if (relativeLayout != null) {
                i2 = R.id.cet_input;
                ClearEditText clearEditText = (ClearEditText) view.findViewById(R.id.cet_input);
                if (clearEditText != null) {
                    i2 = R.id.frag_content;
                    FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.frag_content);
                    if (frameLayout != null) {
                        i2 = R.id.iv_deleteHty;
                        ImageView imageView = (ImageView) view.findViewById(R.id.iv_deleteHty);
                        if (imageView != null) {
                            i2 = R.id.iv_titleLeftIcon;
                            ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
                            if (imageView2 != null) {
                                i2 = R.id.ll_hot;
                                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_hot);
                                if (linearLayout != null) {
                                    i2 = R.id.ll_hty;
                                    LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_hty);
                                    if (linearLayout2 != null) {
                                        i2 = R.id.ll_search;
                                        LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_search);
                                        if (linearLayout3 != null) {
                                            i2 = R.id.ll_tag;
                                            LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_tag);
                                            if (linearLayout4 != null) {
                                                i2 = R.id.ll_top;
                                                LinearLayout linearLayout5 = (LinearLayout) view.findViewById(R.id.ll_top);
                                                if (linearLayout5 != null) {
                                                    i2 = R.id.rv_hotWords;
                                                    RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_hotWords);
                                                    if (recyclerView != null) {
                                                        i2 = R.id.rv_hty;
                                                        RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_hty);
                                                        if (recyclerView2 != null) {
                                                            i2 = R.id.rv_tags;
                                                            RecyclerView recyclerView3 = (RecyclerView) view.findViewById(R.id.rv_tags);
                                                            if (recyclerView3 != null) {
                                                                i2 = R.id.search_layout_bar;
                                                                LinearLayout linearLayout6 = (LinearLayout) view.findViewById(R.id.search_layout_bar);
                                                                if (linearLayout6 != null) {
                                                                    i2 = R.id.tv_doSearch;
                                                                    TextView textView = (TextView) view.findViewById(R.id.tv_doSearch);
                                                                    if (textView != null) {
                                                                        return new ActSearchHome2Binding((LinearLayout) view, appBarLayout, relativeLayout, clearEditText, frameLayout, imageView, imageView2, linearLayout, linearLayout2, linearLayout3, linearLayout4, linearLayout5, recyclerView, recyclerView2, recyclerView3, linearLayout6, textView);
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
    public static ActSearchHome2Binding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActSearchHome2Binding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_search_home2, viewGroup, false);
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
