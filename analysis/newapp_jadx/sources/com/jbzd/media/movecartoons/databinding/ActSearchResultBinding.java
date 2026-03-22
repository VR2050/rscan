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
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.ClearEditText;

/* loaded from: classes2.dex */
public final class ActSearchResultBinding implements ViewBinding {

    @NonNull
    public final RelativeLayout btnTitleBack;

    @NonNull
    public final ClearEditText cetInput;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final LinearLayout llSearch;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    public final LinearLayout llType;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final LinearLayout searchLayoutBar;

    @NonNull
    public final TextView tvDoSearch;

    @NonNull
    public final TextView tvType;

    @NonNull
    public final ViewPager vpContent;

    private ActSearchResultBinding(@NonNull LinearLayout linearLayout, @NonNull RelativeLayout relativeLayout, @NonNull ClearEditText clearEditText, @NonNull ImageView imageView, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull TextView textView, @NonNull TextView textView2, @NonNull ViewPager viewPager) {
        this.rootView = linearLayout;
        this.btnTitleBack = relativeLayout;
        this.cetInput = clearEditText;
        this.ivTitleLeftIcon = imageView;
        this.llSearch = linearLayout2;
        this.llTop = linearLayout3;
        this.llType = linearLayout4;
        this.searchLayoutBar = linearLayout5;
        this.tvDoSearch = textView;
        this.tvType = textView2;
        this.vpContent = viewPager;
    }

    @NonNull
    public static ActSearchResultBinding bind(@NonNull View view) {
        int i2 = R.id.btn_titleBack;
        RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.btn_titleBack);
        if (relativeLayout != null) {
            i2 = R.id.cet_input;
            ClearEditText clearEditText = (ClearEditText) view.findViewById(R.id.cet_input);
            if (clearEditText != null) {
                i2 = R.id.iv_titleLeftIcon;
                ImageView imageView = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
                if (imageView != null) {
                    i2 = R.id.ll_search;
                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_search);
                    if (linearLayout != null) {
                        i2 = R.id.ll_top;
                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_top);
                        if (linearLayout2 != null) {
                            i2 = R.id.ll_type;
                            LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_type);
                            if (linearLayout3 != null) {
                                i2 = R.id.search_layout_bar;
                                LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.search_layout_bar);
                                if (linearLayout4 != null) {
                                    i2 = R.id.tv_doSearch;
                                    TextView textView = (TextView) view.findViewById(R.id.tv_doSearch);
                                    if (textView != null) {
                                        i2 = R.id.tv_type;
                                        TextView textView2 = (TextView) view.findViewById(R.id.tv_type);
                                        if (textView2 != null) {
                                            i2 = R.id.vp_content;
                                            ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_content);
                                            if (viewPager != null) {
                                                return new ActSearchResultBinding((LinearLayout) view, relativeLayout, clearEditText, imageView, linearLayout, linearLayout2, linearLayout3, linearLayout4, textView, textView2, viewPager);
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
    public static ActSearchResultBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActSearchResultBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_search_result, viewGroup, false);
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
