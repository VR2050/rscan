package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.AdBottomBarView;
import com.jbzd.media.movecartoons.view.InlineAdView;
import com.jbzd.media.movecartoons.view.MarqueeRecyclerView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActNovelchapterViewBinding implements ViewBinding {

    @NonNull
    public final AdBottomBarView adBar;

    @NonNull
    public final RelativeLayout btnTitleBack;

    @NonNull
    public final RelativeLayout btnTitleRight;

    @NonNull
    public final RelativeLayout btnTitleRightIcon;

    @NonNull
    public final InlineAdView inlineAd;

    @NonNull
    public final ImageView ivNovelchapterLast;

    @NonNull
    public final ImageView ivNovelchapterNext;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final ImageView ivTitleRightIcon;

    @NonNull
    public final RelativeLayout llNovelLoading;

    @NonNull
    public final LinearLayout llNovelchapterviewBottom;

    @NonNull
    public final SeekBar progressNovelchapter;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final MarqueeRecyclerView rvComicschapterTxts;

    @NonNull
    public final RecyclerView rvListAdImg;

    @NonNull
    public final View titleDivider;

    @NonNull
    public final RelativeLayout titleLayoutComicsview;

    @NonNull
    public final TextView tvNameNovel;

    @NonNull
    public final TextView tvNovelchapterAll;

    @NonNull
    public final TextView tvNovelchapterAuto;

    @NonNull
    public final TextView tvNovelchapterCurrent;

    @NonNull
    public final TextView tvNovelchapterList;

    @NonNull
    public final TextView tvNovelchapterModelDayNight;

    @NonNull
    public final TextView tvNovelchapterSetting;

    @NonNull
    public final TextView tvTitleRight;

    private ActNovelchapterViewBinding(@NonNull LinearLayout linearLayout, @NonNull AdBottomBarView adBottomBarView, @NonNull RelativeLayout relativeLayout, @NonNull RelativeLayout relativeLayout2, @NonNull RelativeLayout relativeLayout3, @NonNull InlineAdView inlineAdView, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull ImageView imageView4, @NonNull RelativeLayout relativeLayout4, @NonNull LinearLayout linearLayout2, @NonNull SeekBar seekBar, @NonNull MarqueeRecyclerView marqueeRecyclerView, @NonNull RecyclerView recyclerView, @NonNull View view, @NonNull RelativeLayout relativeLayout5, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8) {
        this.rootView = linearLayout;
        this.adBar = adBottomBarView;
        this.btnTitleBack = relativeLayout;
        this.btnTitleRight = relativeLayout2;
        this.btnTitleRightIcon = relativeLayout3;
        this.inlineAd = inlineAdView;
        this.ivNovelchapterLast = imageView;
        this.ivNovelchapterNext = imageView2;
        this.ivTitleLeftIcon = imageView3;
        this.ivTitleRightIcon = imageView4;
        this.llNovelLoading = relativeLayout4;
        this.llNovelchapterviewBottom = linearLayout2;
        this.progressNovelchapter = seekBar;
        this.rvComicschapterTxts = marqueeRecyclerView;
        this.rvListAdImg = recyclerView;
        this.titleDivider = view;
        this.titleLayoutComicsview = relativeLayout5;
        this.tvNameNovel = textView;
        this.tvNovelchapterAll = textView2;
        this.tvNovelchapterAuto = textView3;
        this.tvNovelchapterCurrent = textView4;
        this.tvNovelchapterList = textView5;
        this.tvNovelchapterModelDayNight = textView6;
        this.tvNovelchapterSetting = textView7;
        this.tvTitleRight = textView8;
    }

    @NonNull
    public static ActNovelchapterViewBinding bind(@NonNull View view) {
        int i2 = R.id.adBar;
        AdBottomBarView adBottomBarView = (AdBottomBarView) view.findViewById(R.id.adBar);
        if (adBottomBarView != null) {
            i2 = R.id.btn_titleBack;
            RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.btn_titleBack);
            if (relativeLayout != null) {
                i2 = R.id.btn_titleRight;
                RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.btn_titleRight);
                if (relativeLayout2 != null) {
                    i2 = R.id.btn_titleRightIcon;
                    RelativeLayout relativeLayout3 = (RelativeLayout) view.findViewById(R.id.btn_titleRightIcon);
                    if (relativeLayout3 != null) {
                        i2 = R.id.inlineAd;
                        InlineAdView inlineAdView = (InlineAdView) view.findViewById(R.id.inlineAd);
                        if (inlineAdView != null) {
                            i2 = R.id.iv_novelchapter_last;
                            ImageView imageView = (ImageView) view.findViewById(R.id.iv_novelchapter_last);
                            if (imageView != null) {
                                i2 = R.id.iv_novelchapter_next;
                                ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_novelchapter_next);
                                if (imageView2 != null) {
                                    i2 = R.id.iv_titleLeftIcon;
                                    ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
                                    if (imageView3 != null) {
                                        i2 = R.id.iv_titleRightIcon;
                                        ImageView imageView4 = (ImageView) view.findViewById(R.id.iv_titleRightIcon);
                                        if (imageView4 != null) {
                                            i2 = R.id.ll_novel_loading;
                                            RelativeLayout relativeLayout4 = (RelativeLayout) view.findViewById(R.id.ll_novel_loading);
                                            if (relativeLayout4 != null) {
                                                i2 = R.id.ll_novelchapterview_bottom;
                                                LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_novelchapterview_bottom);
                                                if (linearLayout != null) {
                                                    i2 = R.id.progress_novelchapter;
                                                    SeekBar seekBar = (SeekBar) view.findViewById(R.id.progress_novelchapter);
                                                    if (seekBar != null) {
                                                        i2 = R.id.rv_comicschapter_txts;
                                                        MarqueeRecyclerView marqueeRecyclerView = (MarqueeRecyclerView) view.findViewById(R.id.rv_comicschapter_txts);
                                                        if (marqueeRecyclerView != null) {
                                                            i2 = R.id.rv_list_adImg;
                                                            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_list_adImg);
                                                            if (recyclerView != null) {
                                                                i2 = R.id.title_divider;
                                                                View findViewById = view.findViewById(R.id.title_divider);
                                                                if (findViewById != null) {
                                                                    i2 = R.id.title_layout_comicsview;
                                                                    RelativeLayout relativeLayout5 = (RelativeLayout) view.findViewById(R.id.title_layout_comicsview);
                                                                    if (relativeLayout5 != null) {
                                                                        i2 = R.id.tv_name_novel;
                                                                        TextView textView = (TextView) view.findViewById(R.id.tv_name_novel);
                                                                        if (textView != null) {
                                                                            i2 = R.id.tv_novelchapter_all;
                                                                            TextView textView2 = (TextView) view.findViewById(R.id.tv_novelchapter_all);
                                                                            if (textView2 != null) {
                                                                                i2 = R.id.tv_novelchapter_auto;
                                                                                TextView textView3 = (TextView) view.findViewById(R.id.tv_novelchapter_auto);
                                                                                if (textView3 != null) {
                                                                                    i2 = R.id.tv_novelchapter_current;
                                                                                    TextView textView4 = (TextView) view.findViewById(R.id.tv_novelchapter_current);
                                                                                    if (textView4 != null) {
                                                                                        i2 = R.id.tv_novelchapter_list;
                                                                                        TextView textView5 = (TextView) view.findViewById(R.id.tv_novelchapter_list);
                                                                                        if (textView5 != null) {
                                                                                            i2 = R.id.tv_novelchapter_model_day_night;
                                                                                            TextView textView6 = (TextView) view.findViewById(R.id.tv_novelchapter_model_day_night);
                                                                                            if (textView6 != null) {
                                                                                                i2 = R.id.tv_novelchapter_setting;
                                                                                                TextView textView7 = (TextView) view.findViewById(R.id.tv_novelchapter_setting);
                                                                                                if (textView7 != null) {
                                                                                                    i2 = R.id.tv_titleRight;
                                                                                                    TextView textView8 = (TextView) view.findViewById(R.id.tv_titleRight);
                                                                                                    if (textView8 != null) {
                                                                                                        return new ActNovelchapterViewBinding((LinearLayout) view, adBottomBarView, relativeLayout, relativeLayout2, relativeLayout3, inlineAdView, imageView, imageView2, imageView3, imageView4, relativeLayout4, linearLayout, seekBar, marqueeRecyclerView, recyclerView, findViewById, relativeLayout5, textView, textView2, textView3, textView4, textView5, textView6, textView7, textView8);
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
    public static ActNovelchapterViewBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActNovelchapterViewBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_novelchapter_view, viewGroup, false);
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
