package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.AdBottomBarView;
import com.jbzd.media.movecartoons.view.MarqueeRecyclerView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActComicschapterViewBinding implements ViewBinding {

    @NonNull
    public final AdBottomBarView adBar;

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
    public final ImageView ivTopPlace;

    @NonNull
    public final ImageView ivViewLast;

    @NonNull
    public final ImageView ivViewNext;

    @NonNull
    public final FrameLayout llComicschapterviewBottom;

    @NonNull
    public final ConstraintLayout llComicsviewContent;

    @NonNull
    public final SeekBar progressComicschapter;

    @NonNull
    private final LinearLayout rootView;

    @NonNull
    public final MarqueeRecyclerView rvComicschapterImgs;

    @NonNull
    public final RecyclerView rvListAdImg;

    @NonNull
    public final View titleDivider;

    @NonNull
    public final RelativeLayout titleLayoutComicsview;

    @NonNull
    public final TextView tvChapterAll;

    @NonNull
    public final TextView tvChapterAuto;

    @NonNull
    public final TextView tvChapterContenttable;

    @NonNull
    public final TextView tvChapterCurrent;

    @NonNull
    public final TextView tvChapterHorizontal;

    @NonNull
    public final TextView tvChapterVertical;

    @NonNull
    public final TextView tvNameComics;

    @NonNull
    public final TextView tvTitleRight;

    private ActComicschapterViewBinding(@NonNull LinearLayout linearLayout, @NonNull AdBottomBarView adBottomBarView, @NonNull RelativeLayout relativeLayout, @NonNull RelativeLayout relativeLayout2, @NonNull RelativeLayout relativeLayout3, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull ImageView imageView4, @NonNull ImageView imageView5, @NonNull FrameLayout frameLayout, @NonNull ConstraintLayout constraintLayout, @NonNull SeekBar seekBar, @NonNull MarqueeRecyclerView marqueeRecyclerView, @NonNull RecyclerView recyclerView, @NonNull View view, @NonNull RelativeLayout relativeLayout4, @NonNull TextView textView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull TextView textView8) {
        this.rootView = linearLayout;
        this.adBar = adBottomBarView;
        this.btnTitleBack = relativeLayout;
        this.btnTitleRight = relativeLayout2;
        this.btnTitleRightIcon = relativeLayout3;
        this.ivTitleLeftIcon = imageView;
        this.ivTitleRightIcon = imageView2;
        this.ivTopPlace = imageView3;
        this.ivViewLast = imageView4;
        this.ivViewNext = imageView5;
        this.llComicschapterviewBottom = frameLayout;
        this.llComicsviewContent = constraintLayout;
        this.progressComicschapter = seekBar;
        this.rvComicschapterImgs = marqueeRecyclerView;
        this.rvListAdImg = recyclerView;
        this.titleDivider = view;
        this.titleLayoutComicsview = relativeLayout4;
        this.tvChapterAll = textView;
        this.tvChapterAuto = textView2;
        this.tvChapterContenttable = textView3;
        this.tvChapterCurrent = textView4;
        this.tvChapterHorizontal = textView5;
        this.tvChapterVertical = textView6;
        this.tvNameComics = textView7;
        this.tvTitleRight = textView8;
    }

    @NonNull
    public static ActComicschapterViewBinding bind(@NonNull View view) {
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
                        i2 = R.id.iv_titleLeftIcon;
                        ImageView imageView = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
                        if (imageView != null) {
                            i2 = R.id.iv_titleRightIcon;
                            ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_titleRightIcon);
                            if (imageView2 != null) {
                                i2 = R.id.iv_top_place;
                                ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_top_place);
                                if (imageView3 != null) {
                                    i2 = R.id.iv_view_last;
                                    ImageView imageView4 = (ImageView) view.findViewById(R.id.iv_view_last);
                                    if (imageView4 != null) {
                                        i2 = R.id.iv_view_next;
                                        ImageView imageView5 = (ImageView) view.findViewById(R.id.iv_view_next);
                                        if (imageView5 != null) {
                                            i2 = R.id.ll_comicschapterview_bottom;
                                            FrameLayout frameLayout = (FrameLayout) view.findViewById(R.id.ll_comicschapterview_bottom);
                                            if (frameLayout != null) {
                                                i2 = R.id.ll_comicsview_content;
                                                ConstraintLayout constraintLayout = (ConstraintLayout) view.findViewById(R.id.ll_comicsview_content);
                                                if (constraintLayout != null) {
                                                    i2 = R.id.progress_comicschapter;
                                                    SeekBar seekBar = (SeekBar) view.findViewById(R.id.progress_comicschapter);
                                                    if (seekBar != null) {
                                                        i2 = R.id.rv_comicschapter_imgs;
                                                        MarqueeRecyclerView marqueeRecyclerView = (MarqueeRecyclerView) view.findViewById(R.id.rv_comicschapter_imgs);
                                                        if (marqueeRecyclerView != null) {
                                                            i2 = R.id.rv_list_adImg;
                                                            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_list_adImg);
                                                            if (recyclerView != null) {
                                                                i2 = R.id.title_divider;
                                                                View findViewById = view.findViewById(R.id.title_divider);
                                                                if (findViewById != null) {
                                                                    i2 = R.id.title_layout_comicsview;
                                                                    RelativeLayout relativeLayout4 = (RelativeLayout) view.findViewById(R.id.title_layout_comicsview);
                                                                    if (relativeLayout4 != null) {
                                                                        i2 = R.id.tv_chapter_all;
                                                                        TextView textView = (TextView) view.findViewById(R.id.tv_chapter_all);
                                                                        if (textView != null) {
                                                                            i2 = R.id.tv_chapter_auto;
                                                                            TextView textView2 = (TextView) view.findViewById(R.id.tv_chapter_auto);
                                                                            if (textView2 != null) {
                                                                                i2 = R.id.tv_chapter_contenttable;
                                                                                TextView textView3 = (TextView) view.findViewById(R.id.tv_chapter_contenttable);
                                                                                if (textView3 != null) {
                                                                                    i2 = R.id.tv_chapter_current;
                                                                                    TextView textView4 = (TextView) view.findViewById(R.id.tv_chapter_current);
                                                                                    if (textView4 != null) {
                                                                                        i2 = R.id.tv_chapter_horizontal;
                                                                                        TextView textView5 = (TextView) view.findViewById(R.id.tv_chapter_horizontal);
                                                                                        if (textView5 != null) {
                                                                                            i2 = R.id.tv_chapter_vertical;
                                                                                            TextView textView6 = (TextView) view.findViewById(R.id.tv_chapter_vertical);
                                                                                            if (textView6 != null) {
                                                                                                i2 = R.id.tv_name_comics;
                                                                                                TextView textView7 = (TextView) view.findViewById(R.id.tv_name_comics);
                                                                                                if (textView7 != null) {
                                                                                                    i2 = R.id.tv_titleRight;
                                                                                                    TextView textView8 = (TextView) view.findViewById(R.id.tv_titleRight);
                                                                                                    if (textView8 != null) {
                                                                                                        return new ActComicschapterViewBinding((LinearLayout) view, adBottomBarView, relativeLayout, relativeLayout2, relativeLayout3, imageView, imageView2, imageView3, imageView4, imageView5, frameLayout, constraintLayout, seekBar, marqueeRecyclerView, recyclerView, findViewById, relativeLayout4, textView, textView2, textView3, textView4, textView5, textView6, textView7, textView8);
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
    public static ActComicschapterViewBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActComicschapterViewBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_comicschapter_view, viewGroup, false);
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
