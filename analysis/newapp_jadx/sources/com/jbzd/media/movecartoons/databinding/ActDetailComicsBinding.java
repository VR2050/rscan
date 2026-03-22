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
import androidx.appcompat.widget.AppCompatEditText;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.view.FollowTextView;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.qnmd.adnnm.da0yzo.R;

/* loaded from: classes2.dex */
public final class ActDetailComicsBinding implements ViewBinding {

    @NonNull
    public final TextView accIdPosthome;

    @NonNull
    public final AppBarLayout appBarLayoutComicsdetail;

    @NonNull
    public final RelativeLayout btnTitleBack;

    @NonNull
    public final RelativeLayout btnTitleRight;

    @NonNull
    public final RelativeLayout btnTitleRightIcon;

    @NonNull
    public final CircleImageView civHeadPosthome;

    @NonNull
    public final AppCompatEditText edInputCommentComics;

    @NonNull
    public final TextView fansPosthome;

    @NonNull
    public final TextView followsPosthome;

    @NonNull
    public final ImageTextView itvConfirmPost;

    @NonNull
    public final ImageTextView itvFavorite;

    @NonNull
    public final ShapeableImageView ivComicsdetailImg;

    @NonNull
    public final ImageView ivComicsdetailTop;

    @NonNull
    public final ImageView ivDetailNovelAudio;

    @NonNull
    public final ImageView ivSexPosthome;

    @NonNull
    public final ImageView ivTitleLeftIcon;

    @NonNull
    public final ImageView ivTitleRightIcon;

    @NonNull
    public final LinearLayout llComicsdetailBottom;

    @NonNull
    public final LinearLayout llComicsdetailbottomCommentInput;

    @NonNull
    public final LinearLayout llComicsdetailbottomFavorite;

    @NonNull
    public final LinearLayout llComicsdetailbottomStartview;

    @NonNull
    public final LinearLayout llMineInfo;

    @NonNull
    public final LinearLayout llMyTitle;

    @NonNull
    public final LinearLayout llTop;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final RecyclerView rvTag;

    @NonNull
    public final ImageView srcSexLeftline;

    @NonNull
    public final SlidingTabLayout tablayoutComicsdetail;

    @NonNull
    public final View titleDivider;

    @NonNull
    public final RelativeLayout titleLayoutComicsdetailtop;

    @NonNull
    public final TextView tvClickFavorite;

    @NonNull
    public final TextView tvComicsdetailCategory;

    @NonNull
    public final TextView tvComicsdetailChaptercount;

    @NonNull
    public final TextView tvComicsdetailDescription;

    @NonNull
    public final FollowTextView tvComicsdetailFavorite;

    @NonNull
    public final TextView tvComicsdetailName;

    @NonNull
    public final TextView tvComicsdetailbottomFavorite;

    @NonNull
    public final TextView tvReadStart;

    @NonNull
    public final TextView tvTitle;

    @NonNull
    public final TextView tvTitleRight;

    @NonNull
    public final ViewPager vpComicsdetail;

    private ActDetailComicsBinding(@NonNull RelativeLayout relativeLayout, @NonNull TextView textView, @NonNull AppBarLayout appBarLayout, @NonNull RelativeLayout relativeLayout2, @NonNull RelativeLayout relativeLayout3, @NonNull RelativeLayout relativeLayout4, @NonNull CircleImageView circleImageView, @NonNull AppCompatEditText appCompatEditText, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ShapeableImageView shapeableImageView, @NonNull ImageView imageView, @NonNull ImageView imageView2, @NonNull ImageView imageView3, @NonNull ImageView imageView4, @NonNull ImageView imageView5, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull LinearLayout linearLayout6, @NonNull LinearLayout linearLayout7, @NonNull RecyclerView recyclerView, @NonNull ImageView imageView6, @NonNull SlidingTabLayout slidingTabLayout, @NonNull View view, @NonNull RelativeLayout relativeLayout5, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7, @NonNull FollowTextView followTextView, @NonNull TextView textView8, @NonNull TextView textView9, @NonNull TextView textView10, @NonNull TextView textView11, @NonNull TextView textView12, @NonNull ViewPager viewPager) {
        this.rootView = relativeLayout;
        this.accIdPosthome = textView;
        this.appBarLayoutComicsdetail = appBarLayout;
        this.btnTitleBack = relativeLayout2;
        this.btnTitleRight = relativeLayout3;
        this.btnTitleRightIcon = relativeLayout4;
        this.civHeadPosthome = circleImageView;
        this.edInputCommentComics = appCompatEditText;
        this.fansPosthome = textView2;
        this.followsPosthome = textView3;
        this.itvConfirmPost = imageTextView;
        this.itvFavorite = imageTextView2;
        this.ivComicsdetailImg = shapeableImageView;
        this.ivComicsdetailTop = imageView;
        this.ivDetailNovelAudio = imageView2;
        this.ivSexPosthome = imageView3;
        this.ivTitleLeftIcon = imageView4;
        this.ivTitleRightIcon = imageView5;
        this.llComicsdetailBottom = linearLayout;
        this.llComicsdetailbottomCommentInput = linearLayout2;
        this.llComicsdetailbottomFavorite = linearLayout3;
        this.llComicsdetailbottomStartview = linearLayout4;
        this.llMineInfo = linearLayout5;
        this.llMyTitle = linearLayout6;
        this.llTop = linearLayout7;
        this.rvTag = recyclerView;
        this.srcSexLeftline = imageView6;
        this.tablayoutComicsdetail = slidingTabLayout;
        this.titleDivider = view;
        this.titleLayoutComicsdetailtop = relativeLayout5;
        this.tvClickFavorite = textView4;
        this.tvComicsdetailCategory = textView5;
        this.tvComicsdetailChaptercount = textView6;
        this.tvComicsdetailDescription = textView7;
        this.tvComicsdetailFavorite = followTextView;
        this.tvComicsdetailName = textView8;
        this.tvComicsdetailbottomFavorite = textView9;
        this.tvReadStart = textView10;
        this.tvTitle = textView11;
        this.tvTitleRight = textView12;
        this.vpComicsdetail = viewPager;
    }

    @NonNull
    public static ActDetailComicsBinding bind(@NonNull View view) {
        int i2 = R.id.acc_id_posthome;
        TextView textView = (TextView) view.findViewById(R.id.acc_id_posthome);
        if (textView != null) {
            i2 = R.id.app_bar_layout_comicsdetail;
            AppBarLayout appBarLayout = (AppBarLayout) view.findViewById(R.id.app_bar_layout_comicsdetail);
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
                                i2 = R.id.ed_input_comment_comics;
                                AppCompatEditText appCompatEditText = (AppCompatEditText) view.findViewById(R.id.ed_input_comment_comics);
                                if (appCompatEditText != null) {
                                    i2 = R.id.fans_posthome;
                                    TextView textView2 = (TextView) view.findViewById(R.id.fans_posthome);
                                    if (textView2 != null) {
                                        i2 = R.id.follows_posthome;
                                        TextView textView3 = (TextView) view.findViewById(R.id.follows_posthome);
                                        if (textView3 != null) {
                                            i2 = R.id.itv_confirm_post;
                                            ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_confirm_post);
                                            if (imageTextView != null) {
                                                i2 = R.id.itv_favorite;
                                                ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_favorite);
                                                if (imageTextView2 != null) {
                                                    i2 = R.id.iv_comicsdetail_img;
                                                    ShapeableImageView shapeableImageView = (ShapeableImageView) view.findViewById(R.id.iv_comicsdetail_img);
                                                    if (shapeableImageView != null) {
                                                        i2 = R.id.iv_comicsdetail_top;
                                                        ImageView imageView = (ImageView) view.findViewById(R.id.iv_comicsdetail_top);
                                                        if (imageView != null) {
                                                            i2 = R.id.iv_detail_novel_audio;
                                                            ImageView imageView2 = (ImageView) view.findViewById(R.id.iv_detail_novel_audio);
                                                            if (imageView2 != null) {
                                                                i2 = R.id.iv_sex_posthome;
                                                                ImageView imageView3 = (ImageView) view.findViewById(R.id.iv_sex_posthome);
                                                                if (imageView3 != null) {
                                                                    i2 = R.id.iv_titleLeftIcon;
                                                                    ImageView imageView4 = (ImageView) view.findViewById(R.id.iv_titleLeftIcon);
                                                                    if (imageView4 != null) {
                                                                        i2 = R.id.iv_titleRightIcon;
                                                                        ImageView imageView5 = (ImageView) view.findViewById(R.id.iv_titleRightIcon);
                                                                        if (imageView5 != null) {
                                                                            i2 = R.id.ll_comicsdetail_bottom;
                                                                            LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_comicsdetail_bottom);
                                                                            if (linearLayout != null) {
                                                                                i2 = R.id.ll_comicsdetailbottom_comment_input;
                                                                                LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_comicsdetailbottom_comment_input);
                                                                                if (linearLayout2 != null) {
                                                                                    i2 = R.id.ll_comicsdetailbottom_favorite;
                                                                                    LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_comicsdetailbottom_favorite);
                                                                                    if (linearLayout3 != null) {
                                                                                        i2 = R.id.ll_comicsdetailbottom_startview;
                                                                                        LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_comicsdetailbottom_startview);
                                                                                        if (linearLayout4 != null) {
                                                                                            i2 = R.id.ll_mine_info;
                                                                                            LinearLayout linearLayout5 = (LinearLayout) view.findViewById(R.id.ll_mine_info);
                                                                                            if (linearLayout5 != null) {
                                                                                                i2 = R.id.ll_my_title;
                                                                                                LinearLayout linearLayout6 = (LinearLayout) view.findViewById(R.id.ll_my_title);
                                                                                                if (linearLayout6 != null) {
                                                                                                    i2 = R.id.ll_top;
                                                                                                    LinearLayout linearLayout7 = (LinearLayout) view.findViewById(R.id.ll_top);
                                                                                                    if (linearLayout7 != null) {
                                                                                                        i2 = R.id.rv_tag;
                                                                                                        RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_tag);
                                                                                                        if (recyclerView != null) {
                                                                                                            i2 = R.id.src_sex_leftline;
                                                                                                            ImageView imageView6 = (ImageView) view.findViewById(R.id.src_sex_leftline);
                                                                                                            if (imageView6 != null) {
                                                                                                                i2 = R.id.tablayout_comicsdetail;
                                                                                                                SlidingTabLayout slidingTabLayout = (SlidingTabLayout) view.findViewById(R.id.tablayout_comicsdetail);
                                                                                                                if (slidingTabLayout != null) {
                                                                                                                    i2 = R.id.title_divider;
                                                                                                                    View findViewById = view.findViewById(R.id.title_divider);
                                                                                                                    if (findViewById != null) {
                                                                                                                        i2 = R.id.title_layout_comicsdetailtop;
                                                                                                                        RelativeLayout relativeLayout4 = (RelativeLayout) view.findViewById(R.id.title_layout_comicsdetailtop);
                                                                                                                        if (relativeLayout4 != null) {
                                                                                                                            i2 = R.id.tv_click_favorite;
                                                                                                                            TextView textView4 = (TextView) view.findViewById(R.id.tv_click_favorite);
                                                                                                                            if (textView4 != null) {
                                                                                                                                i2 = R.id.tv_comicsdetail_category;
                                                                                                                                TextView textView5 = (TextView) view.findViewById(R.id.tv_comicsdetail_category);
                                                                                                                                if (textView5 != null) {
                                                                                                                                    i2 = R.id.tv_comicsdetail_chaptercount;
                                                                                                                                    TextView textView6 = (TextView) view.findViewById(R.id.tv_comicsdetail_chaptercount);
                                                                                                                                    if (textView6 != null) {
                                                                                                                                        i2 = R.id.tv_comicsdetail_description;
                                                                                                                                        TextView textView7 = (TextView) view.findViewById(R.id.tv_comicsdetail_description);
                                                                                                                                        if (textView7 != null) {
                                                                                                                                            i2 = R.id.tv_comicsdetail_favorite;
                                                                                                                                            FollowTextView followTextView = (FollowTextView) view.findViewById(R.id.tv_comicsdetail_favorite);
                                                                                                                                            if (followTextView != null) {
                                                                                                                                                i2 = R.id.tv_comicsdetail_name;
                                                                                                                                                TextView textView8 = (TextView) view.findViewById(R.id.tv_comicsdetail_name);
                                                                                                                                                if (textView8 != null) {
                                                                                                                                                    i2 = R.id.tv_comicsdetailbottom_favorite;
                                                                                                                                                    TextView textView9 = (TextView) view.findViewById(R.id.tv_comicsdetailbottom_favorite);
                                                                                                                                                    if (textView9 != null) {
                                                                                                                                                        i2 = R.id.tv_read_start;
                                                                                                                                                        TextView textView10 = (TextView) view.findViewById(R.id.tv_read_start);
                                                                                                                                                        if (textView10 != null) {
                                                                                                                                                            i2 = R.id.tv_title;
                                                                                                                                                            TextView textView11 = (TextView) view.findViewById(R.id.tv_title);
                                                                                                                                                            if (textView11 != null) {
                                                                                                                                                                i2 = R.id.tv_titleRight;
                                                                                                                                                                TextView textView12 = (TextView) view.findViewById(R.id.tv_titleRight);
                                                                                                                                                                if (textView12 != null) {
                                                                                                                                                                    i2 = R.id.vp_comicsdetail;
                                                                                                                                                                    ViewPager viewPager = (ViewPager) view.findViewById(R.id.vp_comicsdetail);
                                                                                                                                                                    if (viewPager != null) {
                                                                                                                                                                        return new ActDetailComicsBinding((RelativeLayout) view, textView, appBarLayout, relativeLayout, relativeLayout2, relativeLayout3, circleImageView, appCompatEditText, textView2, textView3, imageTextView, imageTextView2, shapeableImageView, imageView, imageView2, imageView3, imageView4, imageView5, linearLayout, linearLayout2, linearLayout3, linearLayout4, linearLayout5, linearLayout6, linearLayout7, recyclerView, imageView6, slidingTabLayout, findViewById, relativeLayout4, textView4, textView5, textView6, textView7, followTextView, textView8, textView9, textView10, textView11, textView12, viewPager);
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
    public static ActDetailComicsBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static ActDetailComicsBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.act_detail_comics, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public RelativeLayout getRoot() {
        return this.rootView;
    }
}
