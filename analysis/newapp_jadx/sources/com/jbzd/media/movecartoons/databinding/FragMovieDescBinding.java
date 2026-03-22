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
import androidx.core.widget.NestedScrollView;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.viewgroup.RecyclerViewH;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class FragMovieDescBinding implements ViewBinding {

    @NonNull
    public final Banner banner;

    @NonNull
    public final ScaleRelativeLayout bannerParent;

    @NonNull
    public final ImageView imgMore;

    @NonNull
    public final ImageTextView itvClickNum;

    @NonNull
    public final ImageTextView itvComicsdetialCommentnum;

    @NonNull
    public final ImageTextView itvDislike;

    @NonNull
    public final ImageTextView itvDownload;

    @NonNull
    public final ImageTextView itvFavorite;

    @NonNull
    public final ImageTextView itvHeaderMore;

    @NonNull
    public final ImageTextView itvLike;

    @NonNull
    public final ImageTextView itvShare;

    @NonNull
    public final LinearLayout llDownloadMoviedetail;

    @NonNull
    public final LinearLayout llFavoriteMoviedetal;

    @NonNull
    public final TextView llFooterChangeBottom;

    @NonNull
    public final LinearLayout llLikeMoviedetail;

    @NonNull
    public final LinearLayout llMoviedetalComment;

    @NonNull
    public final LinearLayout llMoviedetalPlay;

    @NonNull
    public final LinearLayout llShareMoviedetail;

    @NonNull
    public final LinearLayout llXuanjiMore;

    @NonNull
    public final RelativeLayout rlLuPoint;

    @NonNull
    public final RelativeLayout rlPictures;

    @NonNull
    public final LinearLayout rlVideoBottomParent;

    @NonNull
    private final RelativeLayout rootView;

    @NonNull
    public final RecyclerView rvAds;

    @NonNull
    public final RecyclerView rvContentRecommend;

    @NonNull
    public final RecyclerView rvMovieMorelink;

    @NonNull
    public final RecyclerViewH rvPictures;

    @NonNull
    public final RecyclerView rvTag;

    @NonNull
    public final NestedScrollView scrollBottom;

    @NonNull
    public final TextView textDescript;

    @NonNull
    public final TextView tvDesc;

    @NonNull
    public final TextView tvMore;

    @NonNull
    public final TextView tvMorelinksCount;

    @NonNull
    public final TextView tvVideodetailClick;

    @NonNull
    public final TextView tvVideodetailName;

    private FragMovieDescBinding(@NonNull RelativeLayout relativeLayout, @NonNull Banner banner, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull ImageView imageView, @NonNull ImageTextView imageTextView, @NonNull ImageTextView imageTextView2, @NonNull ImageTextView imageTextView3, @NonNull ImageTextView imageTextView4, @NonNull ImageTextView imageTextView5, @NonNull ImageTextView imageTextView6, @NonNull ImageTextView imageTextView7, @NonNull ImageTextView imageTextView8, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull TextView textView, @NonNull LinearLayout linearLayout3, @NonNull LinearLayout linearLayout4, @NonNull LinearLayout linearLayout5, @NonNull LinearLayout linearLayout6, @NonNull LinearLayout linearLayout7, @NonNull RelativeLayout relativeLayout2, @NonNull RelativeLayout relativeLayout3, @NonNull LinearLayout linearLayout8, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2, @NonNull RecyclerView recyclerView3, @NonNull RecyclerViewH recyclerViewH, @NonNull RecyclerView recyclerView4, @NonNull NestedScrollView nestedScrollView, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4, @NonNull TextView textView5, @NonNull TextView textView6, @NonNull TextView textView7) {
        this.rootView = relativeLayout;
        this.banner = banner;
        this.bannerParent = scaleRelativeLayout;
        this.imgMore = imageView;
        this.itvClickNum = imageTextView;
        this.itvComicsdetialCommentnum = imageTextView2;
        this.itvDislike = imageTextView3;
        this.itvDownload = imageTextView4;
        this.itvFavorite = imageTextView5;
        this.itvHeaderMore = imageTextView6;
        this.itvLike = imageTextView7;
        this.itvShare = imageTextView8;
        this.llDownloadMoviedetail = linearLayout;
        this.llFavoriteMoviedetal = linearLayout2;
        this.llFooterChangeBottom = textView;
        this.llLikeMoviedetail = linearLayout3;
        this.llMoviedetalComment = linearLayout4;
        this.llMoviedetalPlay = linearLayout5;
        this.llShareMoviedetail = linearLayout6;
        this.llXuanjiMore = linearLayout7;
        this.rlLuPoint = relativeLayout2;
        this.rlPictures = relativeLayout3;
        this.rlVideoBottomParent = linearLayout8;
        this.rvAds = recyclerView;
        this.rvContentRecommend = recyclerView2;
        this.rvMovieMorelink = recyclerView3;
        this.rvPictures = recyclerViewH;
        this.rvTag = recyclerView4;
        this.scrollBottom = nestedScrollView;
        this.textDescript = textView2;
        this.tvDesc = textView3;
        this.tvMore = textView4;
        this.tvMorelinksCount = textView5;
        this.tvVideodetailClick = textView6;
        this.tvVideodetailName = textView7;
    }

    @NonNull
    public static FragMovieDescBinding bind(@NonNull View view) {
        int i2 = R.id.banner;
        Banner banner = (Banner) view.findViewById(R.id.banner);
        if (banner != null) {
            i2 = R.id.banner_parent;
            ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.banner_parent);
            if (scaleRelativeLayout != null) {
                i2 = R.id.img_more;
                ImageView imageView = (ImageView) view.findViewById(R.id.img_more);
                if (imageView != null) {
                    i2 = R.id.itv_click_num;
                    ImageTextView imageTextView = (ImageTextView) view.findViewById(R.id.itv_click_num);
                    if (imageTextView != null) {
                        i2 = R.id.itv_comicsdetial_commentnum;
                        ImageTextView imageTextView2 = (ImageTextView) view.findViewById(R.id.itv_comicsdetial_commentnum);
                        if (imageTextView2 != null) {
                            i2 = R.id.itv_dislike;
                            ImageTextView imageTextView3 = (ImageTextView) view.findViewById(R.id.itv_dislike);
                            if (imageTextView3 != null) {
                                i2 = R.id.itv_download;
                                ImageTextView imageTextView4 = (ImageTextView) view.findViewById(R.id.itv_download);
                                if (imageTextView4 != null) {
                                    i2 = R.id.itv_favorite;
                                    ImageTextView imageTextView5 = (ImageTextView) view.findViewById(R.id.itv_favorite);
                                    if (imageTextView5 != null) {
                                        i2 = R.id.itv_header_more;
                                        ImageTextView imageTextView6 = (ImageTextView) view.findViewById(R.id.itv_header_more);
                                        if (imageTextView6 != null) {
                                            i2 = R.id.itv_like;
                                            ImageTextView imageTextView7 = (ImageTextView) view.findViewById(R.id.itv_like);
                                            if (imageTextView7 != null) {
                                                i2 = R.id.itv_share;
                                                ImageTextView imageTextView8 = (ImageTextView) view.findViewById(R.id.itv_share);
                                                if (imageTextView8 != null) {
                                                    i2 = R.id.ll_download_moviedetail;
                                                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_download_moviedetail);
                                                    if (linearLayout != null) {
                                                        i2 = R.id.ll_favorite_moviedetal;
                                                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_favorite_moviedetal);
                                                        if (linearLayout2 != null) {
                                                            i2 = R.id.ll_footer_change_bottom;
                                                            TextView textView = (TextView) view.findViewById(R.id.ll_footer_change_bottom);
                                                            if (textView != null) {
                                                                i2 = R.id.ll_like_moviedetail;
                                                                LinearLayout linearLayout3 = (LinearLayout) view.findViewById(R.id.ll_like_moviedetail);
                                                                if (linearLayout3 != null) {
                                                                    i2 = R.id.ll_moviedetal_comment;
                                                                    LinearLayout linearLayout4 = (LinearLayout) view.findViewById(R.id.ll_moviedetal_comment);
                                                                    if (linearLayout4 != null) {
                                                                        i2 = R.id.ll_moviedetal_play;
                                                                        LinearLayout linearLayout5 = (LinearLayout) view.findViewById(R.id.ll_moviedetal_play);
                                                                        if (linearLayout5 != null) {
                                                                            i2 = R.id.ll_share_moviedetail;
                                                                            LinearLayout linearLayout6 = (LinearLayout) view.findViewById(R.id.ll_share_moviedetail);
                                                                            if (linearLayout6 != null) {
                                                                                i2 = R.id.ll_xuanji_more;
                                                                                LinearLayout linearLayout7 = (LinearLayout) view.findViewById(R.id.ll_xuanji_more);
                                                                                if (linearLayout7 != null) {
                                                                                    i2 = R.id.rl_lu_point;
                                                                                    RelativeLayout relativeLayout = (RelativeLayout) view.findViewById(R.id.rl_lu_point);
                                                                                    if (relativeLayout != null) {
                                                                                        i2 = R.id.rl_pictures;
                                                                                        RelativeLayout relativeLayout2 = (RelativeLayout) view.findViewById(R.id.rl_pictures);
                                                                                        if (relativeLayout2 != null) {
                                                                                            i2 = R.id.rl_videoBottomParent;
                                                                                            LinearLayout linearLayout8 = (LinearLayout) view.findViewById(R.id.rl_videoBottomParent);
                                                                                            if (linearLayout8 != null) {
                                                                                                i2 = R.id.rvAds;
                                                                                                RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rvAds);
                                                                                                if (recyclerView != null) {
                                                                                                    i2 = R.id.rv_content_recommend;
                                                                                                    RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_content_recommend);
                                                                                                    if (recyclerView2 != null) {
                                                                                                        i2 = R.id.rv_movie_morelink;
                                                                                                        RecyclerView recyclerView3 = (RecyclerView) view.findViewById(R.id.rv_movie_morelink);
                                                                                                        if (recyclerView3 != null) {
                                                                                                            i2 = R.id.rv_pictures;
                                                                                                            RecyclerViewH recyclerViewH = (RecyclerViewH) view.findViewById(R.id.rv_pictures);
                                                                                                            if (recyclerViewH != null) {
                                                                                                                i2 = R.id.rv_tag;
                                                                                                                RecyclerView recyclerView4 = (RecyclerView) view.findViewById(R.id.rv_tag);
                                                                                                                if (recyclerView4 != null) {
                                                                                                                    i2 = R.id.scroll_bottom;
                                                                                                                    NestedScrollView nestedScrollView = (NestedScrollView) view.findViewById(R.id.scroll_bottom);
                                                                                                                    if (nestedScrollView != null) {
                                                                                                                        i2 = R.id.text_descript;
                                                                                                                        TextView textView2 = (TextView) view.findViewById(R.id.text_descript);
                                                                                                                        if (textView2 != null) {
                                                                                                                            i2 = R.id.tv_desc;
                                                                                                                            TextView textView3 = (TextView) view.findViewById(R.id.tv_desc);
                                                                                                                            if (textView3 != null) {
                                                                                                                                i2 = R.id.tv_more;
                                                                                                                                TextView textView4 = (TextView) view.findViewById(R.id.tv_more);
                                                                                                                                if (textView4 != null) {
                                                                                                                                    i2 = R.id.tv_morelinks_count;
                                                                                                                                    TextView textView5 = (TextView) view.findViewById(R.id.tv_morelinks_count);
                                                                                                                                    if (textView5 != null) {
                                                                                                                                        i2 = R.id.tv_videodetail_click;
                                                                                                                                        TextView textView6 = (TextView) view.findViewById(R.id.tv_videodetail_click);
                                                                                                                                        if (textView6 != null) {
                                                                                                                                            i2 = R.id.tv_videodetail_name;
                                                                                                                                            TextView textView7 = (TextView) view.findViewById(R.id.tv_videodetail_name);
                                                                                                                                            if (textView7 != null) {
                                                                                                                                                return new FragMovieDescBinding((RelativeLayout) view, banner, scaleRelativeLayout, imageView, imageTextView, imageTextView2, imageTextView3, imageTextView4, imageTextView5, imageTextView6, imageTextView7, imageTextView8, linearLayout, linearLayout2, textView, linearLayout3, linearLayout4, linearLayout5, linearLayout6, linearLayout7, relativeLayout, relativeLayout2, linearLayout8, recyclerView, recyclerView2, recyclerView3, recyclerViewH, recyclerView4, nestedScrollView, textView2, textView3, textView4, textView5, textView6, textView7);
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
    public static FragMovieDescBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragMovieDescBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_movie_desc, viewGroup, false);
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
