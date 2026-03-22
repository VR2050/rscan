package com.jbzd.media.movecartoons.databinding;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.widget.NestedScrollView;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.youth.banner.Banner;

/* loaded from: classes2.dex */
public final class FragComicsDetailinfosBinding implements ViewBinding {

    @NonNull
    public final Banner bannerComics;

    @NonNull
    public final ScaleRelativeLayout bannerParentComics;

    @NonNull
    public final TextView ivChapterdetailMore;

    @NonNull
    public final LinearLayout llFooterChangeBottom;

    @NonNull
    public final LinearLayout llShowallChapter;

    @NonNull
    private final NestedScrollView rootView;

    @NonNull
    public final RecyclerView rvBannerIcoComicsdetail;

    @NonNull
    public final RecyclerView rvRelatedItems;

    @NonNull
    public final RecyclerView rvSeetoseeBottom;

    @NonNull
    public final NestedScrollView scrollBottom;

    @NonNull
    public final TextView tvBannerBottom;

    @NonNull
    public final TextView tvBannerTop;

    @NonNull
    public final TextView tvTablecontentSubtitle;

    private FragComicsDetailinfosBinding(@NonNull NestedScrollView nestedScrollView, @NonNull Banner banner, @NonNull ScaleRelativeLayout scaleRelativeLayout, @NonNull TextView textView, @NonNull LinearLayout linearLayout, @NonNull LinearLayout linearLayout2, @NonNull RecyclerView recyclerView, @NonNull RecyclerView recyclerView2, @NonNull RecyclerView recyclerView3, @NonNull NestedScrollView nestedScrollView2, @NonNull TextView textView2, @NonNull TextView textView3, @NonNull TextView textView4) {
        this.rootView = nestedScrollView;
        this.bannerComics = banner;
        this.bannerParentComics = scaleRelativeLayout;
        this.ivChapterdetailMore = textView;
        this.llFooterChangeBottom = linearLayout;
        this.llShowallChapter = linearLayout2;
        this.rvBannerIcoComicsdetail = recyclerView;
        this.rvRelatedItems = recyclerView2;
        this.rvSeetoseeBottom = recyclerView3;
        this.scrollBottom = nestedScrollView2;
        this.tvBannerBottom = textView2;
        this.tvBannerTop = textView3;
        this.tvTablecontentSubtitle = textView4;
    }

    @NonNull
    public static FragComicsDetailinfosBinding bind(@NonNull View view) {
        int i2 = R.id.banner_comics;
        Banner banner = (Banner) view.findViewById(R.id.banner_comics);
        if (banner != null) {
            i2 = R.id.banner_parent_comics;
            ScaleRelativeLayout scaleRelativeLayout = (ScaleRelativeLayout) view.findViewById(R.id.banner_parent_comics);
            if (scaleRelativeLayout != null) {
                i2 = R.id.iv_chapterdetail_more;
                TextView textView = (TextView) view.findViewById(R.id.iv_chapterdetail_more);
                if (textView != null) {
                    i2 = R.id.ll_footer_change_bottom;
                    LinearLayout linearLayout = (LinearLayout) view.findViewById(R.id.ll_footer_change_bottom);
                    if (linearLayout != null) {
                        i2 = R.id.ll_showall_chapter;
                        LinearLayout linearLayout2 = (LinearLayout) view.findViewById(R.id.ll_showall_chapter);
                        if (linearLayout2 != null) {
                            i2 = R.id.rv_banner_ico_comicsdetail;
                            RecyclerView recyclerView = (RecyclerView) view.findViewById(R.id.rv_banner_ico_comicsdetail);
                            if (recyclerView != null) {
                                i2 = R.id.rv_related_items;
                                RecyclerView recyclerView2 = (RecyclerView) view.findViewById(R.id.rv_related_items);
                                if (recyclerView2 != null) {
                                    i2 = R.id.rv_seetosee_bottom;
                                    RecyclerView recyclerView3 = (RecyclerView) view.findViewById(R.id.rv_seetosee_bottom);
                                    if (recyclerView3 != null) {
                                        NestedScrollView nestedScrollView = (NestedScrollView) view;
                                        i2 = R.id.tv_banner_bottom;
                                        TextView textView2 = (TextView) view.findViewById(R.id.tv_banner_bottom);
                                        if (textView2 != null) {
                                            i2 = R.id.tv_banner_top;
                                            TextView textView3 = (TextView) view.findViewById(R.id.tv_banner_top);
                                            if (textView3 != null) {
                                                i2 = R.id.tv_tablecontent_subtitle;
                                                TextView textView4 = (TextView) view.findViewById(R.id.tv_tablecontent_subtitle);
                                                if (textView4 != null) {
                                                    return new FragComicsDetailinfosBinding(nestedScrollView, banner, scaleRelativeLayout, textView, linearLayout, linearLayout2, recyclerView, recyclerView2, recyclerView3, nestedScrollView, textView2, textView3, textView4);
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
    public static FragComicsDetailinfosBinding inflate(@NonNull LayoutInflater layoutInflater) {
        return inflate(layoutInflater, null, false);
    }

    @NonNull
    public static FragComicsDetailinfosBinding inflate(@NonNull LayoutInflater layoutInflater, @Nullable ViewGroup viewGroup, boolean z) {
        View inflate = layoutInflater.inflate(R.layout.frag_comics_detailinfos, viewGroup, false);
        if (z) {
            viewGroup.addView(inflate);
        }
        return bind(inflate);
    }

    @Override // androidx.viewbinding.ViewBinding
    @NonNull
    public NestedScrollView getRoot() {
        return this.rootView;
    }
}
