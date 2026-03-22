package com.jbzd.media.movecartoons.p396ui.movie;

import android.content.Context;
import android.os.Bundle;
import android.os.CountDownTimer;
import android.text.TextUtils;
import android.view.View;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.core.app.NotificationCompat;
import androidx.fragment.app.FragmentActivity;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.Observer;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.viewbinding.ViewBinding;
import com.drake.brv.BindingAdapter;
import com.drake.brv.annotaion.DividerOrientation;
import com.google.android.flexbox.FlexboxLayoutManager;
import com.jbzd.media.movecartoons.bean.event.EventMoviBottom;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import com.jbzd.media.movecartoons.bean.response.VideoDetailBean;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.databinding.ItemAppVerticalBinding;
import com.jbzd.media.movecartoons.p396ui.dialog.ChooseMultiLinksDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.ShareBottomSheetDialog;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDescFragment;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDescFragment$bottomSeeToSeeAdapter$2;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDescFragment$movieMoreLinksAdapter$2;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDescFragment$tagAdapter$2;
import com.jbzd.media.movecartoons.p396ui.movie.fragment.RecommendFragment;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp;
import com.jbzd.media.movecartoons.view.text.ImageTextView;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import com.youth.banner.Banner;
import com.youth.banner.indicator.RectangleIndicator;
import com.youth.banner.listener.OnBannerListener;
import com.youth.banner.listener.OnPageChangeListener;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0843e0;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p403d.p404a.p405a.p407b.p408a.C4195m;
import p476m.p496b.p497a.C4909c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000³\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\f\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0010\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0010\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\b\u000b\n\u0002\u0010\u000b\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0005*\u0005c\u0082\u0001\u008f\u0001\u0018\u0000 ¤\u00012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0002¤\u0001B\b¢\u0006\u0005\b£\u0001\u0010!J)\u0010\t\u001a\u00020\b2\u0010\b\u0002\u0010\u0005\u001a\n\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u00032\u0006\u0010\u0007\u001a\u00020\u0006H\u0002¢\u0006\u0004\b\t\u0010\nJ\u0017\u0010\r\u001a\u00020\u000b2\u0006\u0010\f\u001a\u00020\u000bH\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u0019\u0010\u0011\u001a\u00020\b2\b\u0010\u0010\u001a\u0004\u0018\u00010\u000fH\u0002¢\u0006\u0004\b\u0011\u0010\u0012J\u0017\u0010\u0014\u001a\u00020\b2\u0006\u0010\u0013\u001a\u00020\u000bH\u0002¢\u0006\u0004\b\u0014\u0010\u0015J\u001f\u0010\u0019\u001a\u00020\b2\u000e\u0010\u0018\u001a\n\u0012\u0004\u0012\u00020\u0017\u0018\u00010\u0016H\u0002¢\u0006\u0004\b\u0019\u0010\u001aJ\u0017\u0010\u001c\u001a\u00020\u000b2\u0006\u0010\u001b\u001a\u00020\u000bH\u0002¢\u0006\u0004\b\u001c\u0010\u000eJ\u000f\u0010\u001e\u001a\u00020\u001dH\u0016¢\u0006\u0004\b\u001e\u0010\u001fJ\u000f\u0010 \u001a\u00020\bH\u0016¢\u0006\u0004\b \u0010!J\u000f\u0010\"\u001a\u00020\bH\u0016¢\u0006\u0004\b\"\u0010!J\u000f\u0010#\u001a\u00020\bH\u0016¢\u0006\u0004\b#\u0010!J\u0017\u0010$\u001a\u00020\b2\b\u0010\u0010\u001a\u0004\u0018\u00010\u000f¢\u0006\u0004\b$\u0010\u0012R\u001d\u0010*\u001a\u00020%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b&\u0010'\u001a\u0004\b(\u0010)R\u001c\u0010+\u001a\u00020\u000b8\u0006@\u0006X\u0086D¢\u0006\f\n\u0004\b+\u0010,\u001a\u0004\b-\u0010.R\u001d\u00101\u001a\u00020%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b/\u0010'\u001a\u0004\b0\u0010)R%\u00106\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u0003028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b3\u0010'\u001a\u0004\b4\u00105R\u001d\u0010;\u001a\u0002078F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b8\u0010'\u001a\u0004\b9\u0010:R\u0018\u0010<\u001a\u0004\u0018\u00010\u001d8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b<\u0010=R\u001d\u0010B\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b?\u0010'\u001a\u0004\b@\u0010AR\u001d\u0010E\u001a\u0002078F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bC\u0010'\u001a\u0004\bD\u0010:R\u001d\u0010H\u001a\u00020\u000b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bF\u0010'\u001a\u0004\bG\u0010.R\u001d\u0010K\u001a\u0002078F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bI\u0010'\u001a\u0004\bJ\u0010:R\u001d\u0010N\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bL\u0010'\u001a\u0004\bM\u0010AR\u001d\u0010S\u001a\u00020O8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bP\u0010'\u001a\u0004\bQ\u0010RR\u001d\u0010V\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bT\u0010'\u001a\u0004\bU\u0010AR\u001d\u0010Y\u001a\u00020O8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bW\u0010'\u001a\u0004\bX\u0010RR\u0018\u0010[\u001a\u0004\u0018\u00010Z8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b[\u0010\\R\u001d\u0010_\u001a\u0002078F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b]\u0010'\u001a\u0004\b^\u0010:R\u001d\u0010b\u001a\u00020%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b`\u0010'\u001a\u0004\ba\u0010)R\u001d\u0010g\u001a\u00020c8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bd\u0010'\u001a\u0004\be\u0010fR\u001d\u0010l\u001a\u00020h8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bi\u0010'\u001a\u0004\bj\u0010kR\u001d\u0010o\u001a\u00020%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bm\u0010'\u001a\u0004\bn\u0010)R\u001d\u0010r\u001a\u00020O8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bp\u0010'\u001a\u0004\bq\u0010RR\u001d\u0010u\u001a\u00020%8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bs\u0010'\u001a\u0004\bt\u0010)R\u001d\u0010x\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bv\u0010'\u001a\u0004\bw\u0010AR\u0018\u0010z\u001a\u0004\u0018\u00010y8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bz\u0010{R\u001d\u0010~\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b|\u0010'\u001a\u0004\b}\u0010AR\u001f\u0010\u0081\u0001\u001a\u00020%8F@\u0006X\u0086\u0084\u0002¢\u0006\r\n\u0004\b\u007f\u0010'\u001a\u0005\b\u0080\u0001\u0010)R\"\u0010\u0086\u0001\u001a\u00030\u0082\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\b\u0083\u0001\u0010'\u001a\u0006\b\u0084\u0001\u0010\u0085\u0001R\"\u0010\u008b\u0001\u001a\u00030\u0087\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u0088\u0001\u0010'\u001a\u0006\b\u0089\u0001\u0010\u008a\u0001R \u0010\u008e\u0001\u001a\u00020O8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u008c\u0001\u0010'\u001a\u0005\b\u008d\u0001\u0010RR\"\u0010\u0093\u0001\u001a\u00030\u008f\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\b\u0090\u0001\u0010'\u001a\u0006\b\u0091\u0001\u0010\u0092\u0001R \u0010\u0096\u0001\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0094\u0001\u0010'\u001a\u0005\b\u0095\u0001\u0010AR \u0010\u0099\u0001\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0097\u0001\u0010'\u001a\u0005\b\u0098\u0001\u0010AR*\u0010\u009b\u0001\u001a\u00030\u009a\u00018\u0006@\u0006X\u0086\u000e¢\u0006\u0018\n\u0006\b\u009b\u0001\u0010\u009c\u0001\u001a\u0006\b\u009b\u0001\u0010\u009d\u0001\"\u0006\b\u009e\u0001\u0010\u009f\u0001R\u001c\u0010¡\u0001\u001a\u0005\u0018\u00010 \u00018\u0002@\u0002X\u0082\u000e¢\u0006\b\n\u0006\b¡\u0001\u0010¢\u0001¨\u0006¥\u0001"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/MovieDescFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean$MultiLinks;", "links", "Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsViewModel;", "viewModel", "", "showPaymentDialog", "(Ljava/util/List;Lcom/jbzd/media/movecartoons/ui/movie/MovieDetailsViewModel;)V", "", "love", "getShowLoveTxt", "(Ljava/lang/String;)Ljava/lang/String;", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "video", "initView", "(Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;)V", "category", "changeMoreTextColor", "(Ljava/lang/String;)V", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "mBanners", "initBannerView", "(Ljava/util/List;)V", "zan", "getFavorNum", "", "getLayout", "()I", "initViews", "()V", "onDestroyView", "initEvents", "showShareDialog", "Landroid/widget/LinearLayout;", "rl_videoBottomParent$delegate", "Lkotlin/Lazy;", "getRl_videoBottomParent", "()Landroid/widget/LinearLayout;", "rl_videoBottomParent", RecommendFragment.key_video_id, "Ljava/lang/String;", "getKey_video_id", "()Ljava/lang/String;", "ll_share_moviedetail$delegate", "getLl_share_moviedetail", "ll_share_moviedetail", "Lcom/youth/banner/Banner;", "banner$delegate", "getBanner", "()Lcom/youth/banner/Banner;", "banner", "Landroidx/recyclerview/widget/RecyclerView;", "rv_movie_morelink$delegate", "getRv_movie_morelink", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_movie_morelink", "mExpandHeight", "Ljava/lang/Integer;", "Landroid/widget/TextView;", "tv_morelinks_count$delegate", "getTv_morelinks_count", "()Landroid/widget/TextView;", "tv_morelinks_count", "rv_content_recommend$delegate", "getRv_content_recommend", "rv_content_recommend", "mVideoId$delegate", "getMVideoId", "mVideoId", "rvAds$delegate", "getRvAds", "rvAds", "tv_videodetail_click$delegate", "getTv_videodetail_click", "tv_videodetail_click", "Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_like$delegate", "getItv_like", "()Lcom/jbzd/media/movecartoons/view/text/ImageTextView;", "itv_like", "ll_footer_change_bottom$delegate", "getLl_footer_change_bottom", "ll_footer_change_bottom", "itv_favorite$delegate", "getItv_favorite", "itv_favorite", "Landroid/os/CountDownTimer;", "adTimer", "Landroid/os/CountDownTimer;", "rv_tag$delegate", "getRv_tag", "rv_tag", "ll_like_moviedetail$delegate", "getLl_like_moviedetail", "ll_like_moviedetail", "com/jbzd/media/movecartoons/ui/movie/MovieDescFragment$tagAdapter$2$1", "tagAdapter$delegate", "getTagAdapter", "()Lcom/jbzd/media/movecartoons/ui/movie/MovieDescFragment$tagAdapter$2$1;", "tagAdapter", "Landroid/widget/ImageView;", "img_more$delegate", "getImg_more", "()Landroid/widget/ImageView;", "img_more", "ll_download_moviedetail$delegate", "getLl_download_moviedetail", "ll_download_moviedetail", "itv_header_more$delegate", "getItv_header_more", "itv_header_more", "ll_xuanji_more$delegate", "getLl_xuanji_more", "ll_xuanji_more", "text_descript$delegate", "getText_descript", "text_descript", "Lcom/jbzd/media/movecartoons/ui/dialog/ShareBottomSheetDialog;", "mShareDialog", "Lcom/jbzd/media/movecartoons/ui/dialog/ShareBottomSheetDialog;", "tv_videodetail_name$delegate", "getTv_videodetail_name", "tv_videodetail_name", "ll_favorite_moviedetal$delegate", "getLl_favorite_moviedetal", "ll_favorite_moviedetal", "com/jbzd/media/movecartoons/ui/movie/MovieDescFragment$bottomSeeToSeeAdapter$2$1", "bottomSeeToSeeAdapter$delegate", "getBottomSeeToSeeAdapter", "()Lcom/jbzd/media/movecartoons/ui/movie/MovieDescFragment$bottomSeeToSeeAdapter$2$1;", "bottomSeeToSeeAdapter", "Lcom/jbzd/media/movecartoons/view/viewgroup/ScaleRelativeLayout;", "banner_parent$delegate", "getBanner_parent", "()Lcom/jbzd/media/movecartoons/view/viewgroup/ScaleRelativeLayout;", "banner_parent", "itv_dislike$delegate", "getItv_dislike", "itv_dislike", "com/jbzd/media/movecartoons/ui/movie/MovieDescFragment$movieMoreLinksAdapter$2$1", "movieMoreLinksAdapter$delegate", "getMovieMoreLinksAdapter", "()Lcom/jbzd/media/movecartoons/ui/movie/MovieDescFragment$movieMoreLinksAdapter$2$1;", "movieMoreLinksAdapter", "tv_more$delegate", "getTv_more", "tv_more", "tv_desc$delegate", "getTv_desc", "tv_desc", "", "isFirst", "Z", "()Z", "setFirst", "(Z)V", "Lcom/jbzd/media/movecartoons/ui/dialog/ChooseMultiLinksDialog;", "mChooseMultiLinksDialog", "Lcom/jbzd/media/movecartoons/ui/dialog/ChooseMultiLinksDialog;", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MovieDescFragment extends MyThemeFragment<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    public static Function1<? super String, Unit> listener;
    public static VideoDetailBean mVideoDetailBean;

    @Nullable
    private CountDownTimer adTimer;

    @Nullable
    private ChooseMultiLinksDialog mChooseMultiLinksDialog;

    @Nullable
    private Integer mExpandHeight;

    @Nullable
    private ShareBottomSheetDialog mShareDialog;

    @NotNull
    private final String key_video_id = RecommendFragment.key_video_id;
    private boolean isFirst = true;

    /* renamed from: mVideoId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mVideoId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$mVideoId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String string;
            Bundle arguments = MovieDescFragment.this.getArguments();
            return (arguments == null || (string = arguments.getString(MovieDescFragment.this.getKey_video_id())) == null) ? "" : string;
        }
    });

    /* renamed from: movieMoreLinksAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy movieMoreLinksAdapter = LazyKt__LazyJVMKt.lazy(new MovieDescFragment$movieMoreLinksAdapter$2(this));

    /* renamed from: tagAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tagAdapter = LazyKt__LazyJVMKt.lazy(new MovieDescFragment$tagAdapter$2(this));

    /* renamed from: rvAds$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rvAds = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$rvAds$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            View view = MovieDescFragment.this.getView();
            RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rvAds);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: rl_videoBottomParent$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rl_videoBottomParent = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$rl_videoBottomParent$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            View view = MovieDescFragment.this.getView();
            LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.rl_videoBottomParent);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: itv_favorite$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_favorite = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$itv_favorite$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = MovieDescFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_favorite);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_dislike$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_dislike = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$itv_dislike$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = MovieDescFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_dislike);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: itv_like$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_like = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$itv_like$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = MovieDescFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_like);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: bottomSeeToSeeAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy bottomSeeToSeeAdapter = LazyKt__LazyJVMKt.lazy(new MovieDescFragment$bottomSeeToSeeAdapter$2(this));

    /* renamed from: ll_footer_change_bottom$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_footer_change_bottom = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$ll_footer_change_bottom$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = MovieDescFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.ll_footer_change_bottom);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: rv_content_recommend$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_content_recommend = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$rv_content_recommend$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            View view = MovieDescFragment.this.getView();
            RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_content_recommend);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: tv_videodetail_name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_videodetail_name = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$tv_videodetail_name$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = MovieDescFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_videodetail_name);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_videodetail_click$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_videodetail_click = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$tv_videodetail_click$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = MovieDescFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_videodetail_click);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_desc$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_desc = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$tv_desc$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = MovieDescFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_desc);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: text_descript$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy text_descript = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$text_descript$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = MovieDescFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.text_descript);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: ll_download_moviedetail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_download_moviedetail = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$ll_download_moviedetail$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            View view = MovieDescFragment.this.getView();
            LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_download_moviedetail);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_favorite_moviedetal$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_favorite_moviedetal = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$ll_favorite_moviedetal$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            View view = MovieDescFragment.this.getView();
            LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_favorite_moviedetal);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_like_moviedetail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_like_moviedetail = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$ll_like_moviedetail$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            View view = MovieDescFragment.this.getView();
            LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_like_moviedetail);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_share_moviedetail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_share_moviedetail = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$ll_share_moviedetail$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            View view = MovieDescFragment.this.getView();
            LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_share_moviedetail);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: ll_xuanji_more$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_xuanji_more = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$ll_xuanji_more$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            View view = MovieDescFragment.this.getView();
            LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_xuanji_more);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: tv_morelinks_count$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_morelinks_count = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$tv_morelinks_count$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = MovieDescFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_morelinks_count);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: rv_movie_morelink$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_movie_morelink = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$rv_movie_morelink$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            View view = MovieDescFragment.this.getView();
            RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_movie_morelink);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: itv_header_more$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy itv_header_more = LazyKt__LazyJVMKt.lazy(new Function0<ImageTextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$itv_header_more$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageTextView invoke() {
            View view = MovieDescFragment.this.getView();
            ImageTextView imageTextView = view == null ? null : (ImageTextView) view.findViewById(R.id.itv_header_more);
            Intrinsics.checkNotNull(imageTextView);
            return imageTextView;
        }
    });

    /* renamed from: rv_tag$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_tag = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$rv_tag$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            View view = MovieDescFragment.this.getView();
            RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_tag);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: img_more$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy img_more = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$img_more$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            View view = MovieDescFragment.this.getView();
            ImageView imageView = view == null ? null : (ImageView) view.findViewById(R.id.img_more);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_more$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_more = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$tv_more$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            View view = MovieDescFragment.this.getView();
            TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_more);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: banner_parent$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy banner_parent = LazyKt__LazyJVMKt.lazy(new Function0<ScaleRelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$banner_parent$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ScaleRelativeLayout invoke() {
            View view = MovieDescFragment.this.getView();
            ScaleRelativeLayout scaleRelativeLayout = view == null ? null : (ScaleRelativeLayout) view.findViewById(R.id.banner_parent);
            Intrinsics.checkNotNull(scaleRelativeLayout);
            return scaleRelativeLayout;
        }
    });

    /* renamed from: banner$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy banner = LazyKt__LazyJVMKt.lazy(new Function0<Banner<?, ?>>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$banner$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final Banner<?, ?> invoke() {
            View view = MovieDescFragment.this.getView();
            Banner<?, ?> banner = view == null ? null : (Banner) view.findViewById(R.id.banner);
            Intrinsics.checkNotNull(banner);
            return banner;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000e\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0019\u0010\u001aJ:\u0010\u000b\u001a\u00020\n2\b\u0010\u0003\u001a\u0004\u0018\u00010\u00022!\u0010\t\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b\u0005\u0012\b\b\u0006\u0012\u0004\b\b(\u0007\u0012\u0004\u0012\u00020\b0\u0004¢\u0006\u0004\b\u000b\u0010\fR\"\u0010\u000e\u001a\u00020\r8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u000e\u0010\u000f\u001a\u0004\b\u0010\u0010\u0011\"\u0004\b\u0012\u0010\u0013R=\u0010\t\u001a\u001d\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b\u0005\u0012\b\b\u0006\u0012\u0004\b\b(\u0007\u0012\u0004\u0012\u00020\b0\u00048\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\t\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016\"\u0004\b\u0017\u0010\u0018¨\u0006\u001b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/movie/MovieDescFragment$Companion;", "", "", "videoId", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "id", "", "listener", "Lcom/jbzd/media/movecartoons/ui/movie/MovieDescFragment;", "newInstance", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;)Lcom/jbzd/media/movecartoons/ui/movie/MovieDescFragment;", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "mVideoDetailBean", "Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "getMVideoDetailBean", "()Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;", "setMVideoDetailBean", "(Lcom/jbzd/media/movecartoons/bean/response/VideoDetailBean;)V", "Lkotlin/jvm/functions/Function1;", "getListener", "()Lkotlin/jvm/functions/Function1;", "setListener", "(Lkotlin/jvm/functions/Function1;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final Function1<String, Unit> getListener() {
            Function1 function1 = MovieDescFragment.listener;
            if (function1 != null) {
                return function1;
            }
            Intrinsics.throwUninitializedPropertyAccessException("listener");
            throw null;
        }

        @NotNull
        public final VideoDetailBean getMVideoDetailBean() {
            VideoDetailBean videoDetailBean = MovieDescFragment.mVideoDetailBean;
            if (videoDetailBean != null) {
                return videoDetailBean;
            }
            Intrinsics.throwUninitializedPropertyAccessException("mVideoDetailBean");
            throw null;
        }

        @NotNull
        public final MovieDescFragment newInstance(@Nullable String videoId, @NotNull Function1<? super String, Unit> listener) {
            Intrinsics.checkNotNullParameter(listener, "listener");
            setListener(listener);
            MovieDescFragment movieDescFragment = new MovieDescFragment();
            Bundle bundle = new Bundle();
            bundle.putString(movieDescFragment.getKey_video_id(), videoId);
            Unit unit = Unit.INSTANCE;
            movieDescFragment.setArguments(bundle);
            return movieDescFragment;
        }

        public final void setListener(@NotNull Function1<? super String, Unit> function1) {
            Intrinsics.checkNotNullParameter(function1, "<set-?>");
            MovieDescFragment.listener = function1;
        }

        public final void setMVideoDetailBean(@NotNull VideoDetailBean videoDetailBean) {
            Intrinsics.checkNotNullParameter(videoDetailBean, "<set-?>");
            MovieDescFragment.mVideoDetailBean = videoDetailBean;
        }
    }

    private final void changeMoreTextColor(String category) {
        if (Intrinsics.areEqual(category, "3")) {
            getImg_more().setVisibility(0);
            getTv_more().setVisibility(8);
        } else {
            getImg_more().setVisibility(8);
            getTv_more().setVisibility(0);
        }
    }

    private final MovieDescFragment$bottomSeeToSeeAdapter$2.C38181 getBottomSeeToSeeAdapter() {
        return (MovieDescFragment$bottomSeeToSeeAdapter$2.C38181) this.bottomSeeToSeeAdapter.getValue();
    }

    private final String getFavorNum(String zan) {
        return (TextUtils.isEmpty(zan) || TextUtils.equals("0", zan)) ? "收藏" : C0843e0.m182a(zan);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getMVideoId() {
        return (String) this.mVideoId.getValue();
    }

    private final MovieDescFragment$movieMoreLinksAdapter$2.C38271 getMovieMoreLinksAdapter() {
        return (MovieDescFragment$movieMoreLinksAdapter$2.C38271) this.movieMoreLinksAdapter.getValue();
    }

    private final String getShowLoveTxt(String love) {
        return (TextUtils.isEmpty(love) || TextUtils.equals("0", love)) ? "收藏" : C0843e0.m182a(love);
    }

    private final MovieDescFragment$tagAdapter$2.C38281 getTagAdapter() {
        return (MovieDescFragment$tagAdapter$2.C38281) this.tagAdapter.getValue();
    }

    private final void initBannerView(final List<AdBean> mBanners) {
        if (mBanners == null || mBanners.isEmpty()) {
            getBanner_parent().setVisibility(8);
            return;
        }
        getBanner_parent().setVisibility(0);
        Banner<?, ?> banner = getBanner();
        banner.setIntercept(mBanners.size() != 1);
        Banner addBannerLifecycleObserver = banner.addBannerLifecycleObserver(this);
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(mBanners, 10));
        Iterator<T> it = mBanners.iterator();
        while (it.hasNext()) {
            arrayList.add(((AdBean) it.next()).content);
        }
        addBannerLifecycleObserver.setAdapter(new BannerAdapterImp(requireContext, arrayList, 0.0f, 1.0d, null, 20));
        banner.setOnBannerListener(new OnBannerListener() { // from class: b.a.a.a.t.i.c
            @Override // com.youth.banner.listener.OnBannerListener
            public final void OnBannerClick(Object obj, int i2) {
                MovieDescFragment.m5866initBannerView$lambda18$lambda17(MovieDescFragment.this, mBanners, obj, i2);
            }
        });
        banner.setIndicator(new RectangleIndicator(requireContext()));
        banner.addOnPageChangeListener(new OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initBannerView$1$3
            @Override // com.youth.banner.listener.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // com.youth.banner.listener.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // com.youth.banner.listener.OnPageChangeListener
            public void onPageSelected(int position) {
            }
        });
        banner.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initBannerView$lambda-18$lambda-17, reason: not valid java name */
    public static final void m5866initBannerView$lambda18$lambda17(MovieDescFragment this$0, List list, Object obj, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        C0840d.a aVar = C0840d.f235a;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        aVar.m176b(requireContext, (AdBean) list.get(i2));
    }

    private final void initView(final VideoDetailBean video) {
        FragmentActivity activity = getActivity();
        Objects.requireNonNull(activity, "null cannot be cast to non-null type com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity");
        final MovieDetailsViewModel viewModel = ((MovieDetailsActivity) activity).getViewModel();
        if (video == null) {
            return;
        }
        MovieDescFragment$bottomSeeToSeeAdapter$2.C38181 bottomSeeToSeeAdapter = getBottomSeeToSeeAdapter();
        List<VideoDetailBean> list = video.relation_video;
        bottomSeeToSeeAdapter.setNewData(list == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) list));
        RecyclerView rv_content_recommend = getRv_content_recommend();
        if (rv_content_recommend.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_content_recommend.getContext());
            c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, rv_content_recommend, 9.0d);
            c4053a.f10337e = C2354n.m2437V(rv_content_recommend.getContext(), 6.0d);
            c4053a.f10339g = false;
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            C1499a.m604Z(c4053a, rv_content_recommend);
        }
        rv_content_recommend.setAdapter(getBottomSeeToSeeAdapter());
        rv_content_recommend.setLayoutManager(new GridLayoutManager(requireContext(), 2));
        getTv_videodetail_name().setText(video.name);
        getTv_videodetail_click().setText(Intrinsics.stringPlus("人气：", C0843e0.m182a(video.click)));
        TextView tv_desc = getTv_desc();
        StringBuilder m586H = C1499a.m586H("完整版时长 ");
        m586H.append((Object) video.duration);
        m586H.append("       播放 ");
        m586H.append(C0843e0.m182a(video.click));
        m586H.append((char) 27425);
        tv_desc.setText(m586H.toString());
        if (Intrinsics.areEqual(video.desc, "")) {
            getText_descript().setVisibility(8);
        } else {
            getText_descript().setVisibility(0);
            TextView text_descript = getText_descript();
            String stringPlus = Intrinsics.stringPlus("简介：", video.desc);
            text_descript.setText(stringPlus != null ? stringPlus : "");
        }
        C2354n.m2374A(getItv_dislike(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initView$1$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                invoke2(imageTextView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageTextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (Intrinsics.areEqual(VideoDetailBean.this.has_love, "y")) {
                    C2354n.m2449Z("你已赞");
                    return;
                }
                final MovieDetailsViewModel movieDetailsViewModel = viewModel;
                String str = VideoDetailBean.this.f10000id;
                if (str == null) {
                    str = "";
                }
                final MovieDescFragment movieDescFragment = this;
                movieDetailsViewModel.doZan(str, ChatMsgBean.SERVICE_ID, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initView$1$2.1
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                        invoke2(obj);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable Object obj) {
                        MovieDetailsViewModel.this.updateUnlikeUnm(!movieDescFragment.getItv_dislike().isSelected());
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initView$1$2.2
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                });
            }
        }, 1);
        C2354n.m2374A(getLl_download_moviedetail(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initView$1$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MovieDetailsViewModel.this.downLoad();
            }
        }, 1);
        ImageTextView itv_like = getItv_like();
        String favorite = video.favorite;
        Intrinsics.checkNotNullExpressionValue(favorite, "favorite");
        itv_like.setText(getFavorNum(favorite));
        getItv_favorite().setSelected(Intrinsics.areEqual(video.has_favorite, "y"));
        getItv_favorite().setText(getItv_favorite().isSelected() ? "已收藏" : "收藏");
        C2354n.m2374A(getLl_favorite_moviedetal(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initView$1$4
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                MovieDescFragment.this.getItv_favorite().setSelected(!MovieDescFragment.this.getItv_favorite().isSelected());
                final MovieDetailsViewModel movieDetailsViewModel = viewModel;
                String str = video.f10000id;
                if (str == null) {
                    str = "";
                }
                final MovieDescFragment movieDescFragment = MovieDescFragment.this;
                movieDetailsViewModel.doFavorite(str, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initView$1$4.1
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                        invoke2(obj);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable Object obj) {
                        String valueOf = String.valueOf(obj);
                        HashMap hashMap = new HashMap();
                        if (!(valueOf.length() == 0)) {
                            try {
                                JSONObject jSONObject = new JSONObject(valueOf);
                                Iterator<String> keys = jSONObject.keys();
                                while (keys.hasNext()) {
                                    String key = keys.next();
                                    String value = jSONObject.getString(key);
                                    Intrinsics.checkNotNullExpressionValue(key, "key");
                                    Intrinsics.checkNotNullExpressionValue(value, "value");
                                    hashMap.put(key, value);
                                }
                            } catch (Exception e2) {
                                e2.printStackTrace();
                            }
                        }
                        MovieDetailsViewModel.this.getMHasFavorite().setValue(Boolean.valueOf(StringsKt__StringsJVMKt.equals$default((String) hashMap.get(NotificationCompat.CATEGORY_STATUS), "y", false, 2, null)));
                        MovieDetailsViewModel.this.updateLoveNum(!movieDescFragment.getItv_favorite().isSelected());
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initView$1$4.2
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                });
            }
        }, 1);
        C2354n.m2374A(getLl_like_moviedetail(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initView$1$5
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                final MovieDetailsViewModel movieDetailsViewModel = MovieDetailsViewModel.this;
                String str = video.f10000id;
                if (str == null) {
                    str = "";
                }
                final MovieDescFragment movieDescFragment = this;
                movieDetailsViewModel.doZan(str, "1", new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initView$1$5.1
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                        invoke2(obj);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@Nullable Object obj) {
                        MovieDetailsViewModel.this.updateZanNum(!movieDescFragment.getItv_like().isSelected());
                    }
                }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initView$1$5.2
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                        invoke2(exc);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull Exception it2) {
                        Intrinsics.checkNotNullParameter(it2, "it");
                    }
                });
            }
        }, 1);
        C2354n.m2374A(getLl_share_moviedetail(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initView$1$6
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull LinearLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                InviteActivity.Companion companion = InviteActivity.INSTANCE;
                Context requireContext = MovieDescFragment.this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext);
            }
        }, 1);
        if (video.is_more_link.equals("y")) {
            getLl_xuanji_more().setVisibility(0);
            TextView tv_morelinks_count = getTv_morelinks_count();
            StringBuilder m584F = C1499a.m584F((char) 20849);
            m584F.append(video.links.size());
            m584F.append((char) 38598);
            tv_morelinks_count.setText(m584F.toString());
            RecyclerView rv_movie_morelink = getRv_movie_morelink();
            if (rv_movie_morelink.getItemDecorationCount() == 0) {
                GridItemDecoration.C4053a c4053a2 = new GridItemDecoration.C4053a(rv_movie_morelink.getContext());
                c4053a2.f10336d = C1499a.m638x(c4053a2, R.color.transparent, rv_movie_morelink, 9.0d);
                c4053a2.f10337e = C2354n.m2437V(rv_movie_morelink.getContext(), 6.0d);
                c4053a2.f10339g = false;
                c4053a2.f10340h = false;
                c4053a2.f10338f = false;
                C1499a.m604Z(c4053a2, rv_movie_morelink);
            }
            if (getIsFirst()) {
                MovieDescFragment$movieMoreLinksAdapter$2.C38271 movieMoreLinksAdapter = getMovieMoreLinksAdapter();
                List<VideoDetailBean.MultiLinks> links = video.links;
                Intrinsics.checkNotNullExpressionValue(links, "links");
                movieMoreLinksAdapter.setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) links));
            } else {
                List<VideoDetailBean.MultiLinks> links2 = video.links;
                Intrinsics.checkNotNullExpressionValue(links2, "links");
                int i2 = 0;
                for (Object obj : links2) {
                    int i3 = i2 + 1;
                    if (i2 < 0) {
                        CollectionsKt__CollectionsKt.throwIndexOverflow();
                    }
                    VideoDetailBean.MultiLinks multiLinks = (VideoDetailBean.MultiLinks) obj;
                    multiLinks.is_select = "n";
                    FragmentActivity activity2 = getActivity();
                    Objects.requireNonNull(activity2, "null cannot be cast to non-null type com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity");
                    if (Intrinsics.areEqual(((MovieDetailsActivity) activity2).getViewModel().getLinkId().getValue(), multiLinks.f9994id)) {
                        multiLinks.is_select = "y";
                    }
                    i2 = i3;
                }
                MovieDescFragment$movieMoreLinksAdapter$2.C38271 movieMoreLinksAdapter2 = getMovieMoreLinksAdapter();
                List<VideoDetailBean.MultiLinks> links3 = video.links;
                Intrinsics.checkNotNullExpressionValue(links3, "links");
                movieMoreLinksAdapter2.setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) links3));
            }
            rv_movie_morelink.setAdapter(getMovieMoreLinksAdapter());
            rv_movie_morelink.setLayoutManager(new LinearLayoutManager(requireContext(), 0, false));
            C2354n.m2374A(getItv_header_more(), 0L, new Function1<ImageTextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initView$1$8
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(ImageTextView imageTextView) {
                    invoke2(imageTextView);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull ImageTextView it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                    MovieDescFragment.this.showPaymentDialog(video.links, viewModel);
                }
            }, 1);
        } else {
            getLl_xuanji_more().setVisibility(8);
        }
        RecyclerView rv_tag = getRv_tag();
        MovieDescFragment$tagAdapter$2.C38281 tagAdapter = getTagAdapter();
        List<TagBean> tags = video.tags;
        Intrinsics.checkNotNullExpressionValue(tags, "tags");
        tagAdapter.setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) tags));
        rv_tag.setAdapter(getTagAdapter());
        FlexboxLayoutManager flexboxLayoutManager = new FlexboxLayoutManager(rv_tag.getContext());
        flexboxLayoutManager.m4176y(1);
        flexboxLayoutManager.m4175x(0);
        Unit unit = Unit.INSTANCE;
        rv_tag.setLayoutManager(flexboxLayoutManager);
        if (rv_tag.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a3 = new GridItemDecoration.C4053a(rv_tag.getContext());
            c4053a3.f10336d = C1499a.m638x(c4053a3, R.color.transparent, rv_tag, 1.0d);
            c4053a3.f10337e = C2354n.m2437V(rv_tag.getContext(), 1.0d);
            c4053a3.f10339g = false;
            c4053a3.f10340h = false;
            c4053a3.f10338f = false;
            C1499a.m604Z(c4053a3, rv_tag);
        }
        RecyclerView rvAds = getRvAds();
        List<AdBean> list2 = video.ico_ads;
        Intrinsics.checkNotNullParameter(rvAds, "<this>");
        C4195m.m4793Z(rvAds).m3939q(list2);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-2, reason: not valid java name */
    public static final void m5867initViews$lambda2(MovieDescFragment this$0) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.mExpandHeight = Integer.valueOf(this$0.getRl_videoBottomParent().getHeight());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-9$lambda-3, reason: not valid java name */
    public static final void m5868initViews$lambda9$lambda3(MovieDescFragment this$0, VideoDetailBean videoDetailBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.initView(videoDetailBean);
        C4909c.m5569b().m5574g(new EventMoviBottom(videoDetailBean.f10000id));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-9$lambda-4, reason: not valid java name */
    public static final void m5869initViews$lambda9$lambda4(MovieDescFragment this$0, Boolean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ImageTextView itv_favorite = this$0.getItv_favorite();
        Intrinsics.checkNotNullExpressionValue(it, "it");
        itv_favorite.setSelected(it.booleanValue());
        this$0.getItv_favorite().setText(this$0.getItv_favorite().isSelected() ? "已收藏" : "收藏");
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-9$lambda-5, reason: not valid java name */
    public static final void m5870initViews$lambda9$lambda5(MovieDescFragment this$0, Boolean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ImageTextView itv_dislike = this$0.getItv_dislike();
        Intrinsics.checkNotNullExpressionValue(it, "it");
        itv_dislike.setSelected(it.booleanValue());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-9$lambda-6, reason: not valid java name */
    public static final void m5871initViews$lambda9$lambda6(MovieDescFragment this$0, Boolean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ImageTextView itv_like = this$0.getItv_like();
        Intrinsics.checkNotNullExpressionValue(it, "it");
        itv_like.setSelected(it.booleanValue());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-9$lambda-7, reason: not valid java name */
    public static final void m5872initViews$lambda9$lambda7(String str) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-9$lambda-8, reason: not valid java name */
    public static final void m5873initViews$lambda9$lambda8(String str) {
        if (!TextUtils.isEmpty(str)) {
            C2354n.m2409L1("缓存成功，请至离线缓存查看进度");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showPaymentDialog(List<? extends VideoDetailBean.MultiLinks> links, MovieDetailsViewModel viewModel) {
        List<? extends VideoDetailBean.MultiLinks> mutableList;
        ChooseMultiLinksDialog chooseMultiLinksDialog;
        FragmentActivity activity = getActivity();
        this.mChooseMultiLinksDialog = activity == null ? null : ChooseMultiLinksDialog.INSTANCE.chooseMultilinks(activity, viewModel);
        if (links != null && (mutableList = CollectionsKt___CollectionsKt.toMutableList((Collection) links)) != null && (chooseMultiLinksDialog = this.mChooseMultiLinksDialog) != null) {
            chooseMultiLinksDialog.setLinksData(mutableList);
        }
        ChooseMultiLinksDialog chooseMultiLinksDialog2 = this.mChooseMultiLinksDialog;
        if (chooseMultiLinksDialog2 == null) {
            return;
        }
        chooseMultiLinksDialog2.show();
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void showPaymentDialog$default(MovieDescFragment movieDescFragment, List list, MovieDetailsViewModel movieDetailsViewModel, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            list = null;
        }
        movieDescFragment.showPaymentDialog(list, movieDetailsViewModel);
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final Banner<?, ?> getBanner() {
        return (Banner) this.banner.getValue();
    }

    @NotNull
    public final ScaleRelativeLayout getBanner_parent() {
        return (ScaleRelativeLayout) this.banner_parent.getValue();
    }

    @NotNull
    public final ImageView getImg_more() {
        return (ImageView) this.img_more.getValue();
    }

    @NotNull
    public final ImageTextView getItv_dislike() {
        return (ImageTextView) this.itv_dislike.getValue();
    }

    @NotNull
    public final ImageTextView getItv_favorite() {
        return (ImageTextView) this.itv_favorite.getValue();
    }

    @NotNull
    public final ImageTextView getItv_header_more() {
        return (ImageTextView) this.itv_header_more.getValue();
    }

    @NotNull
    public final ImageTextView getItv_like() {
        return (ImageTextView) this.itv_like.getValue();
    }

    @NotNull
    public final String getKey_video_id() {
        return this.key_video_id;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_movie_desc;
    }

    @NotNull
    public final LinearLayout getLl_download_moviedetail() {
        return (LinearLayout) this.ll_download_moviedetail.getValue();
    }

    @NotNull
    public final LinearLayout getLl_favorite_moviedetal() {
        return (LinearLayout) this.ll_favorite_moviedetal.getValue();
    }

    @NotNull
    public final TextView getLl_footer_change_bottom() {
        return (TextView) this.ll_footer_change_bottom.getValue();
    }

    @NotNull
    public final LinearLayout getLl_like_moviedetail() {
        return (LinearLayout) this.ll_like_moviedetail.getValue();
    }

    @NotNull
    public final LinearLayout getLl_share_moviedetail() {
        return (LinearLayout) this.ll_share_moviedetail.getValue();
    }

    @NotNull
    public final LinearLayout getLl_xuanji_more() {
        return (LinearLayout) this.ll_xuanji_more.getValue();
    }

    @NotNull
    public final LinearLayout getRl_videoBottomParent() {
        return (LinearLayout) this.rl_videoBottomParent.getValue();
    }

    @NotNull
    public final RecyclerView getRvAds() {
        return (RecyclerView) this.rvAds.getValue();
    }

    @NotNull
    public final RecyclerView getRv_content_recommend() {
        return (RecyclerView) this.rv_content_recommend.getValue();
    }

    @NotNull
    public final RecyclerView getRv_movie_morelink() {
        return (RecyclerView) this.rv_movie_morelink.getValue();
    }

    @NotNull
    public final RecyclerView getRv_tag() {
        return (RecyclerView) this.rv_tag.getValue();
    }

    @NotNull
    public final TextView getText_descript() {
        return (TextView) this.text_descript.getValue();
    }

    @NotNull
    public final TextView getTv_desc() {
        return (TextView) this.tv_desc.getValue();
    }

    @NotNull
    public final TextView getTv_more() {
        return (TextView) this.tv_more.getValue();
    }

    @NotNull
    public final TextView getTv_morelinks_count() {
        return (TextView) this.tv_morelinks_count.getValue();
    }

    @NotNull
    public final TextView getTv_videodetail_click() {
        return (TextView) this.tv_videodetail_click.getValue();
    }

    @NotNull
    public final TextView getTv_videodetail_name() {
        return (TextView) this.tv_videodetail_name.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initEvents() {
        MyThemeFragment.fadeWhenTouch$default(this, getLl_footer_change_bottom(), 0.0f, 1, null);
        C2354n.m2374A(getLl_footer_change_bottom(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initEvents$1
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, 1);
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        RecyclerView rvAds = getRvAds();
        C4195m.m4821n0(rvAds, 5, 0, false, false, 14);
        C4195m.m4784Q(rvAds, C4195m.m4785R(10.0f), DividerOrientation.GRID);
        C4195m.m4774J0(rvAds, new Function2<BindingAdapter, RecyclerView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initViews$1
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter bindingAdapter, RecyclerView recyclerView) {
                invoke2(bindingAdapter, recyclerView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull BindingAdapter bindingAdapter, @NotNull RecyclerView recyclerView) {
                boolean m616f0 = C1499a.m616f0(bindingAdapter, "$this$setup", recyclerView, "it", AdBean.class);
                final int i2 = R.layout.item_app_vertical;
                if (m616f0) {
                    bindingAdapter.f8910l.put(Reflection.typeOf(AdBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initViews$1$invoke$$inlined$addType$1
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(2);
                        }

                        @NotNull
                        public final Integer invoke(@NotNull Object obj, int i3) {
                            Intrinsics.checkNotNullParameter(obj, "$this$null");
                            return Integer.valueOf(i2);
                        }

                        @Override // kotlin.jvm.functions.Function2
                        public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                            return invoke(obj, num.intValue());
                        }
                    });
                } else {
                    bindingAdapter.f8909k.put(Reflection.typeOf(AdBean.class), new Function2<Object, Integer, Integer>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initViews$1$invoke$$inlined$addType$2
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(2);
                        }

                        @NotNull
                        public final Integer invoke(@NotNull Object obj, int i3) {
                            Intrinsics.checkNotNullParameter(obj, "$this$null");
                            return Integer.valueOf(i2);
                        }

                        @Override // kotlin.jvm.functions.Function2
                        public /* bridge */ /* synthetic */ Integer invoke(Object obj, Integer num) {
                            return invoke(obj, num.intValue());
                        }
                    });
                }
                final MovieDescFragment movieDescFragment = MovieDescFragment.this;
                bindingAdapter.m3935l(new Function1<BindingAdapter.BindingViewHolder, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initViews$1.1
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder) {
                        invoke2(bindingViewHolder);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull BindingAdapter.BindingViewHolder onBind) {
                        ItemAppVerticalBinding itemAppVerticalBinding;
                        Intrinsics.checkNotNullParameter(onBind, "$this$onBind");
                        ViewBinding viewBinding = onBind.f8929e;
                        if (viewBinding == null) {
                            Object invoke = ItemAppVerticalBinding.class.getMethod("bind", View.class).invoke(null, onBind.itemView);
                            Objects.requireNonNull(invoke, "null cannot be cast to non-null type com.jbzd.media.movecartoons.databinding.ItemAppVerticalBinding");
                            itemAppVerticalBinding = (ItemAppVerticalBinding) invoke;
                            onBind.f8929e = itemAppVerticalBinding;
                        } else {
                            Objects.requireNonNull(viewBinding, "null cannot be cast to non-null type com.jbzd.media.movecartoons.databinding.ItemAppVerticalBinding");
                            itemAppVerticalBinding = (ItemAppVerticalBinding) viewBinding;
                        }
                        MovieDescFragment movieDescFragment2 = MovieDescFragment.this;
                        AdBean adBean = (AdBean) onBind.m3942b();
                        itemAppVerticalBinding.txtName.setText(adBean.name);
                        C2354n.m2455a2(movieDescFragment2.requireContext()).m3298p(adBean.content).m3295i0().m757R(itemAppVerticalBinding.imgIcon);
                    }
                });
                int[] iArr = {R.id.root};
                final MovieDescFragment movieDescFragment2 = MovieDescFragment.this;
                bindingAdapter.m3937n(iArr, new Function2<BindingAdapter.BindingViewHolder, Integer, Unit>() { // from class: com.jbzd.media.movecartoons.ui.movie.MovieDescFragment$initViews$1.2
                    {
                        super(2);
                    }

                    @Override // kotlin.jvm.functions.Function2
                    public /* bridge */ /* synthetic */ Unit invoke(BindingAdapter.BindingViewHolder bindingViewHolder, Integer num) {
                        invoke(bindingViewHolder, num.intValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(@NotNull BindingAdapter.BindingViewHolder onClick, int i3) {
                        Intrinsics.checkNotNullParameter(onClick, "$this$onClick");
                        MineViewModel.Companion companion = MineViewModel.INSTANCE;
                        String str = ((AdBean) onClick.m3942b()).f10014id;
                        Intrinsics.checkNotNullExpressionValue(str, "getModel<AdBean>().id");
                        String str2 = ((AdBean) onClick.m3942b()).name;
                        Intrinsics.checkNotNullExpressionValue(str2, "getModel<AdBean>().name");
                        companion.systemTrack("ad", str, str2);
                        C0840d.a aVar = C0840d.f235a;
                        Context requireContext = MovieDescFragment.this.requireContext();
                        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                        C0840d.a.m174d(aVar, requireContext, ((AdBean) onClick.m3942b()).link, null, null, 12);
                    }
                });
            }
        });
        getRl_videoBottomParent().post(new Runnable() { // from class: b.a.a.a.t.i.h
            @Override // java.lang.Runnable
            public final void run() {
                MovieDescFragment.m5867initViews$lambda2(MovieDescFragment.this);
            }
        });
        FragmentActivity activity = getActivity();
        Objects.requireNonNull(activity, "null cannot be cast to non-null type com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity");
        MovieDetailsViewModel viewModel = ((MovieDetailsActivity) activity).getViewModel();
        MutableLiveData<VideoDetailBean> detailInfo = viewModel.getDetailInfo();
        FragmentActivity activity2 = getActivity();
        Objects.requireNonNull(activity2, "null cannot be cast to non-null type com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity");
        detailInfo.observe((MovieDetailsActivity) activity2, new Observer() { // from class: b.a.a.a.t.i.f
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDescFragment.m5868initViews$lambda9$lambda3(MovieDescFragment.this, (VideoDetailBean) obj);
            }
        });
        MutableLiveData<Boolean> mHasFavorite = viewModel.getMHasFavorite();
        FragmentActivity activity3 = getActivity();
        Objects.requireNonNull(activity3, "null cannot be cast to non-null type com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity");
        mHasFavorite.observe((MovieDetailsActivity) activity3, new Observer() { // from class: b.a.a.a.t.i.e
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDescFragment.m5869initViews$lambda9$lambda4(MovieDescFragment.this, (Boolean) obj);
            }
        });
        MutableLiveData<Boolean> mHasHate = viewModel.getMHasHate();
        FragmentActivity activity4 = getActivity();
        Objects.requireNonNull(activity4, "null cannot be cast to non-null type com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity");
        mHasHate.observe((MovieDetailsActivity) activity4, new Observer() { // from class: b.a.a.a.t.i.d
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDescFragment.m5870initViews$lambda9$lambda5(MovieDescFragment.this, (Boolean) obj);
            }
        });
        MutableLiveData<Boolean> mHasZan = viewModel.getMHasZan();
        FragmentActivity activity5 = getActivity();
        Objects.requireNonNull(activity5, "null cannot be cast to non-null type com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity");
        mHasZan.observe((MovieDetailsActivity) activity5, new Observer() { // from class: b.a.a.a.t.i.j
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDescFragment.m5871initViews$lambda9$lambda6(MovieDescFragment.this, (Boolean) obj);
            }
        });
        MutableLiveData<String> mZanNum = viewModel.getMZanNum();
        FragmentActivity activity6 = getActivity();
        Objects.requireNonNull(activity6, "null cannot be cast to non-null type com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity");
        mZanNum.observe((MovieDetailsActivity) activity6, new Observer() { // from class: b.a.a.a.t.i.b
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDescFragment.m5872initViews$lambda9$lambda7((String) obj);
            }
        });
        MutableLiveData<String> downloading = viewModel.getDownloading();
        FragmentActivity activity7 = getActivity();
        Objects.requireNonNull(activity7, "null cannot be cast to non-null type com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity");
        downloading.observe((MovieDetailsActivity) activity7, new Observer() { // from class: b.a.a.a.t.i.a
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                MovieDescFragment.m5873initViews$lambda9$lambda8((String) obj);
            }
        });
    }

    /* renamed from: isFirst, reason: from getter */
    public final boolean getIsFirst() {
        return this.isFirst;
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroyView() {
        super.onDestroyView();
    }

    public final void setFirst(boolean z) {
        this.isFirst = z;
    }

    public final void showShareDialog(@Nullable VideoDetailBean video) {
        if (this.mShareDialog == null) {
            ShareBottomSheetDialog.Companion companion = ShareBottomSheetDialog.INSTANCE;
            FragmentActivity requireActivity = requireActivity();
            Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity()");
            this.mShareDialog = companion.getShareBottomSheetDialog(requireActivity);
        }
        ShareBottomSheetDialog shareBottomSheetDialog = this.mShareDialog;
        if (shareBottomSheetDialog != null) {
            if (Intrinsics.areEqual(shareBottomSheetDialog == null ? null : Boolean.valueOf(shareBottomSheetDialog.isShowing()), Boolean.FALSE)) {
                ShareBottomSheetDialog shareBottomSheetDialog2 = this.mShareDialog;
                if (shareBottomSheetDialog2 != null) {
                    shareBottomSheetDialog2.show();
                }
                ShareBottomSheetDialog shareBottomSheetDialog3 = this.mShareDialog;
                if (shareBottomSheetDialog3 == null) {
                    return;
                }
                shareBottomSheetDialog3.setShowData(video);
            }
        }
    }
}
