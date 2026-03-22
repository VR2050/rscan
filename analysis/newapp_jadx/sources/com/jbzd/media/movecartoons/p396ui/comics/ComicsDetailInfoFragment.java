package com.jbzd.media.movecartoons.p396ui.comics;

import android.content.Context;
import android.os.Bundle;
import android.view.View;
import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.Chapter;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsDetailInfoBean;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsChapterViewActivity;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailInfoFragment;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailInfoFragment$icoAdAdapter$2;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailInfoFragment$tableContentAdapter$2;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsTableContentAllActivity;
import com.jbzd.media.movecartoons.p396ui.search.model.ComicsViewModel;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import com.youth.banner.Banner;
import com.youth.banner.indicator.RectangleIndicator;
import com.youth.banner.listener.OnBannerListener;
import com.youth.banner.listener.OnPageChangeListener;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
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
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000}\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\u0005\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\n*\u0003&+C\u0018\u0000 d2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001dB\u0007¢\u0006\u0004\bc\u0010\u0016J\u001f\u0010\u0007\u001a\u00020\u00062\u000e\u0010\u0005\u001a\n\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u0003H\u0002¢\u0006\u0004\b\u0007\u0010\bJ<\u0010\u0011\u001a\u00020\u00062\u0006\u0010\n\u001a\u00020\t2#\b\u0002\u0010\u0010\u001a\u001d\u0012\u0013\u0012\u00110\f¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u000f\u0012\u0004\u0012\u00020\u00060\u000bH\u0002¢\u0006\u0004\b\u0011\u0010\u0012J\r\u0010\u0013\u001a\u00020\u0002¢\u0006\u0004\b\u0013\u0010\u0014J\u000f\u0010\u0015\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0015\u0010\u0016J\u000f\u0010\u0018\u001a\u00020\u0017H\u0016¢\u0006\u0004\b\u0018\u0010\u0019J\u000f\u0010\u001a\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u001a\u0010\u0016R\u001d\u0010 \u001a\u00020\u001b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u001d\u001a\u0004\b\u001e\u0010\u001fR\u001d\u0010%\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u001d\u001a\u0004\b#\u0010$R\u001d\u0010*\u001a\u00020&8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b'\u0010\u001d\u001a\u0004\b(\u0010)R\u001d\u0010/\u001a\u00020+8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\u001d\u001a\u0004\b-\u0010.R\u001d\u00102\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\u001d\u001a\u0004\b1\u0010$R\u001d\u00105\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b3\u0010\u001d\u001a\u0004\b4\u0010\u0014R\u001d\u00108\u001a\u00020\u001b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b6\u0010\u001d\u001a\u0004\b7\u0010\u001fR\u001d\u0010=\u001a\u0002098F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b:\u0010\u001d\u001a\u0004\b;\u0010<R%\u0010B\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u00030>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b?\u0010\u001d\u001a\u0004\b@\u0010AR\u001d\u0010G\u001a\u00020C8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bD\u0010\u001d\u001a\u0004\bE\u0010FR\u001d\u0010J\u001a\u0002098F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bH\u0010\u001d\u001a\u0004\bI\u0010<R\"\u0010K\u001a\u00020\u00178\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bK\u0010L\u001a\u0004\bM\u0010\u0019\"\u0004\bN\u0010OR\u001d\u0010T\u001a\u00020P8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bQ\u0010\u001d\u001a\u0004\bR\u0010SR\u001d\u0010W\u001a\u0002098F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bU\u0010\u001d\u001a\u0004\bV\u0010<R\u001d\u0010Z\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bX\u0010\u001d\u001a\u0004\bY\u0010$R\u001d\u0010_\u001a\u00020[8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\\\u0010\u001d\u001a\u0004\b]\u0010^R\u001d\u0010b\u001a\u00020!8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b`\u0010\u001d\u001a\u0004\ba\u0010$¨\u0006e"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment;", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "mBanners", "", "initBannerView", "(Ljava/util/List;)V", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/Chapter;", "mChapter", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "isBalanceEnough", "result", "checkMoneyForBuyChapter", "(Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/Chapter;Lkotlin/jvm/functions/Function1;)V", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "initEvents", "()V", "", "getLayout", "()I", "initViews", "Landroid/widget/LinearLayout;", "ll_footer_change_bottom$delegate", "Lkotlin/Lazy;", "getLl_footer_change_bottom", "()Landroid/widget/LinearLayout;", "ll_footer_change_bottom", "Landroid/widget/TextView;", "iv_chapterdetail_more$delegate", "getIv_chapterdetail_more", "()Landroid/widget/TextView;", "iv_chapterdetail_more", "com/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$icoAdAdapter$2$1", "icoAdAdapter$delegate", "getIcoAdAdapter", "()Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$icoAdAdapter$2$1;", "icoAdAdapter", "com/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2$1", "bottomSeeToSeeAdapter$delegate", "getBottomSeeToSeeAdapter", "()Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2$1;", "bottomSeeToSeeAdapter", "tv_tablecontent_subtitle$delegate", "getTv_tablecontent_subtitle", "tv_tablecontent_subtitle", "viewModel$delegate", "getViewModel", "viewModel", "ll_showall_chapter$delegate", "getLl_showall_chapter", "ll_showall_chapter", "Landroidx/recyclerview/widget/RecyclerView;", "rv_related_items$delegate", "getRv_related_items", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_related_items", "Lcom/youth/banner/Banner;", "banner_comics$delegate", "getBanner_comics", "()Lcom/youth/banner/Banner;", "banner_comics", "com/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$tableContentAdapter$2$1", "tableContentAdapter$delegate", "getTableContentAdapter", "()Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$tableContentAdapter$2$1;", "tableContentAdapter", "rv_seetosee_bottom$delegate", "getRv_seetosee_bottom", "rv_seetosee_bottom", "bottomDataPage", "I", "getBottomDataPage", "setBottomDataPage", "(I)V", "Lcom/jbzd/media/movecartoons/view/viewgroup/ScaleRelativeLayout;", "banner_parent_comics$delegate", "getBanner_parent_comics", "()Lcom/jbzd/media/movecartoons/view/viewgroup/ScaleRelativeLayout;", "banner_parent_comics", "rv_banner_ico_comicsdetail$delegate", "getRv_banner_ico_comicsdetail", "rv_banner_ico_comicsdetail", "tv_banner_bottom$delegate", "getTv_banner_bottom", "tv_banner_bottom", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;", "mComicsDetailInfo$delegate", "getMComicsDetailInfo", "()Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;", "mComicsDetailInfo", "tv_banner_top$delegate", "getTv_banner_top", "tv_banner_top", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ComicsDetailInfoFragment extends MyThemeFragment<ComicsViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: banner_comics$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy banner_comics;

    /* renamed from: banner_parent_comics$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy banner_parent_comics;
    private int bottomDataPage;

    /* renamed from: bottomSeeToSeeAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy bottomSeeToSeeAdapter;

    /* renamed from: icoAdAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy icoAdAdapter;

    /* renamed from: iv_chapterdetail_more$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_chapterdetail_more;

    /* renamed from: ll_footer_change_bottom$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_footer_change_bottom;

    /* renamed from: ll_showall_chapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_showall_chapter;

    /* renamed from: mComicsDetailInfo$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mComicsDetailInfo;

    /* renamed from: rv_banner_ico_comicsdetail$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_banner_ico_comicsdetail;

    /* renamed from: rv_related_items$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_related_items;

    /* renamed from: rv_seetosee_bottom$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_seetosee_bottom;

    /* renamed from: tableContentAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tableContentAdapter;

    /* renamed from: tv_banner_bottom$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_banner_bottom;

    /* renamed from: tv_banner_top$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_banner_top;

    /* renamed from: tv_tablecontent_subtitle$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_tablecontent_subtitle;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0017\u0010\u0005\u001a\u00020\u00042\b\u0010\u0003\u001a\u0004\u0018\u00010\u0002¢\u0006\u0004\b\u0005\u0010\u0006¨\u0006\t"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$Companion;", "", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;", "comicsDetailInfoBean", "Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment;", "newInstance", "(Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;)Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final ComicsDetailInfoFragment newInstance(@Nullable ComicsDetailInfoBean comicsDetailInfoBean) {
            ComicsDetailInfoFragment comicsDetailInfoFragment = new ComicsDetailInfoFragment();
            Bundle bundle = new Bundle();
            bundle.putSerializable("comicsDetailInfoBean", comicsDetailInfoBean);
            Unit unit = Unit.INSTANCE;
            comicsDetailInfoFragment.setArguments(bundle);
            return comicsDetailInfoFragment;
        }
    }

    public ComicsDetailInfoFragment() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$special$$inlined$viewModels$default$1
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final Fragment invoke() {
                return Fragment.this;
            }
        };
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(ComicsViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$special$$inlined$viewModels$default$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ViewModelStore invoke() {
                ViewModelStore viewModelStore = ((ViewModelStoreOwner) Function0.this.invoke()).getViewModelStore();
                Intrinsics.checkExpressionValueIsNotNull(viewModelStore, "ownerProducer().viewModelStore");
                return viewModelStore;
            }
        }, null);
        this.mComicsDetailInfo = LazyKt__LazyJVMKt.lazy(new Function0<ComicsDetailInfoBean>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$mComicsDetailInfo$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ComicsDetailInfoBean invoke() {
                Bundle arguments = ComicsDetailInfoFragment.this.getArguments();
                Serializable serializable = arguments == null ? null : arguments.getSerializable("comicsDetailInfoBean");
                Objects.requireNonNull(serializable, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsDetailInfoBean");
                return (ComicsDetailInfoBean) serializable;
            }
        });
        this.ll_showall_chapter = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$ll_showall_chapter$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View view = ComicsDetailInfoFragment.this.getView();
                LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_showall_chapter);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.ll_footer_change_bottom = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$ll_footer_change_bottom$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final LinearLayout invoke() {
                View view = ComicsDetailInfoFragment.this.getView();
                LinearLayout linearLayout = view == null ? null : (LinearLayout) view.findViewById(R.id.ll_footer_change_bottom);
                Intrinsics.checkNotNull(linearLayout);
                return linearLayout;
            }
        });
        this.iv_chapterdetail_more = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$iv_chapterdetail_more$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = ComicsDetailInfoFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.iv_chapterdetail_more);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.tv_banner_top = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$tv_banner_top$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = ComicsDetailInfoFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_banner_top);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.tv_banner_bottom = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$tv_banner_bottom$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = ComicsDetailInfoFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_banner_bottom);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.banner_parent_comics = LazyKt__LazyJVMKt.lazy(new Function0<ScaleRelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$banner_parent_comics$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final ScaleRelativeLayout invoke() {
                View view = ComicsDetailInfoFragment.this.getView();
                ScaleRelativeLayout scaleRelativeLayout = view == null ? null : (ScaleRelativeLayout) view.findViewById(R.id.banner_parent_comics);
                Intrinsics.checkNotNull(scaleRelativeLayout);
                return scaleRelativeLayout;
            }
        });
        this.rv_banner_ico_comicsdetail = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$rv_banner_ico_comicsdetail$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = ComicsDetailInfoFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_banner_ico_comicsdetail);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
        this.icoAdAdapter = LazyKt__LazyJVMKt.lazy(new ComicsDetailInfoFragment$icoAdAdapter$2(this));
        this.banner_comics = LazyKt__LazyJVMKt.lazy(new Function0<Banner<?, ?>>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$banner_comics$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final Banner<?, ?> invoke() {
                View view = ComicsDetailInfoFragment.this.getView();
                Banner<?, ?> banner = view == null ? null : (Banner) view.findViewById(R.id.banner_comics);
                Intrinsics.checkNotNull(banner);
                return banner;
            }
        });
        this.tableContentAdapter = LazyKt__LazyJVMKt.lazy(new ComicsDetailInfoFragment$tableContentAdapter$2(this));
        this.bottomSeeToSeeAdapter = LazyKt__LazyJVMKt.lazy(new ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2(this));
        this.tv_tablecontent_subtitle = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$tv_tablecontent_subtitle$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final TextView invoke() {
                View view = ComicsDetailInfoFragment.this.getView();
                TextView textView = view == null ? null : (TextView) view.findViewById(R.id.tv_tablecontent_subtitle);
                Intrinsics.checkNotNull(textView);
                return textView;
            }
        });
        this.rv_related_items = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$rv_related_items$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = ComicsDetailInfoFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_related_items);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
        this.rv_seetosee_bottom = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$rv_seetosee_bottom$2
            {
                super(0);
            }

            /* JADX WARN: Can't rename method to resolve collision */
            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final RecyclerView invoke() {
                View view = ComicsDetailInfoFragment.this.getView();
                RecyclerView recyclerView = view == null ? null : (RecyclerView) view.findViewById(R.id.rv_seetosee_bottom);
                Intrinsics.checkNotNull(recyclerView);
                return recyclerView;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:10:0x0013  */
    /* JADX WARN: Removed duplicated region for block: B:12:0x0019  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0024  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0026  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x001a A[Catch: Exception -> 0x001f, TRY_LEAVE, TryCatch #0 {Exception -> 0x001f, blocks: (B:8:0x000d, B:20:0x001a, B:22:0x0015), top: B:7:0x000d }] */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0015 A[Catch: Exception -> 0x001f, TryCatch #0 {Exception -> 0x001f, blocks: (B:8:0x000d, B:20:0x001a, B:22:0x0015), top: B:7:0x000d }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void checkMoneyForBuyChapter(com.jbzd.media.movecartoons.bean.response.comicsinfo.Chapter r5, kotlin.jvm.functions.Function1<? super java.lang.Boolean, kotlin.Unit> r6) {
        /*
            r4 = this;
            r0 = 0
            java.lang.String r5 = r5.money     // Catch: java.lang.Exception -> Lc
            if (r5 != 0) goto L7
            goto Lc
        L7:
            double r2 = java.lang.Double.parseDouble(r5)     // Catch: java.lang.Exception -> Lc
            goto Ld
        Lc:
            r2 = r0
        Ld:
            com.jbzd.media.movecartoons.MyApp r5 = com.jbzd.media.movecartoons.MyApp.f9891f     // Catch: java.lang.Exception -> L1f
            com.jbzd.media.movecartoons.bean.response.UserInfoBean r5 = com.jbzd.media.movecartoons.MyApp.f9892g     // Catch: java.lang.Exception -> L1f
            if (r5 != 0) goto L15
            r5 = 0
            goto L17
        L15:
            java.lang.String r5 = r5.balance     // Catch: java.lang.Exception -> L1f
        L17:
            if (r5 != 0) goto L1a
            goto L20
        L1a:
            double r0 = java.lang.Double.parseDouble(r5)     // Catch: java.lang.Exception -> L1f
            goto L20
        L1f:
        L20:
            int r5 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r5 < 0) goto L26
            r5 = 1
            goto L27
        L26:
            r5 = 0
        L27:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            r6.invoke(r5)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailInfoFragment.checkMoneyForBuyChapter(com.jbzd.media.movecartoons.bean.response.comicsinfo.Chapter, kotlin.jvm.functions.Function1):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void checkMoneyForBuyChapter$default(ComicsDetailInfoFragment comicsDetailInfoFragment, Chapter chapter, Function1 function1, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            function1 = new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$checkMoneyForBuyChapter$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                    invoke(bool.booleanValue());
                    return Unit.INSTANCE;
                }

                public final void invoke(boolean z) {
                }
            };
        }
        comicsDetailInfoFragment.checkMoneyForBuyChapter(chapter, function1);
    }

    private final ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2.C36691 getBottomSeeToSeeAdapter() {
        return (ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2.C36691) this.bottomSeeToSeeAdapter.getValue();
    }

    private final ComicsDetailInfoFragment$icoAdAdapter$2.C36701 getIcoAdAdapter() {
        return (ComicsDetailInfoFragment$icoAdAdapter$2.C36701) this.icoAdAdapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ComicsDetailInfoBean getMComicsDetailInfo() {
        return (ComicsDetailInfoBean) this.mComicsDetailInfo.getValue();
    }

    private final ComicsDetailInfoFragment$tableContentAdapter$2.C36711 getTableContentAdapter() {
        return (ComicsDetailInfoFragment$tableContentAdapter$2.C36711) this.tableContentAdapter.getValue();
    }

    private final void initBannerView(final List<AdBean> mBanners) {
        if (mBanners == null || mBanners.isEmpty()) {
            return;
        }
        Banner<?, ?> banner_comics = getBanner_comics();
        banner_comics.setIntercept(mBanners.size() != 1);
        Banner addBannerLifecycleObserver = banner_comics.addBannerLifecycleObserver(this);
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(mBanners, 10));
        Iterator<T> it = mBanners.iterator();
        while (it.hasNext()) {
            arrayList.add(((AdBean) it.next()).content);
        }
        addBannerLifecycleObserver.setAdapter(new BannerAdapterImp(requireContext, arrayList, 0.0f, ShadowDrawableWrapper.COS_45, null, 20));
        banner_comics.setOnBannerListener(new OnBannerListener() { // from class: b.a.a.a.t.d.h
            @Override // com.youth.banner.listener.OnBannerListener
            public final void OnBannerClick(Object obj, int i2) {
                ComicsDetailInfoFragment.m5759initBannerView$lambda7$lambda6(ComicsDetailInfoFragment.this, mBanners, obj, i2);
            }
        });
        banner_comics.setIndicator(new RectangleIndicator(requireContext()));
        banner_comics.addOnPageChangeListener(new OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$initBannerView$1$3
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
        banner_comics.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initBannerView$lambda-7$lambda-6, reason: not valid java name */
    public static final void m5759initBannerView$lambda7$lambda6(ComicsDetailInfoFragment this$0, List list, Object obj, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        C0840d.a aVar = C0840d.f235a;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        aVar.m176b(requireContext, (AdBean) list.get(i2));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initEvents$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5760initEvents$lambda1$lambda0(ComicsDetailInfoFragment this$0, ComicsViewModel this_run, List list) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2.C36691 bottomSeeToSeeAdapter = this$0.getBottomSeeToSeeAdapter();
        List<ComicsDetailInfoBean> value = this_run.getComicsItemBean().getValue();
        bottomSeeToSeeAdapter.setNewData(value == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) value));
        if (this$0.getBottomSeeToSeeAdapter() != null) {
            this$0.getBottomSeeToSeeAdapter().notifyDataSetChanged();
        }
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @NotNull
    public final Banner<?, ?> getBanner_comics() {
        return (Banner) this.banner_comics.getValue();
    }

    @NotNull
    public final ScaleRelativeLayout getBanner_parent_comics() {
        return (ScaleRelativeLayout) this.banner_parent_comics.getValue();
    }

    public final int getBottomDataPage() {
        return this.bottomDataPage;
    }

    @NotNull
    public final TextView getIv_chapterdetail_more() {
        return (TextView) this.iv_chapterdetail_more.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_comics_detailinfos;
    }

    @NotNull
    public final LinearLayout getLl_footer_change_bottom() {
        return (LinearLayout) this.ll_footer_change_bottom.getValue();
    }

    @NotNull
    public final LinearLayout getLl_showall_chapter() {
        return (LinearLayout) this.ll_showall_chapter.getValue();
    }

    @NotNull
    public final RecyclerView getRv_banner_ico_comicsdetail() {
        return (RecyclerView) this.rv_banner_ico_comicsdetail.getValue();
    }

    @NotNull
    public final RecyclerView getRv_related_items() {
        return (RecyclerView) this.rv_related_items.getValue();
    }

    @NotNull
    public final RecyclerView getRv_seetosee_bottom() {
        return (RecyclerView) this.rv_seetosee_bottom.getValue();
    }

    @NotNull
    public final TextView getTv_banner_bottom() {
        return (TextView) this.tv_banner_bottom.getValue();
    }

    @NotNull
    public final TextView getTv_banner_top() {
        return (TextView) this.tv_banner_top.getValue();
    }

    @NotNull
    public final TextView getTv_tablecontent_subtitle() {
        return (TextView) this.tv_tablecontent_subtitle.getValue();
    }

    @NotNull
    public final ComicsViewModel getViewModel() {
        return (ComicsViewModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initEvents() {
        MyThemeFragment.fadeWhenTouch$default(this, getLl_showall_chapter(), 0.0f, 1, null);
        C2354n.m2374A(getLl_showall_chapter(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$initEvents$1
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
                ComicsDetailInfoBean mComicsDetailInfo;
                Intrinsics.checkNotNullParameter(it, "it");
                mComicsDetailInfo = ComicsDetailInfoFragment.this.getMComicsDetailInfo();
                if (mComicsDetailInfo == null) {
                    return;
                }
                ComicsDetailInfoFragment comicsDetailInfoFragment = ComicsDetailInfoFragment.this;
                ComicsTableContentAllActivity.Companion companion = ComicsTableContentAllActivity.INSTANCE;
                Context requireContext = comicsDetailInfoFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext, mComicsDetailInfo);
            }
        }, 1);
        MyThemeFragment.fadeWhenTouch$default(this, getLl_footer_change_bottom(), 0.0f, 1, null);
        C2354n.m2374A(getLl_footer_change_bottom(), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$initEvents$2
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
                ComicsDetailInfoBean mComicsDetailInfo;
                Intrinsics.checkNotNullParameter(it, "it");
                ComicsDetailInfoFragment comicsDetailInfoFragment = ComicsDetailInfoFragment.this;
                comicsDetailInfoFragment.setBottomDataPage(comicsDetailInfoFragment.getBottomDataPage() + 1);
                mComicsDetailInfo = ComicsDetailInfoFragment.this.getMComicsDetailInfo();
                if (mComicsDetailInfo == null) {
                    return;
                }
                ComicsViewModel viewModel = ComicsDetailInfoFragment.this.getViewModel();
                String str = mComicsDetailInfo.related_filter;
                Intrinsics.checkNotNullExpressionValue(str, "it1.related_filter");
                ComicsViewModel.comicsSearch$default(viewModel, str, false, 2, null);
            }
        }, 1);
        C2354n.m2374A(getIv_chapterdetail_more(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$initEvents$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull TextView it) {
                ComicsDetailInfoBean mComicsDetailInfo;
                Intrinsics.checkNotNullParameter(it, "it");
                mComicsDetailInfo = ComicsDetailInfoFragment.this.getMComicsDetailInfo();
                if (mComicsDetailInfo == null) {
                    return;
                }
                ComicsDetailInfoFragment comicsDetailInfoFragment = ComicsDetailInfoFragment.this;
                ComicsChapterViewActivity.Companion companion = ComicsChapterViewActivity.INSTANCE;
                Context requireContext = comicsDetailInfoFragment.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
                companion.start(requireContext, mComicsDetailInfo);
            }
        }, 1);
        final ComicsViewModel viewModel = getViewModel();
        viewModel.getComicsItemBean().observe(this, new Observer() { // from class: b.a.a.a.t.d.k
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                ComicsDetailInfoFragment.m5760initEvents$lambda1$lambda0(ComicsDetailInfoFragment.this, viewModel, (List) obj);
            }
        });
        ComicsDetailInfoBean mComicsDetailInfo = getMComicsDetailInfo();
        if (mComicsDetailInfo.f10009ad != null) {
            getTv_banner_top().setVisibility(0);
            getTv_banner_bottom().setVisibility(0);
            getBanner_parent_comics().setVisibility(0);
            AdBean ad = mComicsDetailInfo.f10009ad;
            Intrinsics.checkNotNullExpressionValue(ad, "ad");
            initBannerView(CollectionsKt__CollectionsKt.arrayListOf(ad));
        } else {
            getTv_banner_top().setVisibility(8);
            getTv_banner_bottom().setVisibility(8);
            getBanner_parent_comics().setVisibility(8);
        }
        if (mComicsDetailInfo.detail_page_ad_show_method.equals("ico")) {
            List<AdBean> ico_ads = mComicsDetailInfo.ico_ads;
            Intrinsics.checkNotNullExpressionValue(ico_ads, "ico_ads");
            if (!ico_ads.isEmpty()) {
                getTv_banner_top().setVisibility(8);
                getTv_banner_bottom().setVisibility(8);
                getBanner_parent_comics().setVisibility(8);
                getRv_banner_ico_comicsdetail().setVisibility(0);
                RecyclerView rv_banner_ico_comicsdetail = getRv_banner_ico_comicsdetail();
                rv_banner_ico_comicsdetail.setAdapter(getIcoAdAdapter());
                ComicsDetailInfoFragment$icoAdAdapter$2.C36701 icoAdAdapter = getIcoAdAdapter();
                List<AdBean> ico_ads2 = mComicsDetailInfo.ico_ads;
                Intrinsics.checkNotNullExpressionValue(ico_ads2, "ico_ads");
                icoAdAdapter.setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) ico_ads2));
                rv_banner_ico_comicsdetail.setNestedScrollingEnabled(false);
                GridLayoutManager gridLayoutManager = new GridLayoutManager(requireContext(), 5);
                Unit unit = Unit.INSTANCE;
                rv_banner_ico_comicsdetail.setLayoutManager(gridLayoutManager);
                if (rv_banner_ico_comicsdetail.getItemDecorationCount() == 0) {
                    GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_banner_ico_comicsdetail.getContext());
                    c4053a.m4576a(R.color.transparent);
                    c4053a.f10339g = false;
                    c4053a.f10340h = false;
                    c4053a.f10338f = false;
                    rv_banner_ico_comicsdetail.addItemDecoration(new GridItemDecoration(c4053a));
                }
            }
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        ArrayList<ComicsDetailInfoBean> arrayList;
        List<Chapter> list;
        ArrayList<Chapter> arrayList2;
        String str;
        ArrayList<Chapter> arrayList3;
        ArrayList<Chapter> arrayList4;
        super.initViews();
        this.bottomDataPage = 0;
        TextView tv_tablecontent_subtitle = getTv_tablecontent_subtitle();
        ComicsDetailInfoBean mComicsDetailInfo = getMComicsDetailInfo();
        List list2 = null;
        tv_tablecontent_subtitle.setText(mComicsDetailInfo == null ? null : mComicsDetailInfo.sub_title);
        ComicsDetailInfoBean mComicsDetailInfo2 = getMComicsDetailInfo();
        Integer valueOf = (mComicsDetailInfo2 == null || (arrayList4 = mComicsDetailInfo2.chapter) == null) ? null : Integer.valueOf(arrayList4.size());
        Intrinsics.checkNotNull(valueOf);
        if (valueOf.intValue() < 3) {
            getLl_showall_chapter().setVisibility(8);
        } else {
            getLl_showall_chapter().setVisibility(0);
        }
        ComicsDetailInfoBean mComicsDetailInfo3 = getMComicsDetailInfo();
        Integer valueOf2 = (mComicsDetailInfo3 == null || (arrayList3 = mComicsDetailInfo3.chapter) == null) ? null : Integer.valueOf(arrayList3.size());
        Intrinsics.checkNotNull(valueOf2);
        int intValue = valueOf2.intValue();
        ComicsDetailInfoBean mComicsDetailInfo4 = getMComicsDetailInfo();
        Integer valueOf3 = (mComicsDetailInfo4 == null || (str = mComicsDetailInfo4.chapter_show_num) == null) ? null : Integer.valueOf(Integer.parseInt(str));
        Intrinsics.checkNotNull(valueOf3);
        if (intValue > valueOf3.intValue()) {
            ComicsDetailInfoFragment$tableContentAdapter$2.C36711 tableContentAdapter = getTableContentAdapter();
            ComicsDetailInfoBean mComicsDetailInfo5 = getMComicsDetailInfo();
            String str2 = mComicsDetailInfo5 == null ? null : mComicsDetailInfo5.chapter_show_num;
            if (str2 != null) {
                int parseInt = Integer.parseInt(str2);
                ComicsDetailInfoBean mComicsDetailInfo6 = getMComicsDetailInfo();
                if (mComicsDetailInfo6 != null && (arrayList2 = mComicsDetailInfo6.chapter) != null) {
                    list = arrayList2.subList(0, parseInt);
                    tableContentAdapter.setNewData(list);
                }
            }
            list = null;
            tableContentAdapter.setNewData(list);
        } else {
            ComicsDetailInfoFragment$tableContentAdapter$2.C36711 tableContentAdapter2 = getTableContentAdapter();
            ComicsDetailInfoBean mComicsDetailInfo7 = getMComicsDetailInfo();
            tableContentAdapter2.setNewData(mComicsDetailInfo7 == null ? null : mComicsDetailInfo7.chapter);
        }
        RecyclerView rv_related_items = getRv_related_items();
        if (rv_related_items.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_related_items.getContext());
            c4053a.m4576a(R.color.transparent);
            c4053a.f10339g = false;
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            C1499a.m604Z(c4053a, rv_related_items);
        }
        rv_related_items.setAdapter(getTableContentAdapter());
        rv_related_items.setLayoutManager(new GridLayoutManager(rv_related_items.getContext(), 1));
        ComicsDetailInfoFragment$bottomSeeToSeeAdapter$2.C36691 bottomSeeToSeeAdapter = getBottomSeeToSeeAdapter();
        ComicsDetailInfoBean mComicsDetailInfo8 = getMComicsDetailInfo();
        if (mComicsDetailInfo8 != null && (arrayList = mComicsDetailInfo8.related_items) != null) {
            list2 = CollectionsKt___CollectionsKt.toMutableList((Collection) arrayList);
        }
        bottomSeeToSeeAdapter.setNewData(list2);
        RecyclerView rv_seetosee_bottom = getRv_seetosee_bottom();
        if (rv_seetosee_bottom.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a2 = new GridItemDecoration.C4053a(rv_seetosee_bottom.getContext());
            c4053a2.f10336d = C1499a.m638x(c4053a2, R.color.transparent, rv_seetosee_bottom, 9.0d);
            c4053a2.f10337e = C2354n.m2437V(rv_seetosee_bottom.getContext(), 6.0d);
            c4053a2.f10339g = false;
            c4053a2.f10340h = false;
            c4053a2.f10338f = false;
            C1499a.m604Z(c4053a2, rv_seetosee_bottom);
        }
        rv_seetosee_bottom.setAdapter(getBottomSeeToSeeAdapter());
        rv_seetosee_bottom.setLayoutManager(new GridLayoutManager(requireContext(), 3));
    }

    public final void setBottomDataPage(int i2) {
        this.bottomDataPage = i2;
    }

    @NotNull
    public final ComicsViewModel viewModelInstance() {
        return getViewModel();
    }
}
