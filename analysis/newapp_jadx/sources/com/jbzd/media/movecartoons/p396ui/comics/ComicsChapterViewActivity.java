package com.jbzd.media.movecartoons.p396ui.comics;

import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.SeekBar;
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.ChatMsgBean;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.bean.response.comicschapterinfo.ComicsChapterInfoBean;
import com.jbzd.media.movecartoons.bean.response.comicschapterinfo.Content;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.Chapter;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsDetailInfoBean;
import com.jbzd.media.movecartoons.bean.response.home.NewAd;
import com.jbzd.media.movecartoons.core.MyThemeViewModelActivity;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsChapterViewActivity;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsChapterViewActivity$contentAdapter$2;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsChapterViewActivity$imageAdAdapter$2;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsTableContentAllActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.AutoChangePageDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.BuyDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.ComicsChapterRobotDialog;
import com.jbzd.media.movecartoons.p396ui.search.model.ComicsViewModel;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.wallet.RechargeActivity;
import com.jbzd.media.movecartoons.view.AdBottomBarView;
import com.jbzd.media.movecartoons.view.FullScreenAdMaskView;
import com.jbzd.media.movecartoons.view.LooperLayoutManager;
import com.jbzd.media.movecartoons.view.MarqueeRecyclerView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.ranges.IntRange;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.ComponentCallbacks2C1553c;
import p005b.p143g.p144a.p147m.EnumC1570b;
import p005b.p143g.p144a.p147m.p150t.AbstractC1643k;
import p005b.p143g.p144a.p166q.C1779f;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0094\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000b\n\u0002\b\u0011\n\u0002\u0018\u0002\n\u0002\b\u0010\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0007*\u0002\u001a6\u0018\u0000 \u008f\u00012\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002\u008f\u0001B\b¢\u0006\u0005\b\u008e\u0001\u0010\tJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\b\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ%\u0010\u0013\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u00032\u0006\u0010\u0010\u001a\u00020\u000f2\u0006\u0010\u0012\u001a\u00020\u0011¢\u0006\u0004\b\u0013\u0010\u0014J\u000f\u0010\u0015\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0015\u0010\tJ\u0019\u0010\u0018\u001a\u00020\u00052\b\u0010\u0017\u001a\u0004\u0018\u00010\u0016H\u0014¢\u0006\u0004\b\u0018\u0010\u0019R\u001d\u0010\u001f\u001a\u00020\u001a8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u001c\u001a\u0004\b\u001d\u0010\u001eR\u001d\u0010$\u001a\u00020 8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u001c\u001a\u0004\b\"\u0010#R\"\u0010%\u001a\u00020\u000f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b%\u0010&\u001a\u0004\b'\u0010(\"\u0004\b)\u0010*R\u001d\u0010/\u001a\u00020+8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\u001c\u001a\u0004\b-\u0010.R\u001d\u00102\u001a\u00020+8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\u001c\u001a\u0004\b1\u0010.R\u001d\u00105\u001a\u00020+8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b3\u0010\u001c\u001a\u0004\b4\u0010.R\u001d\u0010:\u001a\u0002068B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b7\u0010\u001c\u001a\u0004\b8\u00109R\"\u0010;\u001a\u00020\u000f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b;\u0010&\u001a\u0004\b<\u0010(\"\u0004\b=\u0010*R\u001d\u0010B\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b?\u0010\u001c\u001a\u0004\b@\u0010AR\u001d\u0010E\u001a\u00020+8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bC\u0010\u001c\u001a\u0004\bD\u0010.R\u001d\u0010I\u001a\u00020\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bF\u0010\u001c\u001a\u0004\bG\u0010HR\u001d\u0010L\u001a\u00020\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bJ\u0010\u001c\u001a\u0004\bK\u0010HR\u0016\u0010N\u001a\u00020M8\u0002@\u0002X\u0082\u0004¢\u0006\u0006\n\u0004\bN\u0010OR\u001d\u0010R\u001a\u00020+8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bP\u0010\u001c\u001a\u0004\bQ\u0010.R\u001d\u0010W\u001a\u00020S8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bT\u0010\u001c\u001a\u0004\bU\u0010VR\u001d\u0010Z\u001a\u00020\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bX\u0010\u001c\u001a\u0004\bY\u0010HR\"\u0010\\\u001a\u00020[8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\\\u0010]\u001a\u0004\b^\u0010_\"\u0004\b`\u0010aR\u001d\u0010d\u001a\u00020+8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bb\u0010\u001c\u001a\u0004\bc\u0010.R\"\u0010e\u001a\u00020\f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\be\u0010f\u001a\u0004\bg\u0010\u000e\"\u0004\bh\u0010iR\"\u0010j\u001a\u00020\u000f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bj\u0010&\u001a\u0004\bk\u0010(\"\u0004\bl\u0010*R\u001d\u0010q\u001a\u00020m8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bn\u0010\u001c\u001a\u0004\bo\u0010pR\u001f\u0010t\u001a\u0004\u0018\u00010\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\br\u0010\u001c\u001a\u0004\bs\u0010(R\u001d\u0010w\u001a\u00020+8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bu\u0010\u001c\u001a\u0004\bv\u0010.R\u001d\u0010z\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bx\u0010\u001c\u001a\u0004\by\u0010\u000bR\u001d\u0010}\u001a\u00020\u00118F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b{\u0010\u001c\u001a\u0004\b|\u0010HR \u0010\u0082\u0001\u001a\u00020~8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0004\b\u007f\u0010\u001c\u001a\u0006\b\u0080\u0001\u0010\u0081\u0001R\u001a\u0010\u0084\u0001\u001a\u00030\u0083\u00018\u0002@\u0002X\u0082.¢\u0006\b\n\u0006\b\u0084\u0001\u0010\u0085\u0001R \u0010\u0088\u0001\u001a\u00020+8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0086\u0001\u0010\u001c\u001a\u0005\b\u0087\u0001\u0010.R\"\u0010\u008d\u0001\u001a\u00030\u0089\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u008a\u0001\u0010\u001c\u001a\u0006\b\u008b\u0001\u0010\u008c\u0001¨\u0006\u0090\u0001"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/comics/ComicsChapterViewActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelActivity;", "Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "Landroid/content/Context;", "context", "", "showAutoChangePage", "(Landroid/content/Context;)V", "settingTools", "()V", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "", "getLayoutId", "()I", "", "url", "Landroid/widget/ImageView;", "target", "loadPreviewImage", "(Landroid/content/Context;Ljava/lang/String;Landroid/widget/ImageView;)V", "bindEvent", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "com/jbzd/media/movecartoons/ui/comics/ComicsChapterViewActivity$imageAdAdapter$2$1", "imageAdAdapter$delegate", "Lkotlin/Lazy;", "getImageAdAdapter", "()Lcom/jbzd/media/movecartoons/ui/comics/ComicsChapterViewActivity$imageAdAdapter$2$1;", "imageAdAdapter", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;", "comicsDetailInfoBean$delegate", "getComicsDetailInfoBean", "()Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;", "comicsDetailInfoBean", "scrollState", "Ljava/lang/String;", "getScrollState", "()Ljava/lang/String;", "setScrollState", "(Ljava/lang/String;)V", "Landroid/widget/TextView;", "tv_chapter_horizontal$delegate", "getTv_chapter_horizontal", "()Landroid/widget/TextView;", "tv_chapter_horizontal", "tv_titleRight$delegate", "getTv_titleRight", "tv_titleRight", "tv_chapter_auto$delegate", "getTv_chapter_auto", "tv_chapter_auto", "com/jbzd/media/movecartoons/ui/comics/ComicsChapterViewActivity$contentAdapter$2$1", "contentAdapter$delegate", "getContentAdapter", "()Lcom/jbzd/media/movecartoons/ui/comics/ComicsChapterViewActivity$contentAdapter$2$1;", "contentAdapter", "showModel", "getShowModel", "setShowModel", "Lcom/jbzd/media/movecartoons/view/MarqueeRecyclerView;", "rv_comicschapter_imgs$delegate", "getRv_comicschapter_imgs", "()Lcom/jbzd/media/movecartoons/view/MarqueeRecyclerView;", "rv_comicschapter_imgs", "tv_chapter_contenttable$delegate", "getTv_chapter_contenttable", "tv_chapter_contenttable", "iv_view_next$delegate", "getIv_view_next", "()Landroid/widget/ImageView;", "iv_view_next", "iv_titleLeftIcon$delegate", "getIv_titleLeftIcon", "iv_titleLeftIcon", "Lcom/jbzd/media/movecartoons/view/LooperLayoutManager;", "manager", "Lcom/jbzd/media/movecartoons/view/LooperLayoutManager;", "tv_name_comics$delegate", "getTv_name_comics", "tv_name_comics", "Landroidx/recyclerview/widget/RecyclerView;", "rv_list_adImg$delegate", "getRv_list_adImg", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_list_adImg", "iv_top_place$delegate", "getIv_top_place", "iv_top_place", "", "showTools", "Z", "getShowTools", "()Z", "setShowTools", "(Z)V", "tv_chapter_all$delegate", "getTv_chapter_all", "tv_chapter_all", "indexCurrent", "I", "getIndexCurrent", "setIndexCurrent", "(I)V", "chapterId", "getChapterId", "setChapterId", "Landroid/widget/FrameLayout;", "ll_comicschapterview_bottom$delegate", "getLl_comicschapterview_bottom", "()Landroid/widget/FrameLayout;", "ll_comicschapterview_bottom", "mChapterId$delegate", "getMChapterId", "mChapterId", "tv_chapter_vertical$delegate", "getTv_chapter_vertical", "tv_chapter_vertical", "viewModel$delegate", "getViewModel", "viewModel", "iv_view_last$delegate", "getIv_view_last", "iv_view_last", "Landroid/widget/SeekBar;", "progress_comicschapter$delegate", "getProgress_comicschapter", "()Landroid/widget/SeekBar;", "progress_comicschapter", "Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView;", "maskView", "Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView;", "tv_chapter_current$delegate", "getTv_chapter_current", "tv_chapter_current", "Landroid/widget/RelativeLayout;", "btn_titleRight$delegate", "getBtn_titleRight", "()Landroid/widget/RelativeLayout;", "btn_titleRight", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ComicsChapterViewActivity extends MyThemeViewModelActivity<ComicsViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    private int indexCurrent;
    private FullScreenAdMaskView maskView;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(ComicsViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$special$$inlined$viewModels$default$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewModelStore invoke() {
            ViewModelStore viewModelStore = ComponentActivity.this.getViewModelStore();
            Intrinsics.checkExpressionValueIsNotNull(viewModelStore, "viewModelStore");
            return viewModelStore;
        }
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$special$$inlined$viewModels$default$1
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewModelProvider.Factory invoke() {
            ViewModelProvider.Factory defaultViewModelProviderFactory = ComponentActivity.this.getDefaultViewModelProviderFactory();
            Intrinsics.checkExpressionValueIsNotNull(defaultViewModelProviderFactory, "defaultViewModelProviderFactory");
            return defaultViewModelProviderFactory;
        }
    });

    @NotNull
    private String chapterId = "";

    @NotNull
    private String scrollState = "0";

    @NotNull
    private String showModel = "0";
    private boolean showTools = true;

    /* renamed from: comicsDetailInfoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy comicsDetailInfoBean = LazyKt__LazyJVMKt.lazy(new Function0<ComicsDetailInfoBean>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$comicsDetailInfoBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ComicsDetailInfoBean invoke() {
            Serializable serializableExtra = ComicsChapterViewActivity.this.getIntent().getSerializableExtra("comicsDetailInfo");
            Objects.requireNonNull(serializableExtra, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsDetailInfoBean");
            return (ComicsDetailInfoBean) serializableExtra;
        }
    });

    /* renamed from: mChapterId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mChapterId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$mChapterId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ComicsChapterViewActivity.this.getIntent().getStringExtra("chapterId");
        }
    });

    @NotNull
    private final LooperLayoutManager manager = new LooperLayoutManager(this);

    /* renamed from: contentAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy contentAdapter = LazyKt__LazyJVMKt.lazy(new ComicsChapterViewActivity$contentAdapter$2(this));

    /* renamed from: rv_comicschapter_imgs$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_comicschapter_imgs = LazyKt__LazyJVMKt.lazy(new Function0<MarqueeRecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$rv_comicschapter_imgs$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MarqueeRecyclerView invoke() {
            MarqueeRecyclerView marqueeRecyclerView = (MarqueeRecyclerView) ComicsChapterViewActivity.this.findViewById(R.id.rv_comicschapter_imgs);
            Intrinsics.checkNotNull(marqueeRecyclerView);
            return marqueeRecyclerView;
        }
    });

    /* renamed from: iv_view_last$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_view_last = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$iv_view_last$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) ComicsChapterViewActivity.this.findViewById(R.id.iv_view_last);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: iv_view_next$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_view_next = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$iv_view_next$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) ComicsChapterViewActivity.this.findViewById(R.id.iv_view_next);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: ll_comicschapterview_bottom$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_comicschapterview_bottom = LazyKt__LazyJVMKt.lazy(new Function0<FrameLayout>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$ll_comicschapterview_bottom$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final FrameLayout invoke() {
            FrameLayout frameLayout = (FrameLayout) ComicsChapterViewActivity.this.findViewById(R.id.ll_comicschapterview_bottom);
            Intrinsics.checkNotNull(frameLayout);
            return frameLayout;
        }
    });

    /* renamed from: imageAdAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy imageAdAdapter = LazyKt__LazyJVMKt.lazy(new ComicsChapterViewActivity$imageAdAdapter$2(this));

    /* renamed from: tv_titleRight$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_titleRight = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$tv_titleRight$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsChapterViewActivity.this.findViewById(R.id.tv_titleRight);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: btn_titleRight$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy btn_titleRight = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$btn_titleRight$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            RelativeLayout relativeLayout = (RelativeLayout) ComicsChapterViewActivity.this.findViewById(R.id.btn_titleRight);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    /* renamed from: tv_chapter_vertical$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_chapter_vertical = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$tv_chapter_vertical$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsChapterViewActivity.this.findViewById(R.id.tv_chapter_vertical);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_chapter_horizontal$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_chapter_horizontal = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$tv_chapter_horizontal$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsChapterViewActivity.this.findViewById(R.id.tv_chapter_horizontal);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: iv_titleLeftIcon$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_titleLeftIcon = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$iv_titleLeftIcon$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) ComicsChapterViewActivity.this.findViewById(R.id.iv_titleLeftIcon);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_chapter_contenttable$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_chapter_contenttable = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$tv_chapter_contenttable$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsChapterViewActivity.this.findViewById(R.id.tv_chapter_contenttable);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_chapter_auto$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_chapter_auto = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$tv_chapter_auto$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsChapterViewActivity.this.findViewById(R.id.tv_chapter_auto);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_name_comics$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_name_comics = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$tv_name_comics$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsChapterViewActivity.this.findViewById(R.id.tv_name_comics);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_chapter_current$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_chapter_current = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$tv_chapter_current$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsChapterViewActivity.this.findViewById(R.id.tv_chapter_current);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_chapter_all$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_chapter_all = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$tv_chapter_all$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) ComicsChapterViewActivity.this.findViewById(R.id.tv_chapter_all);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: progress_comicschapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy progress_comicschapter = LazyKt__LazyJVMKt.lazy(new Function0<SeekBar>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$progress_comicschapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SeekBar invoke() {
            SeekBar seekBar = (SeekBar) ComicsChapterViewActivity.this.findViewById(R.id.progress_comicschapter);
            Intrinsics.checkNotNull(seekBar);
            return seekBar;
        }
    });

    /* renamed from: rv_list_adImg$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_list_adImg = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$rv_list_adImg$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) ComicsChapterViewActivity.this.findViewById(R.id.rv_list_adImg);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    /* renamed from: iv_top_place$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_top_place = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$iv_top_place$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) ComicsChapterViewActivity.this.findViewById(R.id.iv_top_place);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0006\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bJ%\u0010\u000b\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\n\u001a\u00020\t2\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u000b\u0010\f¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/comics/ComicsChapterViewActivity$Companion;", "", "Landroid/content/Context;", "context", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;", "mComicsDetailInfoBean", "", "start", "(Landroid/content/Context;Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;)V", "", "chapterId", "startFromComicsDetaial", "(Landroid/content/Context;Ljava/lang/String;Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context, @NotNull ComicsDetailInfoBean mComicsDetailInfoBean) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(mComicsDetailInfoBean, "mComicsDetailInfoBean");
            Intent intent = new Intent(context, (Class<?>) ComicsChapterViewActivity.class);
            intent.putExtra("comicsDetailInfo", mComicsDetailInfoBean);
            intent.putExtra("chapterId", mComicsDetailInfoBean.last_chapter_id);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }

        public final void startFromComicsDetaial(@NotNull Context context, @NotNull String chapterId, @NotNull ComicsDetailInfoBean mComicsDetailInfoBean) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(chapterId, "chapterId");
            Intrinsics.checkNotNullParameter(mComicsDetailInfoBean, "mComicsDetailInfoBean");
            ArrayList<Chapter> arrayList = mComicsDetailInfoBean.chapter;
            Intent intent = new Intent(context, (Class<?>) ComicsChapterViewActivity.class);
            intent.putExtra("comicsDetailInfo", mComicsDetailInfoBean);
            intent.putExtra("chapterId", chapterId);
            new Bundle();
            intent.putParcelableArrayListExtra("chapters", arrayList);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-6$lambda-3, reason: not valid java name */
    public static final void m5748bindEvent$lambda6$lambda3(final ComicsChapterViewActivity this$0, final ComicsViewModel this_run, final ComicsChapterInfoBean comicsChapterInfoBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        if (comicsChapterInfoBean.can_view.equals("n")) {
            if (comicsChapterInfoBean.type.equals("captcha")) {
                new ComicsChapterRobotDialog(this$0.getViewModel(), "", new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$12$1$1
                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(String str) {
                        invoke2(str);
                        return Unit.INSTANCE;
                    }

                    /* renamed from: invoke, reason: avoid collision after fix types in other method */
                    public final void invoke2(@NotNull String it) {
                        Intrinsics.checkNotNullParameter(it, "it");
                    }
                }).show(this$0.getSupportFragmentManager(), "ComicsChapterRobotDialog");
                return;
            }
            if (comicsChapterInfoBean.type.equals(VideoTypeBean.video_type_vip)) {
                MyApp myApp = MyApp.f9891f;
                if (MyApp.f9892g.isVipUser()) {
                    return;
                }
                String str = comicsChapterInfoBean.type;
                Intrinsics.checkNotNullExpressionValue(str, "it.type");
                new BuyDialog("", str, "需要开通VIP才可以看哦~.~", new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$12$1$2
                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    {
                        super(1);
                    }

                    @Override // kotlin.jvm.functions.Function1
                    public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                        invoke(bool.booleanValue());
                        return Unit.INSTANCE;
                    }

                    public final void invoke(boolean z) {
                        if (z) {
                            ComicsChapterInfoBean value = ComicsViewModel.this.getComicsChapterInfoBean().getValue();
                            if (StringsKt__StringsJVMKt.equals$default(value == null ? null : value.type, VideoTypeBean.video_type_vip, false, 2, null)) {
                                BuyActivity.INSTANCE.start(this$0);
                            } else {
                                RechargeActivity.INSTANCE.start(this$0);
                            }
                        }
                    }
                }).show(this$0.getSupportFragmentManager(), "vipDialog");
                return;
            }
            return;
        }
        this$0.getTv_name_comics().setText(comicsChapterInfoBean.chapter.name);
        this$0.getTv_chapter_current().setText("0");
        this$0.getTv_chapter_all().setText(String.valueOf(comicsChapterInfoBean.chapter.content.size()));
        ComicsChapterViewActivity$contentAdapter$2.C36621 contentAdapter = this$0.getContentAdapter();
        List<Content> list = comicsChapterInfoBean.chapter.content;
        Intrinsics.checkNotNullExpressionValue(list, "it.chapter.content");
        contentAdapter.setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) list));
        MarqueeRecyclerView rv_comicschapter_imgs = this$0.getRv_comicschapter_imgs();
        if (rv_comicschapter_imgs.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_comicschapter_imgs.getContext());
            c4053a.m4576a(R.color.transparent);
            c4053a.f10339g = false;
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            rv_comicschapter_imgs.addItemDecoration(new GridItemDecoration(c4053a));
        }
        rv_comicschapter_imgs.setSpeed(10L);
        rv_comicschapter_imgs.setScrollVertical(true);
        rv_comicschapter_imgs.setAdapter(this$0.getContentAdapter());
        rv_comicschapter_imgs.setLayoutManager(new LinearLayoutManager(rv_comicschapter_imgs.getContext(), 1, false));
        this$0.getRv_comicschapter_imgs().addOnScrollListener(new RecyclerView.OnScrollListener() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$12$1$4
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(@NotNull RecyclerView recyclerView, int newState) {
                Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
                super.onScrollStateChanged(recyclerView, newState);
                if (newState == 0) {
                    ComicsChapterViewActivity.this.setScrollState("0");
                    ComicsChapterViewActivity.this.getIv_view_last().setVisibility(8);
                    ComicsChapterViewActivity.this.getIv_view_next().setVisibility(8);
                    ComicsChapterViewActivity.this.getLl_comicschapterview_bottom().setVisibility(8);
                } else if (newState == 1) {
                    ComicsChapterViewActivity.this.setScrollState(ChatMsgBean.SERVICE_ID);
                } else if (newState == 2) {
                    ComicsChapterViewActivity.this.setScrollState("0");
                }
                ComicsChapterViewActivity.this.getIv_view_last().setVisibility(8);
                ComicsChapterViewActivity.this.getIv_view_next().setVisibility(8);
                ComicsChapterViewActivity.this.getLl_comicschapterview_bottom().setVisibility(8);
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(@NotNull RecyclerView recyclerView, int dx, int dy) {
                Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
                super.onScrolled(recyclerView, dx, dy);
                RecyclerView.LayoutManager layoutManager = recyclerView.getLayoutManager();
                Objects.requireNonNull(layoutManager, "null cannot be cast to non-null type androidx.recyclerview.widget.LinearLayoutManager");
                ComicsChapterViewActivity.this.getTv_chapter_current().setText(String.valueOf(((LinearLayoutManager) layoutManager).findFirstVisibleItemPosition() + 1));
                String format = String.format("%.2f", Arrays.copyOf(new Object[]{Float.valueOf(Float.parseFloat(ComicsChapterViewActivity.this.getTv_chapter_current().getText().toString()) / comicsChapterInfoBean.chapter.content.size())}, 1));
                Intrinsics.checkNotNullExpressionValue(format, "format(this, *args)");
                ComicsChapterViewActivity.this.getProgress_comicschapter().setProgress((int) (Float.parseFloat(format) * 100));
            }
        });
        this$0.getProgress_comicschapter().setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$12$1$5
            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onProgressChanged(@NotNull SeekBar seekBar, int progress, boolean fromUser) {
                Intrinsics.checkNotNullParameter(seekBar, "seekBar");
                this$0.getTv_chapter_current().setText(String.valueOf((int) (progress * 0.01d * ComicsChapterInfoBean.this.chapter.content.size())));
            }

            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onStartTrackingTouch(@NotNull SeekBar seekBar) {
                Intrinsics.checkNotNullParameter(seekBar, "seekBar");
            }

            @Override // android.widget.SeekBar.OnSeekBarChangeListener
            public void onStopTrackingTouch(@NotNull SeekBar seekBar) {
                Intrinsics.checkNotNullParameter(seekBar, "seekBar");
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-6$lambda-5, reason: not valid java name */
    public static final void m5749bindEvent$lambda6$lambda5(ComicsChapterViewActivity this$0, Boolean it) {
        String mChapterId;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        if (!it.booleanValue() || (mChapterId = this$0.getMChapterId()) == null) {
            return;
        }
        ComicsViewModel.comicsChapterDetail$default(this$0.getViewModel(), mChapterId, false, 2, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ComicsDetailInfoBean getComicsDetailInfoBean() {
        return (ComicsDetailInfoBean) this.comicsDetailInfoBean.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ComicsChapterViewActivity$contentAdapter$2.C36621 getContentAdapter() {
        return (ComicsChapterViewActivity$contentAdapter$2.C36621) this.contentAdapter.getValue();
    }

    private final ComicsChapterViewActivity$imageAdAdapter$2.C36631 getImageAdAdapter() {
        return (ComicsChapterViewActivity$imageAdAdapter$2.C36631) this.imageAdAdapter.getValue();
    }

    private final String getMChapterId() {
        return (String) this.mChapterId.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void settingTools() {
        if (getIv_view_last().getVisibility() == 8 && Intrinsics.areEqual(this.scrollState, "0")) {
            getIv_view_last().setVisibility(0);
            getIv_view_next().setVisibility(0);
            getLl_comicschapterview_bottom().setVisibility(0);
        } else {
            getIv_view_last().setVisibility(8);
            getIv_view_next().setVisibility(8);
            getLl_comicschapterview_bottom().setVisibility(8);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showAutoChangePage(Context context) {
        new AutoChangePageDialog(11 - getRv_comicschapter_imgs().getSpeed(), new Function2<Integer, Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$showAutoChangePage$1
            {
                super(2);
            }

            @Override // kotlin.jvm.functions.Function2
            public /* bridge */ /* synthetic */ Unit invoke(Integer num, Boolean bool) {
                invoke(num.intValue(), bool.booleanValue());
                return Unit.INSTANCE;
            }

            public final void invoke(int i2, boolean z) {
                if (!z) {
                    ComicsChapterViewActivity.this.getRv_comicschapter_imgs().setAutoRun(false);
                    ComicsChapterViewActivity.this.getRv_comicschapter_imgs().stop();
                    return;
                }
                ComicsChapterViewActivity.this.getRv_comicschapter_imgs().speed = 11 - i2;
                ComicsChapterViewActivity.this.getRv_comicschapter_imgs().setAutoRun(true);
                ComicsChapterViewActivity.this.getRv_comicschapter_imgs().start();
                ComicsChapterViewActivity.this.setScrollState("1");
                ComicsChapterViewActivity.this.settingTools();
            }
        }).show(((ComicsChapterViewActivity) context).getSupportFragmentManager(), "ComicsChapterViewActivity");
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        this.chapterId = String.valueOf(getMChapterId());
        ArrayList<Chapter> arrayList = getComicsDetailInfoBean().chapter;
        Intrinsics.checkNotNullExpressionValue(arrayList, "comicsDetailInfoBean.chapter");
        IntRange indices = CollectionsKt__CollectionsKt.getIndices(arrayList);
        Intrinsics.checkNotNull(indices);
        int first = indices.getFirst();
        int last = indices.getLast();
        if (first <= last) {
            while (true) {
                int i2 = first + 1;
                if (Intrinsics.areEqual(this.chapterId, getComicsDetailInfoBean().chapter.get(first).f10008id)) {
                    this.indexCurrent = first;
                }
                if (first == last) {
                    break;
                } else {
                    first = i2;
                }
            }
        }
        MyApp myApp = MyApp.f9891f;
        Intrinsics.checkNotNullExpressionValue(MyApp.m4185f().comics_detail_ads_top, "MyApp.systemBean.comics_detail_ads_top");
        if (!r0.isEmpty()) {
            getIv_top_place().setVisibility(0);
            getRv_list_adImg().setVisibility(0);
            RecyclerView rv_list_adImg = getRv_list_adImg();
            rv_list_adImg.setAdapter(getImageAdAdapter());
            if (MyApp.m4185f().comics_detail_ads_top != null) {
                if (MyApp.m4185f().comics_detail_ads_top.size() > 3) {
                    getImageAdAdapter().setNewData(MyApp.m4185f().comics_detail_ads_top.subList(0, 3));
                } else {
                    getImageAdAdapter().setNewData(MyApp.m4185f().comics_detail_ads_top);
                }
                rv_list_adImg.setLayoutManager(new GridLayoutManager(this, 3));
                if (rv_list_adImg.getItemDecorationCount() == 0) {
                    GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_list_adImg.getContext());
                    c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, rv_list_adImg, 6.0d);
                    c4053a.f10337e = C2354n.m2437V(rv_list_adImg.getContext(), 6.0d);
                    c4053a.f10339g = false;
                    c4053a.f10340h = false;
                    c4053a.f10338f = false;
                    C1499a.m604Z(c4053a, rv_list_adImg);
                }
            }
        } else {
            getRv_list_adImg().setVisibility(8);
            getIv_top_place().setVisibility(8);
        }
        C2354n.m2374A(getTv_titleRight(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$2
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
                Intrinsics.checkNotNullParameter(it, "it");
                InviteActivity.INSTANCE.start(ComicsChapterViewActivity.this);
            }
        }, 1);
        C2354n.m2374A(getBtn_titleRight(), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                invoke2(relativeLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull RelativeLayout it) {
                Intrinsics.checkNotNullParameter(it, "it");
                InviteActivity.INSTANCE.start(ComicsChapterViewActivity.this);
            }
        }, 1);
        getTv_chapter_vertical().setSelected(true);
        getTv_chapter_horizontal().setSelected(false);
        C2354n.m2374A(getIv_titleLeftIcon(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$4
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                Intrinsics.checkNotNullParameter(it, "it");
                ComicsChapterViewActivity.this.onBackPressed();
            }
        }, 1);
        MyThemeViewModelActivity.fadeWhenTouch$default(this, getIv_view_last(), 0.0f, 1, null);
        MyThemeViewModelActivity.fadeWhenTouch$default(this, getIv_view_next(), 0.0f, 1, null);
        MyThemeViewModelActivity.fadeWhenTouch$default(this, getTv_chapter_contenttable(), 0.0f, 1, null);
        MyThemeViewModelActivity.fadeWhenTouch$default(this, getTv_chapter_vertical(), 0.0f, 1, null);
        MyThemeViewModelActivity.fadeWhenTouch$default(this, getTv_chapter_horizontal(), 0.0f, 1, null);
        MyThemeViewModelActivity.fadeWhenTouch$default(this, getTv_chapter_auto(), 0.0f, 1, null);
        C2354n.m2374A(getIv_view_last(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$5
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                ComicsDetailInfoBean comicsDetailInfoBean;
                FullScreenAdMaskView fullScreenAdMaskView;
                ComicsDetailInfoBean comicsDetailInfoBean2;
                ComicsDetailInfoBean comicsDetailInfoBean3;
                Intrinsics.checkNotNullParameter(it, "it");
                if (ComicsChapterViewActivity.this.getIndexCurrent() > 0) {
                    ComicsChapterViewActivity.this.setIndexCurrent(r5.getIndexCurrent() - 1);
                    ComicsChapterViewActivity comicsChapterViewActivity = ComicsChapterViewActivity.this;
                    comicsDetailInfoBean3 = comicsChapterViewActivity.getComicsDetailInfoBean();
                    String str = comicsDetailInfoBean3.chapter.get(ComicsChapterViewActivity.this.getIndexCurrent()).f10008id;
                    Intrinsics.checkNotNullExpressionValue(str, "comicsDetailInfoBean.chapter[indexCurrent].id");
                    comicsChapterViewActivity.setChapterId(str);
                    ComicsViewModel.comicsChapterDetail$default(ComicsChapterViewActivity.this.getViewModel(), ComicsChapterViewActivity.this.getChapterId(), false, 2, null);
                } else {
                    C2354n.m2379B1("已经是第1话了~.~");
                }
                comicsDetailInfoBean = ComicsChapterViewActivity.this.getComicsDetailInfoBean();
                if (Intrinsics.areEqual(comicsDetailInfoBean.chapter.get(ComicsChapterViewActivity.this.getIndexCurrent()).show_adv_full, "y")) {
                    fullScreenAdMaskView = ComicsChapterViewActivity.this.maskView;
                    if (fullScreenAdMaskView == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("maskView");
                        throw null;
                    }
                    comicsDetailInfoBean2 = ComicsChapterViewActivity.this.getComicsDetailInfoBean();
                    fullScreenAdMaskView.show(comicsDetailInfoBean2.adv_full);
                }
            }
        }, 1);
        C2354n.m2374A(getIv_view_next(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$6
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ImageView imageView) {
                invoke2(imageView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull ImageView it) {
                ComicsDetailInfoBean comicsDetailInfoBean;
                ComicsDetailInfoBean comicsDetailInfoBean2;
                FullScreenAdMaskView fullScreenAdMaskView;
                ComicsDetailInfoBean comicsDetailInfoBean3;
                ComicsDetailInfoBean comicsDetailInfoBean4;
                Intrinsics.checkNotNullParameter(it, "it");
                int indexCurrent = ComicsChapterViewActivity.this.getIndexCurrent();
                comicsDetailInfoBean = ComicsChapterViewActivity.this.getComicsDetailInfoBean();
                if (indexCurrent < comicsDetailInfoBean.chapter.size() - 1) {
                    ComicsChapterViewActivity comicsChapterViewActivity = ComicsChapterViewActivity.this;
                    comicsChapterViewActivity.setIndexCurrent(comicsChapterViewActivity.getIndexCurrent() + 1);
                    ComicsChapterViewActivity comicsChapterViewActivity2 = ComicsChapterViewActivity.this;
                    comicsDetailInfoBean4 = comicsChapterViewActivity2.getComicsDetailInfoBean();
                    String str = comicsDetailInfoBean4.chapter.get(ComicsChapterViewActivity.this.getIndexCurrent()).f10008id;
                    Intrinsics.checkNotNullExpressionValue(str, "comicsDetailInfoBean.chapter[indexCurrent].id");
                    comicsChapterViewActivity2.setChapterId(str);
                    ComicsViewModel.comicsChapterDetail$default(ComicsChapterViewActivity.this.getViewModel(), ComicsChapterViewActivity.this.getChapterId(), false, 2, null);
                } else {
                    C2354n.m2379B1("已经是最后话了哦~.~");
                }
                comicsDetailInfoBean2 = ComicsChapterViewActivity.this.getComicsDetailInfoBean();
                if (Intrinsics.areEqual(comicsDetailInfoBean2.chapter.get(ComicsChapterViewActivity.this.getIndexCurrent()).show_adv_full, "y")) {
                    fullScreenAdMaskView = ComicsChapterViewActivity.this.maskView;
                    if (fullScreenAdMaskView == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("maskView");
                        throw null;
                    }
                    comicsDetailInfoBean3 = ComicsChapterViewActivity.this.getComicsDetailInfoBean();
                    fullScreenAdMaskView.show(comicsDetailInfoBean3.adv_full);
                }
            }
        }, 1);
        C2354n.m2374A(getTv_chapter_contenttable(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$7
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
                ComicsDetailInfoBean comicsDetailInfoBean;
                Intrinsics.checkNotNullParameter(it, "it");
                ComicsTableContentAllActivity.Companion companion = ComicsTableContentAllActivity.Companion;
                ComicsChapterViewActivity comicsChapterViewActivity = ComicsChapterViewActivity.this;
                comicsDetailInfoBean = comicsChapterViewActivity.getComicsDetailInfoBean();
                companion.start(comicsChapterViewActivity, comicsDetailInfoBean);
            }
        }, 1);
        C2354n.m2374A(getTv_chapter_vertical(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$8
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
                ComicsChapterViewActivity$contentAdapter$2.C36621 contentAdapter;
                Intrinsics.checkNotNullParameter(it, "it");
                if (it.isSelected()) {
                    return;
                }
                ComicsChapterViewActivity.this.getTv_chapter_vertical().setSelected(true);
                ComicsChapterViewActivity.this.getTv_chapter_horizontal().setSelected(false);
                ComicsChapterViewActivity.this.setShowModel("0");
                MarqueeRecyclerView rv_comicschapter_imgs = ComicsChapterViewActivity.this.getRv_comicschapter_imgs();
                ComicsChapterViewActivity comicsChapterViewActivity = ComicsChapterViewActivity.this;
                if (rv_comicschapter_imgs.getItemDecorationCount() == 0) {
                    GridItemDecoration.C4053a c4053a2 = new GridItemDecoration.C4053a(rv_comicschapter_imgs.getContext());
                    c4053a2.m4576a(R.color.transparent);
                    c4053a2.f10339g = false;
                    c4053a2.f10340h = false;
                    c4053a2.f10338f = false;
                    rv_comicschapter_imgs.addItemDecoration(new GridItemDecoration(c4053a2));
                }
                rv_comicschapter_imgs.setSpeed(10L);
                rv_comicschapter_imgs.setScrollVertical(true);
                contentAdapter = comicsChapterViewActivity.getContentAdapter();
                rv_comicschapter_imgs.setAdapter(contentAdapter);
                rv_comicschapter_imgs.setLayoutManager(new LinearLayoutManager(rv_comicschapter_imgs.getContext(), 1, false));
            }
        }, 1);
        C2354n.m2374A(getTv_chapter_horizontal(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$9
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
                ComicsChapterViewActivity$contentAdapter$2.C36621 contentAdapter;
                Intrinsics.checkNotNullParameter(it, "it");
                if (it.isSelected()) {
                    return;
                }
                ComicsChapterViewActivity.this.getTv_chapter_vertical().setSelected(false);
                ComicsChapterViewActivity.this.getTv_chapter_horizontal().setSelected(true);
                ComicsChapterViewActivity.this.setShowModel("1");
                MarqueeRecyclerView rv_comicschapter_imgs = ComicsChapterViewActivity.this.getRv_comicschapter_imgs();
                ComicsChapterViewActivity comicsChapterViewActivity = ComicsChapterViewActivity.this;
                if (rv_comicschapter_imgs.getItemDecorationCount() == 0) {
                    GridItemDecoration.C4053a c4053a2 = new GridItemDecoration.C4053a(rv_comicschapter_imgs.getContext());
                    c4053a2.m4576a(R.color.transparent);
                    c4053a2.f10339g = false;
                    c4053a2.f10340h = false;
                    c4053a2.f10338f = false;
                    rv_comicschapter_imgs.addItemDecoration(new GridItemDecoration(c4053a2));
                }
                rv_comicschapter_imgs.setSpeed(10L);
                rv_comicschapter_imgs.setScrollVertical(false);
                contentAdapter = comicsChapterViewActivity.getContentAdapter();
                rv_comicschapter_imgs.setAdapter(contentAdapter);
                rv_comicschapter_imgs.setLayoutManager(new LinearLayoutManager(rv_comicschapter_imgs.getContext(), 0, false));
            }
        }, 1);
        C2354n.m2374A(getTv_chapter_auto(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$10
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
                Intrinsics.checkNotNullParameter(it, "it");
                ComicsChapterViewActivity comicsChapterViewActivity = ComicsChapterViewActivity.this;
                Context context = comicsChapterViewActivity.getTv_chapter_auto().getContext();
                Intrinsics.checkNotNullExpressionValue(context, "tv_chapter_auto.context");
                comicsChapterViewActivity.showAutoChangePage(context);
            }
        }, 1);
        String mChapterId = getMChapterId();
        if (mChapterId != null) {
            ComicsViewModel.comicsChapterDetail$default(getViewModel(), mChapterId, false, 2, null);
        }
        final ComicsViewModel viewModel = getViewModel();
        viewModel.getComicsChapterInfoBean().observe(this, new Observer() { // from class: b.a.a.a.t.d.d
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                ComicsChapterViewActivity.m5748bindEvent$lambda6$lambda3(ComicsChapterViewActivity.this, viewModel, (ComicsChapterInfoBean) obj);
            }
        });
        viewModel.getPicVerState().observe(this, new Observer() { // from class: b.a.a.a.t.d.c
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                ComicsChapterViewActivity.m5749bindEvent$lambda6$lambda5(ComicsChapterViewActivity.this, (Boolean) obj);
            }
        });
        int i3 = R$id.adBar;
        ((AdBottomBarView) findViewById(i3)).setListener(new AdBottomBarView.Listener() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$12$3
            @Override // com.jbzd.media.movecartoons.view.AdBottomBarView.Listener
            public void onAdClosed(@Nullable NewAd lastAd) {
            }

            @Override // com.jbzd.media.movecartoons.view.AdBottomBarView.Listener
            public void onVipClick(@Nullable NewAd currentAd) {
                BuyActivity.INSTANCE.start(ComicsChapterViewActivity.this);
            }
        });
        ((AdBottomBarView) findViewById(i3)).setInnerAd(getComicsDetailInfoBean().adv_float);
        ((AdBottomBarView) findViewById(i3)).show();
        FullScreenAdMaskView attachTo = FullScreenAdMaskView.INSTANCE.attachTo(this);
        this.maskView = attachTo;
        if (attachTo == null) {
            Intrinsics.throwUninitializedPropertyAccessException("maskView");
            throw null;
        }
        attachTo.setListener(new FullScreenAdMaskView.Listener() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsChapterViewActivity$bindEvent$12$4
            @Override // com.jbzd.media.movecartoons.view.FullScreenAdMaskView.Listener
            public void onDismiss() {
            }

            @Override // com.jbzd.media.movecartoons.view.FullScreenAdMaskView.Listener
            public void onMainButtonClick(@Nullable NewAd current) {
                C0840d.a aVar = C0840d.f235a;
                ComicsChapterViewActivity comicsChapterViewActivity = ComicsChapterViewActivity.this;
                Intrinsics.checkNotNull(current);
                aVar.m177c(comicsChapterViewActivity, current);
            }

            @Override // com.jbzd.media.movecartoons.view.FullScreenAdMaskView.Listener
            public void onVipClick(@Nullable NewAd current) {
                BuyActivity.INSTANCE.start(ComicsChapterViewActivity.this);
            }
        });
        if (Intrinsics.areEqual(getComicsDetailInfoBean().chapter.get(getIndexCurrent()).show_adv_full, "y")) {
            FullScreenAdMaskView fullScreenAdMaskView = this.maskView;
            if (fullScreenAdMaskView != null) {
                fullScreenAdMaskView.show(getComicsDetailInfoBean().adv_full);
            } else {
                Intrinsics.throwUninitializedPropertyAccessException("maskView");
                throw null;
            }
        }
    }

    @NotNull
    public final RelativeLayout getBtn_titleRight() {
        return (RelativeLayout) this.btn_titleRight.getValue();
    }

    @NotNull
    public final String getChapterId() {
        return this.chapterId;
    }

    public final int getIndexCurrent() {
        return this.indexCurrent;
    }

    @NotNull
    public final ImageView getIv_titleLeftIcon() {
        return (ImageView) this.iv_titleLeftIcon.getValue();
    }

    @NotNull
    public final ImageView getIv_top_place() {
        return (ImageView) this.iv_top_place.getValue();
    }

    @NotNull
    public final ImageView getIv_view_last() {
        return (ImageView) this.iv_view_last.getValue();
    }

    @NotNull
    public final ImageView getIv_view_next() {
        return (ImageView) this.iv_view_next.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_comicschapter_view;
    }

    @NotNull
    public final FrameLayout getLl_comicschapterview_bottom() {
        return (FrameLayout) this.ll_comicschapterview_bottom.getValue();
    }

    @NotNull
    public final SeekBar getProgress_comicschapter() {
        return (SeekBar) this.progress_comicschapter.getValue();
    }

    @NotNull
    public final MarqueeRecyclerView getRv_comicschapter_imgs() {
        return (MarqueeRecyclerView) this.rv_comicschapter_imgs.getValue();
    }

    @NotNull
    public final RecyclerView getRv_list_adImg() {
        return (RecyclerView) this.rv_list_adImg.getValue();
    }

    @NotNull
    public final String getScrollState() {
        return this.scrollState;
    }

    @NotNull
    public final String getShowModel() {
        return this.showModel;
    }

    public final boolean getShowTools() {
        return this.showTools;
    }

    @NotNull
    public final TextView getTv_chapter_all() {
        return (TextView) this.tv_chapter_all.getValue();
    }

    @NotNull
    public final TextView getTv_chapter_auto() {
        return (TextView) this.tv_chapter_auto.getValue();
    }

    @NotNull
    public final TextView getTv_chapter_contenttable() {
        return (TextView) this.tv_chapter_contenttable.getValue();
    }

    @NotNull
    public final TextView getTv_chapter_current() {
        return (TextView) this.tv_chapter_current.getValue();
    }

    @NotNull
    public final TextView getTv_chapter_horizontal() {
        return (TextView) this.tv_chapter_horizontal.getValue();
    }

    @NotNull
    public final TextView getTv_chapter_vertical() {
        return (TextView) this.tv_chapter_vertical.getValue();
    }

    @NotNull
    public final TextView getTv_name_comics() {
        return (TextView) this.tv_name_comics.getValue();
    }

    @NotNull
    public final TextView getTv_titleRight() {
        return (TextView) this.tv_titleRight.getValue();
    }

    @NotNull
    public final ComicsViewModel getViewModel() {
        return (ComicsViewModel) this.viewModel.getValue();
    }

    public final void loadPreviewImage(@NotNull Context context, @NotNull String url, @NotNull ImageView target) {
        String str;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(url, "url");
        Intrinsics.checkNotNullParameter(target, "target");
        C1779f c1779f = new C1779f();
        AbstractC1643k abstractC1643k = AbstractC1643k.f2222a;
        C1779f mo1097x = c1779f.mo1086i(abstractC1643k).mo1097x(Integer.MIN_VALUE, Integer.MIN_VALUE);
        EnumC1570b enumC1570b = EnumC1570b.PREFER_RGB_565;
        C1779f mo1088l = mo1097x.mo1090n(enumC1570b).mo1098y(R.drawable.ic_place_holder_vertical).mo1088l(R.drawable.ic_place_holder_vertical);
        Intrinsics.checkNotNullExpressionValue(mo1088l, "RequestOptions()\n            .diskCacheStrategy(DiskCacheStrategy.ALL)\n            .override(Target.SIZE_ORIGINAL, Target.SIZE_ORIGINAL)//关键代码，加载原始大小\n            .format(DecodeFormat.PREFER_RGB_565)//设置为这种格式去掉透明度通道，可以减少内存占有\n            .placeholder(\n                R.drawable.ic_place_holder_vertical\n            ).error(R.drawable.ic_place_holder_vertical)");
        C1779f c1779f2 = mo1088l;
        C1779f mo1088l2 = new C1779f().mo1086i(abstractC1643k).mo1097x(Integer.MIN_VALUE, Integer.MIN_VALUE).mo1090n(enumC1570b).mo1098y(R.drawable.ic_place_holder_vertical_51).mo1088l(R.drawable.ic_place_holder_vertical_51);
        Intrinsics.checkNotNullExpressionValue(mo1088l2, "RequestOptions()\n            .diskCacheStrategy(DiskCacheStrategy.ALL)\n            .override(Target.SIZE_ORIGINAL, Target.SIZE_ORIGINAL)//关键代码，加载原始大小\n            .format(DecodeFormat.PREFER_RGB_565)//设置为这种格式去掉透明度通道，可以减少内存占有\n            .placeholder(\n                R.drawable.ic_place_holder_vertical_51\n            ).error(R.drawable.ic_place_holder_vertical_51)");
        C1779f c1779f3 = mo1088l2;
        ApplicationC2828a context2 = C2827a.f7670a;
        if (context2 == null) {
            Intrinsics.throwUninitializedPropertyAccessException("context");
            throw null;
        }
        Intrinsics.checkNotNullParameter(context2, "context");
        try {
            PackageManager packageManager = context2.getPackageManager();
            ApplicationInfo applicationInfo = packageManager.getApplicationInfo(context2.getPackageName(), 128);
            Intrinsics.checkNotNullExpressionValue(applicationInfo, "manager.getApplicationInfo(context.packageName, PackageManager.GET_META_DATA)");
            str = (String) packageManager.getApplicationLabel(applicationInfo);
        } catch (PackageManager.NameNotFoundException unused) {
            str = "";
        }
        if (Intrinsics.areEqual(str != null ? Boolean.valueOf(StringsKt__StringsJVMKt.startsWith$default(str, "九妖", false, 2, null)) : null, Boolean.TRUE)) {
            ComponentCallbacks2C1553c.m738h(context).mo778k(c1779f2).mo775h(url).m757R(target);
        } else {
            ComponentCallbacks2C1553c.m738h(context).mo778k(c1779f3).mo775h(url).m757R(target);
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
    }

    public final void setChapterId(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.chapterId = str;
    }

    public final void setIndexCurrent(int i2) {
        this.indexCurrent = i2;
    }

    public final void setScrollState(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.scrollState = str;
    }

    public final void setShowModel(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.showModel = str;
    }

    public final void setShowTools(boolean z) {
        this.showTools = z;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelActivity
    @NotNull
    public ComicsViewModel viewModelInstance() {
        return getViewModel();
    }
}
