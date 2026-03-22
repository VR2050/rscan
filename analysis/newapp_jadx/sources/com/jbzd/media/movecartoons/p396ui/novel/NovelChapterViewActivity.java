package com.jbzd.media.movecartoons.p396ui.novel;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.lifecycle.MutableLiveData;
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
import com.jbzd.media.movecartoons.bean.response.home.NewAd;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapter;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapterInfoBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelDetailInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelActivity;
import com.jbzd.media.movecartoons.p396ui.dialog.AutoChangePageDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.BuyDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.ComicsChapterRobotDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.NovelReadSettingDialog;
import com.jbzd.media.movecartoons.p396ui.novel.NovelChapterViewActivity;
import com.jbzd.media.movecartoons.p396ui.novel.NovelChapterViewActivity$imageAdAdapter$2;
import com.jbzd.media.movecartoons.p396ui.novel.NovelChapterViewActivity$novelContentAdapter$2;
import com.jbzd.media.movecartoons.p396ui.novel.NovelTableContentAllActivity;
import com.jbzd.media.movecartoons.p396ui.search.model.ComicsViewModel;
import com.jbzd.media.movecartoons.p396ui.share.InviteActivity;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.wallet.RechargeActivity;
import com.jbzd.media.movecartoons.view.AdBottomBarView;
import com.jbzd.media.movecartoons.view.FullScreenAdMaskView;
import com.jbzd.media.movecartoons.view.InlineAdView;
import com.jbzd.media.movecartoons.view.MarqueeRecyclerView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsJVMKt;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.functions.Function4;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.ranges.IntRange;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0862o;
import p005b.p006a.p007a.p008a.p009a.C0866p;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2853d;
import p448i.p449a.p450a.C4349b;
import p458k.C4375d0;
import p458k.C4379f0;
import p458k.C4381g0;
import p458k.InterfaceC4369a0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0095\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0010 \n\u0002\u0010\u000e\n\u0002\b\u0010\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010\u000b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\t\n\u0002\u0010\u0007\n\u0002\b\u0011\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0010*\u0003p\u0083\u0001\u0018\u0000 \u0097\u00012\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002\u0097\u0001B\b¢\u0006\u0005\b\u0096\u0001\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0006\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0005J\u0017\u0010\t\u001a\u00020\u00032\u0006\u0010\b\u001a\u00020\u0007H\u0002¢\u0006\u0004\b\t\u0010\nJ\u0017\u0010\u000b\u001a\u00020\u00032\u0006\u0010\b\u001a\u00020\u0007H\u0002¢\u0006\u0004\b\u000b\u0010\nJ\u000f\u0010\f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000f\u001a\u00020\u000eH\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\u0003H\u0017¢\u0006\u0004\b\u0011\u0010\u0005J\u0019\u0010\u0014\u001a\u00020\u00032\b\u0010\u0013\u001a\u0004\u0018\u00010\u0012H\u0014¢\u0006\u0004\b\u0014\u0010\u0015J\u000f\u0010\u0016\u001a\u00020\u0003H\u0014¢\u0006\u0004\b\u0016\u0010\u0005J\u000f\u0010\u0017\u001a\u00020\u0003H\u0014¢\u0006\u0004\b\u0017\u0010\u0005R(\u0010\u001a\u001a\b\u0012\u0004\u0012\u00020\u00190\u00188\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001a\u0010\u001b\u001a\u0004\b\u001c\u0010\u001d\"\u0004\b\u001e\u0010\u001fR\u001d\u0010#\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b \u0010!\u001a\u0004\b\"\u0010\rR\"\u0010$\u001a\u00020\u00198\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b$\u0010%\u001a\u0004\b&\u0010'\"\u0004\b(\u0010)R\u001d\u0010.\u001a\u00020*8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b+\u0010!\u001a\u0004\b,\u0010-R\u001d\u00103\u001a\u00020/8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b0\u0010!\u001a\u0004\b1\u00102R\"\u00104\u001a\u00020\u00198\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b4\u0010%\u001a\u0004\b5\u0010'\"\u0004\b6\u0010)R\"\u00108\u001a\u0002078\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b8\u00109\u001a\u0004\b:\u0010;\"\u0004\b<\u0010=R\u001d\u0010B\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b?\u0010!\u001a\u0004\b@\u0010AR\"\u0010C\u001a\u00020>8\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\bC\u0010D\u001a\u0004\bE\u0010A\"\u0004\bF\u0010GR\"\u0010I\u001a\u00020H8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bI\u0010J\u001a\u0004\bK\u0010L\"\u0004\bM\u0010NR\"\u0010O\u001a\u00020\u000e8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bO\u0010P\u001a\u0004\bQ\u0010\u0010\"\u0004\bR\u0010SR\u001f\u0010V\u001a\u0004\u0018\u00010\u00198B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bT\u0010!\u001a\u0004\bU\u0010'R\u001d\u0010Y\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bW\u0010!\u001a\u0004\bX\u0010AR\u001d\u0010^\u001a\u00020Z8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b[\u0010!\u001a\u0004\b\\\u0010]R\u0016\u0010`\u001a\u00020_8\u0002@\u0002X\u0082.¢\u0006\u0006\n\u0004\b`\u0010aR\u001d\u0010f\u001a\u00020b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bc\u0010!\u001a\u0004\bd\u0010eR\u001d\u0010i\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bg\u0010!\u001a\u0004\bh\u0010AR\u001d\u0010l\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bj\u0010!\u001a\u0004\bk\u0010AR\"\u0010m\u001a\u00020\u00198\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\bm\u0010%\u001a\u0004\bn\u0010'\"\u0004\bo\u0010)R\u001d\u0010t\u001a\u00020p8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bq\u0010!\u001a\u0004\br\u0010sR\u001d\u0010w\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bu\u0010!\u001a\u0004\bv\u0010AR\u001d\u0010|\u001a\u00020x8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\by\u0010!\u001a\u0004\bz\u0010{R\u001d\u0010\u007f\u001a\u00020b8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b}\u0010!\u001a\u0004\b~\u0010eR \u0010\u0082\u0001\u001a\u00020>8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0080\u0001\u0010!\u001a\u0005\b\u0081\u0001\u0010AR\"\u0010\u0087\u0001\u001a\u00030\u0083\u00018B@\u0002X\u0082\u0084\u0002¢\u0006\u000f\n\u0005\b\u0084\u0001\u0010!\u001a\u0006\b\u0085\u0001\u0010\u0086\u0001R\"\u0010\u008c\u0001\u001a\u00030\u0088\u00018F@\u0006X\u0086\u0084\u0002¢\u0006\u000f\n\u0005\b\u0089\u0001\u0010!\u001a\u0006\b\u008a\u0001\u0010\u008b\u0001R&\u0010\u008d\u0001\u001a\u00020\u000e8\u0006@\u0006X\u0086\u000e¢\u0006\u0015\n\u0005\b\u008d\u0001\u0010P\u001a\u0005\b\u008e\u0001\u0010\u0010\"\u0005\b\u008f\u0001\u0010SR&\u0010\u0090\u0001\u001a\u00020\u000e8\u0006@\u0006X\u0086\u000e¢\u0006\u0015\n\u0005\b\u0090\u0001\u0010P\u001a\u0005\b\u0091\u0001\u0010\u0010\"\u0005\b\u0092\u0001\u0010SR \u0010\u0095\u0001\u001a\u00020b8F@\u0006X\u0086\u0084\u0002¢\u0006\u000e\n\u0005\b\u0093\u0001\u0010!\u001a\u0005\b\u0094\u0001\u0010e¨\u0006\u0098\u0001"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/novel/NovelChapterViewActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelActivity;", "Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "", "checkAdDialog", "()V", "settingTools", "Landroid/content/Context;", "context", "showAutoReadDialog", "(Landroid/content/Context;)V", "showReadSettingDialog", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "", "getLayoutId", "()I", "bindEvent", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "onResume", "onDestroy", "", "", "novelTxt", "Ljava/util/List;", "getNovelTxt", "()Ljava/util/List;", "setNovelTxt", "(Ljava/util/List;)V", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "viewModel", "read_model_day", "Ljava/lang/String;", "getRead_model_day", "()Ljava/lang/String;", "setRead_model_day", "(Ljava/lang/String;)V", "Lcom/jbzd/media/movecartoons/view/MarqueeRecyclerView;", "rv_comicschapter_txts$delegate", "getRv_comicschapter_txts", "()Lcom/jbzd/media/movecartoons/view/MarqueeRecyclerView;", "rv_comicschapter_txts", "Landroidx/recyclerview/widget/RecyclerView;", "rv_list_adImg$delegate", "getRv_list_adImg", "()Landroidx/recyclerview/widget/RecyclerView;", "rv_list_adImg", "chapterId", "getChapterId", "setChapterId", "", "darkModel", "Z", "getDarkModel", "()Z", "setDarkModel", "(Z)V", "Landroid/widget/TextView;", "tv_name_novel$delegate", "getTv_name_novel", "()Landroid/widget/TextView;", "tv_name_novel", "tv_chapteritem_txt", "Landroid/widget/TextView;", "getTv_chapteritem_txt", "setTv_chapteritem_txt", "(Landroid/widget/TextView;)V", "", "contentSize", "F", "getContentSize", "()F", "setContentSize", "(F)V", "indexCurrent", "I", "getIndexCurrent", "setIndexCurrent", "(I)V", "mChapterId$delegate", "getMChapterId", "mChapterId", "tv_titleRight$delegate", "getTv_titleRight", "tv_titleRight", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "mNovelDetailInfoBean$delegate", "getMNovelDetailInfoBean", "()Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "mNovelDetailInfoBean", "Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView;", "maskView", "Lcom/jbzd/media/movecartoons/view/FullScreenAdMaskView;", "Landroid/widget/ImageView;", "iv_titleLeftIcon$delegate", "getIv_titleLeftIcon", "()Landroid/widget/ImageView;", "iv_titleLeftIcon", "tv_novelchapter_model_day_night$delegate", "getTv_novelchapter_model_day_night", "tv_novelchapter_model_day_night", "tv_novelchapter_list$delegate", "getTv_novelchapter_list", "tv_novelchapter_list", "scrollState", "getScrollState", "setScrollState", "com/jbzd/media/movecartoons/ui/novel/NovelChapterViewActivity$novelContentAdapter$2$1", "novelContentAdapter$delegate", "getNovelContentAdapter", "()Lcom/jbzd/media/movecartoons/ui/novel/NovelChapterViewActivity$novelContentAdapter$2$1;", "novelContentAdapter", "tv_novelchapter_setting$delegate", "getTv_novelchapter_setting", "tv_novelchapter_setting", "Landroid/widget/LinearLayout;", "ll_novelchapterview_bottom$delegate", "getLl_novelchapterview_bottom", "()Landroid/widget/LinearLayout;", "ll_novelchapterview_bottom", "iv_novelchapter_next$delegate", "getIv_novelchapter_next", "iv_novelchapter_next", "tv_novelchapter_auto$delegate", "getTv_novelchapter_auto", "tv_novelchapter_auto", "com/jbzd/media/movecartoons/ui/novel/NovelChapterViewActivity$imageAdAdapter$2$1", "imageAdAdapter$delegate", "getImageAdAdapter", "()Lcom/jbzd/media/movecartoons/ui/novel/NovelChapterViewActivity$imageAdAdapter$2$1;", "imageAdAdapter", "Landroid/widget/RelativeLayout;", "ll_novel_loading$delegate", "getLl_novel_loading", "()Landroid/widget/RelativeLayout;", "ll_novel_loading", "daynightColorBg", "getDaynightColorBg", "setDaynightColorBg", "daynightColorConent", "getDaynightColorConent", "setDaynightColorConent", "iv_novelchapter_last$delegate", "getIv_novelchapter_last", "iv_novelchapter_last", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class NovelChapterViewActivity extends MyThemeViewModelActivity<ComicsViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    private boolean darkModel;
    private int indexCurrent;
    private FullScreenAdMaskView maskView;
    public TextView tv_chapteritem_txt;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(ComicsViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$special$$inlined$viewModels$default$1
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
    private String read_model_day = "0";

    @NotNull
    private String scrollState = "0";

    /* renamed from: mNovelDetailInfoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mNovelDetailInfoBean = LazyKt__LazyJVMKt.lazy(new Function0<NovelDetailInfoBean>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$mNovelDetailInfoBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final NovelDetailInfoBean invoke() {
            Serializable serializableExtra = NovelChapterViewActivity.this.getIntent().getSerializableExtra("novelDetailInfoBean");
            Objects.requireNonNull(serializableExtra, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.novel.NovelDetailInfoBean");
            return (NovelDetailInfoBean) serializableExtra;
        }
    });

    /* renamed from: mChapterId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mChapterId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$mChapterId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return NovelChapterViewActivity.this.getIntent().getStringExtra("chapterId");
        }
    });

    @NotNull
    private List<String> novelTxt = new ArrayList();
    private int daynightColorBg = R.color.white;
    private int daynightColorConent = R.color.black;
    private float contentSize = 14.0f;

    /* renamed from: novelContentAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy novelContentAdapter = LazyKt__LazyJVMKt.lazy(new NovelChapterViewActivity$novelContentAdapter$2(this));

    /* renamed from: imageAdAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy imageAdAdapter = LazyKt__LazyJVMKt.lazy(new NovelChapterViewActivity$imageAdAdapter$2(this));

    /* renamed from: tv_titleRight$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_titleRight = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$tv_titleRight$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelChapterViewActivity.this.findViewById(R.id.tv_titleRight);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: iv_titleLeftIcon$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_titleLeftIcon = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$iv_titleLeftIcon$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) NovelChapterViewActivity.this.findViewById(R.id.iv_titleLeftIcon);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_novelchapter_model_day_night$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_novelchapter_model_day_night = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$tv_novelchapter_model_day_night$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelChapterViewActivity.this.findViewById(R.id.tv_novelchapter_model_day_night);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_novelchapter_auto$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_novelchapter_auto = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$tv_novelchapter_auto$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelChapterViewActivity.this.findViewById(R.id.tv_novelchapter_auto);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: tv_novelchapter_setting$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_novelchapter_setting = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$tv_novelchapter_setting$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelChapterViewActivity.this.findViewById(R.id.tv_novelchapter_setting);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: iv_novelchapter_last$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_novelchapter_last = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$iv_novelchapter_last$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) NovelChapterViewActivity.this.findViewById(R.id.iv_novelchapter_last);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: iv_novelchapter_next$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy iv_novelchapter_next = LazyKt__LazyJVMKt.lazy(new Function0<ImageView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$iv_novelchapter_next$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ImageView invoke() {
            ImageView imageView = (ImageView) NovelChapterViewActivity.this.findViewById(R.id.iv_novelchapter_next);
            Intrinsics.checkNotNull(imageView);
            return imageView;
        }
    });

    /* renamed from: tv_novelchapter_list$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_novelchapter_list = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$tv_novelchapter_list$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelChapterViewActivity.this.findViewById(R.id.tv_novelchapter_list);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: ll_novel_loading$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_novel_loading = LazyKt__LazyJVMKt.lazy(new Function0<RelativeLayout>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$ll_novel_loading$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RelativeLayout invoke() {
            RelativeLayout relativeLayout = (RelativeLayout) NovelChapterViewActivity.this.findViewById(R.id.ll_novel_loading);
            Intrinsics.checkNotNull(relativeLayout);
            return relativeLayout;
        }
    });

    /* renamed from: rv_comicschapter_txts$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_comicschapter_txts = LazyKt__LazyJVMKt.lazy(new Function0<MarqueeRecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$rv_comicschapter_txts$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MarqueeRecyclerView invoke() {
            MarqueeRecyclerView marqueeRecyclerView = (MarqueeRecyclerView) NovelChapterViewActivity.this.findViewById(R.id.rv_comicschapter_txts);
            Intrinsics.checkNotNull(marqueeRecyclerView);
            return marqueeRecyclerView;
        }
    });

    /* renamed from: ll_novelchapterview_bottom$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy ll_novelchapterview_bottom = LazyKt__LazyJVMKt.lazy(new Function0<LinearLayout>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$ll_novelchapterview_bottom$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final LinearLayout invoke() {
            LinearLayout linearLayout = (LinearLayout) NovelChapterViewActivity.this.findViewById(R.id.ll_novelchapterview_bottom);
            Intrinsics.checkNotNull(linearLayout);
            return linearLayout;
        }
    });

    /* renamed from: tv_name_novel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tv_name_novel = LazyKt__LazyJVMKt.lazy(new Function0<TextView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$tv_name_novel$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final TextView invoke() {
            TextView textView = (TextView) NovelChapterViewActivity.this.findViewById(R.id.tv_name_novel);
            Intrinsics.checkNotNull(textView);
            return textView;
        }
    });

    /* renamed from: rv_list_adImg$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rv_list_adImg = LazyKt__LazyJVMKt.lazy(new Function0<RecyclerView>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$rv_list_adImg$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RecyclerView invoke() {
            RecyclerView recyclerView = (RecyclerView) NovelChapterViewActivity.this.findViewById(R.id.rv_list_adImg);
            Intrinsics.checkNotNull(recyclerView);
            return recyclerView;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000b\u0010\fJ%\u0010\t\u001a\u00020\b2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\t\u0010\n¨\u0006\r"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/novel/NovelChapterViewActivity$Companion;", "", "Landroid/content/Context;", "context", "", "chapter_id", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "mNovelDetailInfoBean", "", "start", "(Landroid/content/Context;Ljava/lang/String;Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context, @NotNull String chapter_id, @NotNull NovelDetailInfoBean mNovelDetailInfoBean) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(chapter_id, "chapter_id");
            Intrinsics.checkNotNullParameter(mNovelDetailInfoBean, "mNovelDetailInfoBean");
            Intent intent = new Intent(context, (Class<?>) NovelChapterViewActivity.class);
            intent.putExtra("novelDetailInfoBean", mNovelDetailInfoBean);
            intent.putExtra("chapterId", chapter_id);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-8$lambda-2, reason: not valid java name */
    public static final void m5908bindEvent$lambda8$lambda2(NovelChapterViewActivity context, ComicsViewModel this_run, NovelChapterInfoBean novelChapterInfoBean) {
        C4381g0 m4972b;
        Intrinsics.checkNotNullParameter(context, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        Intrinsics.checkNotNullParameter(context, "context");
        String str = novelChapterInfoBean.chapter.content;
        NovelChapterViewActivity$bindEvent$11$1$1 listener = new NovelChapterViewActivity$bindEvent$11$1$1(context, this_run);
        Intrinsics.checkNotNullParameter(listener, "listener");
        C4375d0.a aVar = new C4375d0.a();
        InterfaceC4369a0 interceptor = C4349b.m4917b().f11213f;
        Intrinsics.checkParameterIsNotNull(interceptor, "interceptor");
        aVar.f11390d.add(interceptor);
        C4375d0 c4375d0 = new C4375d0(aVar);
        if (str == null) {
            m4972b = null;
        } else {
            C4381g0.a aVar2 = new C4381g0.a();
            aVar2.m4978h(str);
            C2853d c2853d = C2853d.f7770a;
            aVar2.m4971a("referer", C2853d.f7771b);
            m4972b = aVar2.m4972b();
        }
        if (m4972b != null) {
            Intrinsics.checkNotNull(c4375d0);
            ((C4379f0) c4375d0.mo4955a(m4972b)).mo4964k(new C0862o(listener));
        }
        C4349b.m4917b().m4918a(str, new C0866p(listener));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-8$lambda-4, reason: not valid java name */
    public static final void m5909bindEvent$lambda8$lambda4(final NovelChapterViewActivity this$0, String str) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getLl_novel_loading().setVisibility(8);
        this$0.setNovelTxt(new ArrayList());
        this$0.setNovelTxt(CollectionsKt___CollectionsKt.plus((Collection) this$0.getNovelTxt(), (Iterable) CollectionsKt__CollectionsJVMKt.listOf(str.toString())));
        this$0.getNovelContentAdapter().setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) this$0.getNovelTxt()));
        MarqueeRecyclerView rv_comicschapter_txts = this$0.getRv_comicschapter_txts();
        rv_comicschapter_txts.setScrollbarFadingEnabled(false);
        if (rv_comicschapter_txts.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(rv_comicschapter_txts.getContext());
            c4053a.m4576a(R.color.transparent);
            c4053a.f10339g = false;
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            rv_comicschapter_txts.addItemDecoration(new GridItemDecoration(c4053a));
        }
        rv_comicschapter_txts.setSpeed(10L);
        rv_comicschapter_txts.setScrollVertical(true);
        rv_comicschapter_txts.setAdapter(this$0.getNovelContentAdapter());
        rv_comicschapter_txts.setLayoutManager(new LinearLayoutManager(rv_comicschapter_txts.getContext(), 1, false));
        this$0.getRv_comicschapter_txts().addOnScrollListener(new RecyclerView.OnScrollListener() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$11$2$2
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(@NotNull RecyclerView recyclerView, int newState) {
                Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
                super.onScrollStateChanged(recyclerView, newState);
                if (newState == 0) {
                    NovelChapterViewActivity.this.setScrollState("0");
                    NovelChapterViewActivity.this.getIv_novelchapter_last().setVisibility(8);
                    NovelChapterViewActivity.this.getIv_novelchapter_next().setVisibility(8);
                    NovelChapterViewActivity.this.getLl_novelchapterview_bottom().setVisibility(8);
                } else if (newState == 1) {
                    NovelChapterViewActivity.this.setScrollState(ChatMsgBean.SERVICE_ID);
                } else if (newState == 2) {
                    NovelChapterViewActivity.this.setScrollState("0");
                }
                NovelChapterViewActivity.this.getIv_novelchapter_last().setVisibility(8);
                NovelChapterViewActivity.this.getIv_novelchapter_next().setVisibility(8);
                NovelChapterViewActivity.this.getLl_novelchapterview_bottom().setVisibility(8);
            }

            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(@NotNull RecyclerView recyclerView, int dx, int dy) {
                Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
                super.onScrolled(recyclerView, dx, dy);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-8$lambda-5, reason: not valid java name */
    public static final void m5910bindEvent$lambda8$lambda5(final NovelChapterViewActivity this$0, final ComicsViewModel this_run, NovelChapterInfoBean novelChapterInfoBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        if (!novelChapterInfoBean.can_view.equals("n")) {
            this$0.getTv_name_novel().setText(novelChapterInfoBean.chapter.name);
            NovelChapter novelChapter = novelChapterInfoBean.chapter;
            if (!StringsKt__StringsJVMKt.equals$default(novelChapter == null ? null : novelChapter.is_audio, "y", false, 2, null)) {
                this_run.getNovelChapterInfoBeanTxt().setValue(novelChapterInfoBean);
                return;
            }
            MutableLiveData<String> novelChapterInfoBeanAudio = this_run.getNovelChapterInfoBeanAudio();
            NovelChapter novelChapter2 = novelChapterInfoBean.chapter;
            novelChapterInfoBeanAudio.setValue(novelChapter2 != null ? novelChapter2.content : null);
            return;
        }
        if (novelChapterInfoBean.type.equals("captcha")) {
            new ComicsChapterRobotDialog(this$0.getViewModel(), "", new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$11$3$1
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
        if (novelChapterInfoBean.type.equals(VideoTypeBean.video_type_vip)) {
            MyApp myApp = MyApp.f9891f;
            if (MyApp.f9892g.isVipUser()) {
                return;
            }
            String str = novelChapterInfoBean.type;
            Intrinsics.checkNotNullExpressionValue(str, "it.type");
            new BuyDialog("", str, "需要开通VIP才可以看哦~.~", new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$11$3$2
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
                        NovelChapterInfoBean value = ComicsViewModel.this.getNovelChapterInfoBean().getValue();
                        if (StringsKt__StringsJVMKt.equals$default(value == null ? null : value.type, VideoTypeBean.video_type_vip, false, 2, null)) {
                            BuyActivity.INSTANCE.start(this$0);
                        } else {
                            RechargeActivity.INSTANCE.start(this$0);
                        }
                    }
                }
            }).show(this$0.getSupportFragmentManager(), "vipDialog");
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-8$lambda-6, reason: not valid java name */
    public static final void m5911bindEvent$lambda8$lambda6(String str) {
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-8$lambda-7, reason: not valid java name */
    public static final void m5912bindEvent$lambda8$lambda7(NovelChapterViewActivity this$0, Boolean it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullExpressionValue(it, "it");
        if (it.booleanValue() && (!StringsKt__StringsJVMKt.isBlank(this$0.getChapterId()))) {
            ComicsViewModel.novelChapterDetail$default(this$0.getViewModel(), this$0.getChapterId(), false, 2, null);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void checkAdDialog() {
        int i2 = this.indexCurrent;
        if (i2 < 0 || i2 >= getMNovelDetailInfoBean().chapter.size()) {
            return;
        }
        if (Intrinsics.areEqual(getMNovelDetailInfoBean().chapter.get(this.indexCurrent).show_adv_inside, "y")) {
            ((InlineAdView) findViewById(R$id.inlineAd)).show(getMNovelDetailInfoBean().adv_inside);
        }
        if (Intrinsics.areEqual(getMNovelDetailInfoBean().chapter.get(this.indexCurrent).show_adv_full, "y")) {
            FullScreenAdMaskView fullScreenAdMaskView = this.maskView;
            if (fullScreenAdMaskView != null) {
                fullScreenAdMaskView.show(getMNovelDetailInfoBean().adv_full);
            } else {
                Intrinsics.throwUninitializedPropertyAccessException("maskView");
                throw null;
            }
        }
    }

    private final NovelChapterViewActivity$imageAdAdapter$2.C38341 getImageAdAdapter() {
        return (NovelChapterViewActivity$imageAdAdapter$2.C38341) this.imageAdAdapter.getValue();
    }

    private final String getMChapterId() {
        return (String) this.mChapterId.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final NovelDetailInfoBean getMNovelDetailInfoBean() {
        return (NovelDetailInfoBean) this.mNovelDetailInfoBean.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final NovelChapterViewActivity$novelContentAdapter$2.C38351 getNovelContentAdapter() {
        return (NovelChapterViewActivity$novelContentAdapter$2.C38351) this.novelContentAdapter.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void settingTools() {
        if (getIv_novelchapter_last().getVisibility() == 8 && Intrinsics.areEqual(this.scrollState, "0")) {
            getIv_novelchapter_last().setVisibility(0);
            getIv_novelchapter_next().setVisibility(0);
            getLl_novelchapterview_bottom().setVisibility(0);
        } else {
            getIv_novelchapter_last().setVisibility(8);
            getIv_novelchapter_next().setVisibility(8);
            getLl_novelchapterview_bottom().setVisibility(8);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showAutoReadDialog(Context context) {
        new AutoChangePageDialog(11 - getRv_comicschapter_txts().getSpeed(), new Function2<Integer, Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$showAutoReadDialog$1
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
                    NovelChapterViewActivity.this.getRv_comicschapter_txts().setAutoRun(false);
                    NovelChapterViewActivity.this.getRv_comicschapter_txts().stop();
                    return;
                }
                NovelChapterViewActivity.this.getRv_comicschapter_txts().speed = 11 - i2;
                NovelChapterViewActivity.this.getRv_comicschapter_txts().setAutoRun(true);
                NovelChapterViewActivity.this.getRv_comicschapter_txts().start();
                NovelChapterViewActivity.this.setScrollState("1");
                NovelChapterViewActivity.this.settingTools();
            }
        }).show(((NovelChapterViewActivity) context).getSupportFragmentManager(), "NovelChapterViewActivity");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void showReadSettingDialog(Context context) {
        new NovelReadSettingDialog(new Function4<Float, Float, Integer, Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$showReadSettingDialog$1
            {
                super(4);
            }

            @Override // kotlin.jvm.functions.Function4
            public /* bridge */ /* synthetic */ Unit invoke(Float f2, Float f3, Integer num, Boolean bool) {
                invoke(f2.floatValue(), f3.floatValue(), num.intValue(), bool.booleanValue());
                return Unit.INSTANCE;
            }

            public final void invoke(float f2, float f3, int i2, boolean z) {
                NovelChapterViewActivity$novelContentAdapter$2.C38351 novelContentAdapter;
                NovelChapterViewActivity.this.setContentSize(f2);
                NovelChapterViewActivity.this.setDarkModel(z);
                if (i2 == 0) {
                    NovelChapterViewActivity novelChapterViewActivity = NovelChapterViewActivity.this;
                    novelChapterViewActivity.setDaynightColorBg(novelChapterViewActivity.getResources().getColor(R.color.white));
                    NovelChapterViewActivity novelChapterViewActivity2 = NovelChapterViewActivity.this;
                    novelChapterViewActivity2.setDaynightColorConent(novelChapterViewActivity2.getResources().getColor(R.color.black));
                } else if (i2 == 1) {
                    NovelChapterViewActivity.this.setDaynightColorBg(Color.parseColor("#FFF7D4"));
                    NovelChapterViewActivity.this.setDaynightColorConent(Color.parseColor("#511b00"));
                } else if (i2 == 2) {
                    NovelChapterViewActivity.this.setDaynightColorBg(Color.parseColor("#DFF5DA"));
                    NovelChapterViewActivity novelChapterViewActivity3 = NovelChapterViewActivity.this;
                    novelChapterViewActivity3.setDaynightColorConent(novelChapterViewActivity3.getResources().getColor(R.color.black));
                } else if (i2 == 3) {
                    NovelChapterViewActivity.this.setDaynightColorBg(Color.parseColor("#483836"));
                    NovelChapterViewActivity.this.setDaynightColorConent(Color.parseColor("#d9bbb1"));
                } else if (i2 == 4) {
                    NovelChapterViewActivity.this.setDaynightColorBg(Color.parseColor("#213258"));
                    NovelChapterViewActivity.this.setDaynightColorConent(Color.parseColor("#abb9ca"));
                }
                novelContentAdapter = NovelChapterViewActivity.this.getNovelContentAdapter();
                novelContentAdapter.notifyDataSetChanged();
            }
        }).show(((NovelChapterViewActivity) context).getSupportFragmentManager(), "ComicsChapterViewActivity");
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    @SuppressLint({"ClickableViewAccessibility"})
    public void bindEvent() {
        this.chapterId = String.valueOf(getMChapterId());
        ArrayList<NovelChapter> arrayList = getMNovelDetailInfoBean().chapter;
        Intrinsics.checkNotNullExpressionValue(arrayList, "mNovelDetailInfoBean.chapter");
        IntRange indices = CollectionsKt__CollectionsKt.getIndices(arrayList);
        Intrinsics.checkNotNull(indices);
        int first = indices.getFirst();
        int last = indices.getLast();
        if (first <= last) {
            while (true) {
                int i2 = first + 1;
                if (Intrinsics.areEqual(this.chapterId, getMNovelDetailInfoBean().chapter.get(first).f10026id)) {
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
        Intrinsics.checkNotNullExpressionValue(MyApp.m4185f().novel_detail_ads_top, "MyApp.systemBean.novel_detail_ads_top");
        if (!r0.isEmpty()) {
            getRv_list_adImg().setVisibility(0);
            RecyclerView rv_list_adImg = getRv_list_adImg();
            rv_list_adImg.setAdapter(getImageAdAdapter());
            if (MyApp.m4185f().novel_detail_ads_top != null) {
                if (MyApp.m4185f().novel_detail_ads_top.size() > 3) {
                    getImageAdAdapter().setNewData(MyApp.m4185f().novel_detail_ads_top.subList(0, 3));
                } else {
                    getImageAdAdapter().setNewData(MyApp.m4185f().novel_detail_ads_top);
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
        }
        C2354n.m2374A(getTv_titleRight(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$2
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
                InviteActivity.INSTANCE.start(NovelChapterViewActivity.this);
            }
        }, 1);
        C2354n.m2374A(getIv_titleLeftIcon(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$3
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
                NovelChapterViewActivity.this.onBackPressed();
            }
        }, 1);
        MyThemeViewModelActivity.fadeWhenTouch$default(this, getTv_novelchapter_model_day_night(), 0.0f, 1, null);
        MyThemeViewModelActivity.fadeWhenTouch$default(this, getTv_novelchapter_auto(), 0.0f, 1, null);
        MyThemeViewModelActivity.fadeWhenTouch$default(this, getTv_novelchapter_setting(), 0.0f, 1, null);
        MyThemeViewModelActivity.fadeWhenTouch$default(this, getIv_novelchapter_last(), 0.0f, 1, null);
        MyThemeViewModelActivity.fadeWhenTouch$default(this, getIv_novelchapter_next(), 0.0f, 1, null);
        MyThemeViewModelActivity.fadeWhenTouch$default(this, getTv_novelchapter_list(), 0.0f, 1, null);
        C2354n.m2374A(getIv_novelchapter_last(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$4
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
                NovelDetailInfoBean mNovelDetailInfoBean;
                Intrinsics.checkNotNullParameter(it, "it");
                if (NovelChapterViewActivity.this.getIndexCurrent() > 0) {
                    NovelChapterViewActivity.this.setIndexCurrent(r5.getIndexCurrent() - 1);
                    NovelChapterViewActivity novelChapterViewActivity = NovelChapterViewActivity.this;
                    mNovelDetailInfoBean = novelChapterViewActivity.getMNovelDetailInfoBean();
                    String str = mNovelDetailInfoBean.chapter.get(NovelChapterViewActivity.this.getIndexCurrent()).f10026id;
                    Intrinsics.checkNotNullExpressionValue(str, "mNovelDetailInfoBean.chapter[indexCurrent].id");
                    novelChapterViewActivity.setChapterId(str);
                    ComicsViewModel.novelChapterDetail$default(NovelChapterViewActivity.this.getViewModel(), NovelChapterViewActivity.this.getChapterId(), false, 2, null);
                } else {
                    C2354n.m2379B1("第一章了哦~");
                }
                NovelChapterViewActivity.this.checkAdDialog();
            }
        }, 1);
        C2354n.m2374A(getIv_novelchapter_next(), 0L, new Function1<ImageView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$5
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
                NovelDetailInfoBean mNovelDetailInfoBean;
                NovelDetailInfoBean mNovelDetailInfoBean2;
                Intrinsics.checkNotNullParameter(it, "it");
                int indexCurrent = NovelChapterViewActivity.this.getIndexCurrent();
                mNovelDetailInfoBean = NovelChapterViewActivity.this.getMNovelDetailInfoBean();
                if (indexCurrent < mNovelDetailInfoBean.chapter.size() - 1) {
                    NovelChapterViewActivity novelChapterViewActivity = NovelChapterViewActivity.this;
                    novelChapterViewActivity.setIndexCurrent(novelChapterViewActivity.getIndexCurrent() + 1);
                    NovelChapterViewActivity novelChapterViewActivity2 = NovelChapterViewActivity.this;
                    mNovelDetailInfoBean2 = novelChapterViewActivity2.getMNovelDetailInfoBean();
                    String str = mNovelDetailInfoBean2.chapter.get(NovelChapterViewActivity.this.getIndexCurrent()).f10026id;
                    Intrinsics.checkNotNullExpressionValue(str, "mNovelDetailInfoBean.chapter[indexCurrent].id");
                    novelChapterViewActivity2.setChapterId(str);
                    ComicsViewModel.novelChapterDetail$default(NovelChapterViewActivity.this.getViewModel(), NovelChapterViewActivity.this.getChapterId(), false, 2, null);
                } else {
                    C2354n.m2379B1("最后一章了哦~");
                }
                NovelChapterViewActivity.this.checkAdDialog();
            }
        }, 1);
        C2354n.m2374A(getTv_novelchapter_list(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$6
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
                NovelDetailInfoBean mNovelDetailInfoBean;
                Intrinsics.checkNotNullParameter(it, "it");
                NovelTableContentAllActivity.Companion companion = NovelTableContentAllActivity.Companion;
                NovelChapterViewActivity novelChapterViewActivity = NovelChapterViewActivity.this;
                mNovelDetailInfoBean = novelChapterViewActivity.getMNovelDetailInfoBean();
                companion.start(novelChapterViewActivity, mNovelDetailInfoBean);
            }
        }, 1);
        C2354n.m2374A(getTv_novelchapter_model_day_night(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$7
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
                NovelChapterViewActivity$novelContentAdapter$2.C38351 novelContentAdapter;
                NovelChapterViewActivity$novelContentAdapter$2.C38351 novelContentAdapter2;
                Intrinsics.checkNotNullParameter(it, "it");
                if (!Intrinsics.areEqual(NovelChapterViewActivity.this.getRead_model_day(), "0")) {
                    NovelChapterViewActivity.this.getTv_novelchapter_model_day_night().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, NovelChapterViewActivity.this.getResources().getDrawable(R.drawable.icon_novelread_light), (Drawable) null, (Drawable) null);
                    NovelChapterViewActivity novelChapterViewActivity = NovelChapterViewActivity.this;
                    novelChapterViewActivity.setDaynightColorBg(novelChapterViewActivity.getResources().getColor(R.color.black));
                    NovelChapterViewActivity novelChapterViewActivity2 = NovelChapterViewActivity.this;
                    novelChapterViewActivity2.setDaynightColorConent(novelChapterViewActivity2.getResources().getColor(R.color.white));
                    novelContentAdapter = NovelChapterViewActivity.this.getNovelContentAdapter();
                    novelContentAdapter.notifyDataSetChanged();
                    NovelChapterViewActivity.this.setRead_model_day("0");
                    NovelChapterViewActivity.this.getTv_novelchapter_model_day_night().setText("日间");
                    return;
                }
                NovelChapterViewActivity.this.getTv_novelchapter_model_day_night().setCompoundDrawablesWithIntrinsicBounds((Drawable) null, NovelChapterViewActivity.this.getResources().getDrawable(R.drawable.icon_novelread_model_night), (Drawable) null, (Drawable) null);
                NovelChapterViewActivity novelChapterViewActivity3 = NovelChapterViewActivity.this;
                novelChapterViewActivity3.setDaynightColorBg(novelChapterViewActivity3.getResources().getColor(R.color.white));
                NovelChapterViewActivity novelChapterViewActivity4 = NovelChapterViewActivity.this;
                novelChapterViewActivity4.setDaynightColorConent(novelChapterViewActivity4.getResources().getColor(R.color.black));
                NovelChapterViewActivity.this.setRead_model_day("1");
                NovelChapterViewActivity.this.getTv_novelchapter_model_day_night().setText("夜间");
                if (NovelChapterViewActivity.this.getTv_chapteritem_txt() != null) {
                    NovelChapterViewActivity.this.getTv_chapteritem_txt().setBackgroundColor(NovelChapterViewActivity.this.getDaynightColorBg());
                    NovelChapterViewActivity.this.getTv_chapteritem_txt().setTextColor(NovelChapterViewActivity.this.getDaynightColorConent());
                }
                novelContentAdapter2 = NovelChapterViewActivity.this.getNovelContentAdapter();
                novelContentAdapter2.notifyDataSetChanged();
            }
        }, 1);
        C2354n.m2374A(getTv_novelchapter_auto(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$8
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
                NovelChapterViewActivity novelChapterViewActivity = NovelChapterViewActivity.this;
                Context context = novelChapterViewActivity.getTv_novelchapter_auto().getContext();
                Intrinsics.checkNotNullExpressionValue(context, "tv_novelchapter_auto.context");
                novelChapterViewActivity.showAutoReadDialog(context);
            }
        }, 1);
        C2354n.m2374A(getTv_novelchapter_setting(), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$9
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
                NovelChapterViewActivity novelChapterViewActivity = NovelChapterViewActivity.this;
                Context context = novelChapterViewActivity.getTv_novelchapter_auto().getContext();
                Intrinsics.checkNotNullExpressionValue(context, "tv_novelchapter_auto.context");
                novelChapterViewActivity.showReadSettingDialog(context);
            }
        }, 1);
        String mChapterId = getMChapterId();
        if (mChapterId != null) {
            ComicsViewModel.novelChapterDetail$default(getViewModel(), mChapterId, false, 2, null);
        }
        final ComicsViewModel viewModel = getViewModel();
        viewModel.getNovelChapterInfoBeanTxt().observe(this, new Observer() { // from class: b.a.a.a.t.j.d
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                NovelChapterViewActivity.m5908bindEvent$lambda8$lambda2(NovelChapterViewActivity.this, viewModel, (NovelChapterInfoBean) obj);
            }
        });
        viewModel.getNovelChapterInfoBeanTxtShow().observe(this, new Observer() { // from class: b.a.a.a.t.j.h
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                NovelChapterViewActivity.m5909bindEvent$lambda8$lambda4(NovelChapterViewActivity.this, (String) obj);
            }
        });
        viewModel.getNovelChapterInfoBean().observe(this, new Observer() { // from class: b.a.a.a.t.j.e
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                NovelChapterViewActivity.m5910bindEvent$lambda8$lambda5(NovelChapterViewActivity.this, viewModel, (NovelChapterInfoBean) obj);
            }
        });
        viewModel.getNovelChapterInfoBeanAudio().observe(this, new Observer() { // from class: b.a.a.a.t.j.k
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                NovelChapterViewActivity.m5911bindEvent$lambda8$lambda6((String) obj);
            }
        });
        viewModel.getPicVerState().observe(this, new Observer() { // from class: b.a.a.a.t.j.f
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                NovelChapterViewActivity.m5912bindEvent$lambda8$lambda7(NovelChapterViewActivity.this, (Boolean) obj);
            }
        });
        int i3 = R$id.adBar;
        ((AdBottomBarView) findViewById(i3)).setListener(new AdBottomBarView.Listener() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$12
            @Override // com.jbzd.media.movecartoons.view.AdBottomBarView.Listener
            public void onAdClosed(@Nullable NewAd lastAd) {
            }

            @Override // com.jbzd.media.movecartoons.view.AdBottomBarView.Listener
            public void onVipClick(@Nullable NewAd currentAd) {
                BuyActivity.INSTANCE.start(NovelChapterViewActivity.this);
            }
        });
        ((AdBottomBarView) findViewById(i3)).setInnerAd(getMNovelDetailInfoBean().adv_float);
        ((AdBottomBarView) findViewById(i3)).show();
        ((InlineAdView) findViewById(R$id.inlineAd)).setListener(new InlineAdView.Listener() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$13
            @Override // com.jbzd.media.movecartoons.view.InlineAdView.Listener
            public void onVipClick(@Nullable NewAd current) {
                BuyActivity.INSTANCE.start(NovelChapterViewActivity.this);
            }
        });
        FullScreenAdMaskView attachTo = FullScreenAdMaskView.INSTANCE.attachTo(this);
        this.maskView = attachTo;
        if (attachTo == null) {
            Intrinsics.throwUninitializedPropertyAccessException("maskView");
            throw null;
        }
        attachTo.setListener(new FullScreenAdMaskView.Listener() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelChapterViewActivity$bindEvent$14
            @Override // com.jbzd.media.movecartoons.view.FullScreenAdMaskView.Listener
            public void onDismiss() {
            }

            @Override // com.jbzd.media.movecartoons.view.FullScreenAdMaskView.Listener
            public void onMainButtonClick(@Nullable NewAd current) {
                C0840d.a aVar = C0840d.f235a;
                NovelChapterViewActivity novelChapterViewActivity = NovelChapterViewActivity.this;
                Intrinsics.checkNotNull(current);
                aVar.m177c(novelChapterViewActivity, current);
            }

            @Override // com.jbzd.media.movecartoons.view.FullScreenAdMaskView.Listener
            public void onVipClick(@Nullable NewAd current) {
                BuyActivity.INSTANCE.start(NovelChapterViewActivity.this);
            }
        });
        checkAdDialog();
    }

    @NotNull
    public final String getChapterId() {
        return this.chapterId;
    }

    public final float getContentSize() {
        return this.contentSize;
    }

    public final boolean getDarkModel() {
        return this.darkModel;
    }

    public final int getDaynightColorBg() {
        return this.daynightColorBg;
    }

    public final int getDaynightColorConent() {
        return this.daynightColorConent;
    }

    public final int getIndexCurrent() {
        return this.indexCurrent;
    }

    @NotNull
    public final ImageView getIv_novelchapter_last() {
        return (ImageView) this.iv_novelchapter_last.getValue();
    }

    @NotNull
    public final ImageView getIv_novelchapter_next() {
        return (ImageView) this.iv_novelchapter_next.getValue();
    }

    @NotNull
    public final ImageView getIv_titleLeftIcon() {
        return (ImageView) this.iv_titleLeftIcon.getValue();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_novelchapter_view;
    }

    @NotNull
    public final RelativeLayout getLl_novel_loading() {
        return (RelativeLayout) this.ll_novel_loading.getValue();
    }

    @NotNull
    public final LinearLayout getLl_novelchapterview_bottom() {
        return (LinearLayout) this.ll_novelchapterview_bottom.getValue();
    }

    @NotNull
    public final List<String> getNovelTxt() {
        return this.novelTxt;
    }

    @NotNull
    public final String getRead_model_day() {
        return this.read_model_day;
    }

    @NotNull
    public final MarqueeRecyclerView getRv_comicschapter_txts() {
        return (MarqueeRecyclerView) this.rv_comicschapter_txts.getValue();
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
    public final TextView getTv_chapteritem_txt() {
        TextView textView = this.tv_chapteritem_txt;
        if (textView != null) {
            return textView;
        }
        Intrinsics.throwUninitializedPropertyAccessException("tv_chapteritem_txt");
        throw null;
    }

    @NotNull
    public final TextView getTv_name_novel() {
        return (TextView) this.tv_name_novel.getValue();
    }

    @NotNull
    public final TextView getTv_novelchapter_auto() {
        return (TextView) this.tv_novelchapter_auto.getValue();
    }

    @NotNull
    public final TextView getTv_novelchapter_list() {
        return (TextView) this.tv_novelchapter_list.getValue();
    }

    @NotNull
    public final TextView getTv_novelchapter_model_day_night() {
        return (TextView) this.tv_novelchapter_model_day_night.getValue();
    }

    @NotNull
    public final TextView getTv_novelchapter_setting() {
        return (TextView) this.tv_novelchapter_setting.getValue();
    }

    @NotNull
    public final TextView getTv_titleRight() {
        return (TextView) this.tv_titleRight.getValue();
    }

    @NotNull
    public final ComicsViewModel getViewModel() {
        return (ComicsViewModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
        this.daynightColorBg = getResources().getColor(R.color.white);
        this.daynightColorConent = getResources().getColor(R.color.black);
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
    }

    @Override // androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onResume() {
        super.onResume();
    }

    public final void setChapterId(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.chapterId = str;
    }

    public final void setContentSize(float f2) {
        this.contentSize = f2;
    }

    public final void setDarkModel(boolean z) {
        this.darkModel = z;
    }

    public final void setDaynightColorBg(int i2) {
        this.daynightColorBg = i2;
    }

    public final void setDaynightColorConent(int i2) {
        this.daynightColorConent = i2;
    }

    public final void setIndexCurrent(int i2) {
        this.indexCurrent = i2;
    }

    public final void setNovelTxt(@NotNull List<String> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.novelTxt = list;
    }

    public final void setRead_model_day(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.read_model_day = str;
    }

    public final void setScrollState(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.scrollState = str;
    }

    public final void setTv_chapteritem_txt(@NotNull TextView textView) {
        Intrinsics.checkNotNullParameter(textView, "<set-?>");
        this.tv_chapteritem_txt = textView;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelActivity
    @NotNull
    public ComicsViewModel viewModelInstance() {
        return getViewModel();
    }
}
