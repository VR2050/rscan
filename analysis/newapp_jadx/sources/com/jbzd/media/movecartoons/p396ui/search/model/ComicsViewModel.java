package com.jbzd.media.movecartoons.p396ui.search.model;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.response.ComicsDayInfoBean;
import com.jbzd.media.movecartoons.bean.response.FilterData;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.PicVefBean;
import com.jbzd.media.movecartoons.bean.response.comicschapterinfo.ComicsChapterInfoBean;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsDetailInfoBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapterInfoBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelDetailInfoBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelItemsBean;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONArray;
import org.json.JSONObject;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p143g.p144a.p146l.C1568e;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u009c\u0001\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0018\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\r\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\bx\u0010\u0007J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u001f\u0010\u000b\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\b2\b\b\u0002\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u001f\u0010\r\u001a\u00020\u00052\u0006\u0010\t\u001a\u00020\b2\b\b\u0002\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b\r\u0010\fJ\u0017\u0010\u000e\u001a\u00020\u00052\b\b\u0002\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b\u000e\u0010\u000fJ\u001f\u0010\u0011\u001a\u00020\u00052\u0006\u0010\u0010\u001a\u00020\b2\b\b\u0002\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b\u0011\u0010\fJ\u001f\u0010\u0012\u001a\u00020\u00052\u0006\u0010\u0010\u001a\u00020\b2\b\b\u0002\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b\u0012\u0010\fJm\u0010\u001e\u001a\u00020\u00052\u0006\u0010\u0013\u001a\u00020\b2\u0006\u0010\n\u001a\u00020\u00022%\b\u0002\u0010\u0019\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u0015¢\u0006\f\b\u0016\u0012\b\b\u0017\u0012\u0004\b\b(\u0018\u0012\u0004\u0012\u00020\u00050\u00142'\b\u0002\u0010\u001d\u001a!\u0012\u0017\u0012\u00150\u001aj\u0002`\u001b¢\u0006\f\b\u0016\u0012\b\b\u0017\u0012\u0004\b\b(\u001c\u0012\u0004\u0012\u00020\u00050\u0014¢\u0006\u0004\b\u001e\u0010\u001fJm\u0010!\u001a\u00020\u00052\u0006\u0010 \u001a\u00020\b2\u0006\u0010\n\u001a\u00020\u00022%\b\u0002\u0010\u0019\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u0015¢\u0006\f\b\u0016\u0012\b\b\u0017\u0012\u0004\b\b(\u0018\u0012\u0004\u0012\u00020\u00050\u00142'\b\u0002\u0010\u001d\u001a!\u0012\u0017\u0012\u00150\u001aj\u0002`\u001b¢\u0006\f\b\u0016\u0012\b\b\u0017\u0012\u0004\b\b(\u001c\u0012\u0004\u0012\u00020\u00050\u0014¢\u0006\u0004\b!\u0010\u001fJm\u0010#\u001a\u00020\u00052\u0006\u0010\"\u001a\u00020\b2\u0006\u0010\n\u001a\u00020\u00022%\b\u0002\u0010\u0019\u001a\u001f\u0012\u0015\u0012\u0013\u0018\u00010\u0015¢\u0006\f\b\u0016\u0012\b\b\u0017\u0012\u0004\b\b(\u0018\u0012\u0004\u0012\u00020\u00050\u00142'\b\u0002\u0010\u001d\u001a!\u0012\u0017\u0012\u00150\u001aj\u0002`\u001b¢\u0006\f\b\u0016\u0012\b\b\u0017\u0012\u0004\b\b(\u001c\u0012\u0004\u0012\u00020\u00050\u0014¢\u0006\u0004\b#\u0010\u001fJ\u0015\u0010%\u001a\u00020\u00052\u0006\u0010$\u001a\u00020\u0002¢\u0006\u0004\b%\u0010\u000fJ\u0015\u0010&\u001a\u00020\u00052\u0006\u0010$\u001a\u00020\u0002¢\u0006\u0004\b&\u0010\u000fJ\u001f\u0010(\u001a\u00020\u00052\u0006\u0010'\u001a\u00020\b2\b\b\u0002\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b(\u0010\fJ\u001f\u0010)\u001a\u00020\u00052\u0006\u0010'\u001a\u00020\b2\b\b\u0002\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b)\u0010\fJ\u001f\u0010+\u001a\u00020\u00052\u0006\u0010*\u001a\u00020\b2\b\b\u0002\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b+\u0010\fJ'\u0010-\u001a\u00020\u00052\u0006\u0010*\u001a\u00020\b2\u0006\u0010,\u001a\u00020\b2\b\b\u0002\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b-\u0010.J\u000f\u0010/\u001a\u00020\u0005H\u0016¢\u0006\u0004\b/\u0010\u0007J\u001f\u00101\u001a\u00020\u00052\u0006\u00100\u001a\u00020\b2\b\b\u0002\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b1\u0010\fJ\u0017\u00102\u001a\u00020\u00052\b\b\u0002\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b2\u0010\u000fJ\u0017\u00103\u001a\u00020\u00052\b\b\u0002\u0010\n\u001a\u00020\u0002¢\u0006\u0004\b3\u0010\u000fR#\u0010:\u001a\b\u0012\u0004\u0012\u000205048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b6\u00107\u001a\u0004\b8\u00109R#\u0010>\u001a\b\u0012\u0004\u0012\u00020;048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b<\u00107\u001a\u0004\b=\u00109R#\u0010A\u001a\b\u0012\u0004\u0012\u00020\b048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b?\u00107\u001a\u0004\b@\u00109RU\u0010H\u001a:\u00126\u00124\u0012\u0004\u0012\u00020\b\u0012\n\u0012\b\u0012\u0004\u0012\u00020D0C0Bj\u001e\u0012\u0004\u0012\u00020\b\u0012\u0014\u0012\u0012\u0012\u0004\u0012\u00020D0Cj\b\u0012\u0004\u0012\u00020D`F`E048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bG\u00107\u001a\u0004\b1\u00109R#\u0010K\u001a\b\u0012\u0004\u0012\u00020\u0002048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bI\u00107\u001a\u0004\bJ\u00109R#\u0010N\u001a\b\u0012\u0004\u0012\u00020\b048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bL\u00107\u001a\u0004\bM\u00109R)\u0010S\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020P0O048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bQ\u00107\u001a\u0004\bR\u00109R#\u0010V\u001a\b\u0012\u0004\u0012\u000205048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bT\u00107\u001a\u0004\bU\u00109R\u0018\u0010X\u001a\u0004\u0018\u00010W8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bX\u0010YRU\u0010\\\u001a:\u00126\u00124\u0012\u0004\u0012\u00020\b\u0012\n\u0012\b\u0012\u0004\u0012\u00020D0C0Bj\u001e\u0012\u0004\u0012\u00020\b\u0012\u0014\u0012\u0012\u0012\u0004\u0012\u00020D0Cj\b\u0012\u0004\u0012\u00020D`F`E048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bZ\u00107\u001a\u0004\b[\u00109R#\u0010`\u001a\b\u0012\u0004\u0012\u00020]048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b^\u00107\u001a\u0004\b_\u00109R#\u0010d\u001a\b\u0012\u0004\u0012\u00020a048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bb\u00107\u001a\u0004\bc\u00109R\u0018\u0010e\u001a\u0004\u0018\u00010W8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\be\u0010YR#\u0010i\u001a\b\u0012\u0004\u0012\u00020f048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bg\u00107\u001a\u0004\bh\u00109R#\u0010l\u001a\b\u0012\u0004\u0012\u00020\u0002048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bj\u00107\u001a\u0004\bk\u00109R)\u0010o\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020a0O048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bm\u00107\u001a\u0004\bn\u00109RY\u0010s\u001a>\u0012\u0004\u0012\u00020\b\u0012\u0014\u0012\u0012\u0012\u0004\u0012\u00020D0Cj\b\u0012\u0004\u0012\u00020D`F0Bj\u001e\u0012\u0004\u0012\u00020\b\u0012\u0014\u0012\u0012\u0012\u0004\u0012\u00020D0Cj\b\u0012\u0004\u0012\u00020D`F`E8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bp\u00107\u001a\u0004\bq\u0010rR)\u0010w\u001a\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020t0O048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\bu\u00107\u001a\u0004\bv\u00109¨\u0006y"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "loveIsNum", "()Z", "", "onCreate", "()V", "", "idComics", "hasLoading", "comicsDetail", "(Ljava/lang/String;Z)V", "novelDetail", "comicsDayInfo", "(Z)V", "filter", "comicsSearch", "novelSearch", "comicsId", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "response", FindBean.status_success, "Ljava/lang/Exception;", "Lkotlin/Exception;", C1568e.f1949a, "error", "comicsDoFavorite", "(Ljava/lang/String;ZLkotlin/jvm/functions/Function1;Lkotlin/jvm/functions/Function1;)V", "id", "novelDoFavorite", "page", "comicsFavorite", "hasLike", "updateLikeNum", "updateLikeNumNovel", "chapterId", "comicsChapterDetail", "novelChapterDetail", "key", "systemCaptcha", "codeValue", "systemUnlock", "(Ljava/lang/String;Ljava/lang/String;Z)V", "onDestroy", "position", "getLibrary", "postFilter", "comicsFilter", "Landroidx/lifecycle/MutableLiveData;", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelChapterInfoBean;", "novelChapterInfoBeanTxt$delegate", "Lkotlin/Lazy;", "getNovelChapterInfoBeanTxt", "()Landroidx/lifecycle/MutableLiveData;", "novelChapterInfoBeanTxt", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "novelDetailInfo$delegate", "getNovelDetailInfo", "novelDetailInfo", "novelChapterInfoBeanAudio$delegate", "getNovelChapterInfoBeanAudio", "novelChapterInfoBeanAudio", "Ljava/util/HashMap;", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/bean/response/FilterData;", "Lkotlin/collections/HashMap;", "Lkotlin/collections/ArrayList;", "library$delegate", "library", "mHasLike$delegate", "getMHasLike", "mHasLike", "novelChapterInfoBeanTxtShow$delegate", "getNovelChapterInfoBeanTxtShow", "novelChapterInfoBeanTxtShow", "", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelItemsBean;", "novelItemsBean$delegate", "getNovelItemsBean", "novelItemsBean", "novelChapterInfoBean$delegate", "getNovelChapterInfoBean", "novelChapterInfoBean", "Lc/a/d1;", "hotJob", "Lc/a/d1;", "filterData$delegate", "getFilterData", "filterData", "Lcom/jbzd/media/movecartoons/bean/response/PicVefBean;", "picVefBean$delegate", "getPicVefBean", "picVefBean", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;", "comicsDetailInfo$delegate", "getComicsDetailInfo", "comicsDetailInfo", "libraryJob", "Lcom/jbzd/media/movecartoons/bean/response/comicschapterinfo/ComicsChapterInfoBean;", "comicsChapterInfoBean$delegate", "getComicsChapterInfoBean", "comicsChapterInfoBean", "picVerState$delegate", "getPicVerState", "picVerState", "comicsItemBean$delegate", "getComicsItemBean", "comicsItemBean", "listMap$delegate", "getListMap", "()Ljava/util/HashMap;", "listMap", "Lcom/jbzd/media/movecartoons/bean/response/ComicsDayInfoBean;", "comicsDayInfoBean$delegate", "getComicsDayInfoBean", "comicsDayInfoBean", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ComicsViewModel extends BaseViewModel {

    @Nullable
    private InterfaceC3053d1 hotJob;

    @Nullable
    private InterfaceC3053d1 libraryJob;

    /* renamed from: comicsDetailInfo$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy comicsDetailInfo = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<ComicsDetailInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsDetailInfo$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<ComicsDetailInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: novelDetailInfo$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy novelDetailInfo = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<NovelDetailInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelDetailInfo$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<NovelDetailInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: mHasLike$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mHasLike = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$mHasLike$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: comicsChapterInfoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy comicsChapterInfoBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<ComicsChapterInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsChapterInfoBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<ComicsChapterInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: novelChapterInfoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy novelChapterInfoBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<NovelChapterInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelChapterInfoBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<NovelChapterInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: novelChapterInfoBeanTxt$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy novelChapterInfoBeanTxt = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<NovelChapterInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelChapterInfoBeanTxt$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<NovelChapterInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: novelChapterInfoBeanTxtShow$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy novelChapterInfoBeanTxtShow = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelChapterInfoBeanTxtShow$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: novelChapterInfoBeanAudio$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy novelChapterInfoBeanAudio = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<String>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelChapterInfoBeanAudio$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<String> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: picVefBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy picVefBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<PicVefBean>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$picVefBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<PicVefBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: picVerState$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy picVerState = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$picVerState$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: comicsItemBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy comicsItemBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<ComicsDetailInfoBean>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsItemBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<ComicsDetailInfoBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: novelItemsBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy novelItemsBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<NovelItemsBean>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelItemsBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<NovelItemsBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: comicsDayInfoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy comicsDayInfoBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<List<ComicsDayInfoBean>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsDayInfoBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<List<ComicsDayInfoBean>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: listMap$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy listMap = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, ArrayList<FilterData>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$listMap$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, ArrayList<FilterData>> invoke() {
            return new HashMap<>();
        }
    });

    /* renamed from: library$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy library = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<HashMap<String, ArrayList<FilterData>>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$library$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<HashMap<String, ArrayList<FilterData>>> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: filterData$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy filterData = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<HashMap<String, ArrayList<FilterData>>>>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$filterData$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<HashMap<String, ArrayList<FilterData>>> invoke() {
            return new MutableLiveData<>();
        }
    });

    public static /* synthetic */ void comicsChapterDetail$default(ComicsViewModel comicsViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        comicsViewModel.comicsChapterDetail(str, z);
    }

    public static /* synthetic */ void comicsDayInfo$default(ComicsViewModel comicsViewModel, boolean z, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = true;
        }
        comicsViewModel.comicsDayInfo(z);
    }

    public static /* synthetic */ void comicsDetail$default(ComicsViewModel comicsViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        comicsViewModel.comicsDetail(str, z);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void comicsDoFavorite$default(ComicsViewModel comicsViewModel, String str, boolean z, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsDoFavorite$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 8) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsDoFavorite$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        comicsViewModel.comicsDoFavorite(str, z, function1, function12);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void comicsFavorite$default(ComicsViewModel comicsViewModel, String str, boolean z, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsFavorite$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 8) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsFavorite$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        comicsViewModel.comicsFavorite(str, z, function1, function12);
    }

    public static /* synthetic */ void comicsFilter$default(ComicsViewModel comicsViewModel, boolean z, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = true;
        }
        comicsViewModel.comicsFilter(z);
    }

    public static /* synthetic */ void comicsSearch$default(ComicsViewModel comicsViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        comicsViewModel.comicsSearch(str, z);
    }

    public static /* synthetic */ void getLibrary$default(ComicsViewModel comicsViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        comicsViewModel.getLibrary(str, z);
    }

    public static /* synthetic */ void novelChapterDetail$default(ComicsViewModel comicsViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        comicsViewModel.novelChapterDetail(str, z);
    }

    public static /* synthetic */ void novelDetail$default(ComicsViewModel comicsViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        comicsViewModel.novelDetail(str, z);
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void novelDoFavorite$default(ComicsViewModel comicsViewModel, String str, boolean z, Function1 function1, Function1 function12, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            function1 = new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelDoFavorite$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Object obj2) {
                    invoke2(obj2);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@Nullable Object obj2) {
                }
            };
        }
        if ((i2 & 8) != 0) {
            function12 = new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelDoFavorite$2
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                    invoke2(exc);
                    return Unit.INSTANCE;
                }

                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                public final void invoke2(@NotNull Exception it) {
                    Intrinsics.checkNotNullParameter(it, "it");
                }
            };
        }
        comicsViewModel.novelDoFavorite(str, z, function1, function12);
    }

    public static /* synthetic */ void novelSearch$default(ComicsViewModel comicsViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        comicsViewModel.novelSearch(str, z);
    }

    public static /* synthetic */ void postFilter$default(ComicsViewModel comicsViewModel, boolean z, int i2, Object obj) {
        if ((i2 & 1) != 0) {
            z = true;
        }
        comicsViewModel.postFilter(z);
    }

    public static /* synthetic */ void systemCaptcha$default(ComicsViewModel comicsViewModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        comicsViewModel.systemCaptcha(str, z);
    }

    public static /* synthetic */ void systemUnlock$default(ComicsViewModel comicsViewModel, String str, String str2, boolean z, int i2, Object obj) {
        if ((i2 & 4) != 0) {
            z = true;
        }
        comicsViewModel.systemUnlock(str, str2, z);
    }

    public final void comicsChapterDetail(@NotNull String chapterId, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(chapterId, "chapterId");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("id", chapterId);
        this.hotJob = C0917a.m221e(C0917a.f372a, "comics/chapterDetail", ComicsChapterInfoBean.class, hashMap, new Function1<ComicsChapterInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsChapterDetail$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ComicsChapterInfoBean comicsChapterInfoBean) {
                invoke2(comicsChapterInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable ComicsChapterInfoBean comicsChapterInfoBean) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getComicsChapterInfoBean().setValue(comicsChapterInfoBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsChapterDetail$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    public final void comicsDayInfo(final boolean hasLoading) {
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        this.hotJob = C0917a.m222f(C0917a.f372a, "comics/dayInfo", ComicsDayInfoBean.class, new HashMap(), new Function1<List<? extends ComicsDayInfoBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsDayInfo$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends ComicsDayInfoBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends ComicsDayInfoBean> list) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getComicsDayInfoBean().setValue(list == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) list));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsDayInfo$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    public final void comicsDetail(@NotNull String idComics, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(idComics, "idComics");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("id", idComics);
        this.hotJob = C0917a.m221e(C0917a.f372a, "comics/detail", ComicsDetailInfoBean.class, hashMap, new Function1<ComicsDetailInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsDetail$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(ComicsDetailInfoBean comicsDetailInfoBean) {
                invoke2(comicsDetailInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable ComicsDetailInfoBean comicsDetailInfoBean) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getComicsDetailInfo().setValue(comicsDetailInfoBean);
                this.getMHasLike().setValue(Boolean.valueOf(Intrinsics.areEqual(comicsDetailInfoBean == null ? null : comicsDetailInfoBean.has_favorite, "y")));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsDetail$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    public final void comicsDoFavorite(@NotNull String comicsId, boolean hasLoading, @NotNull Function1<Object, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(comicsId, "comicsId");
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("id", comicsId);
        this.hotJob = C0917a.m221e(C0917a.f372a, "comics/doFavorite", String.class, hashMap, success, error, false, false, null, false, 480);
    }

    public final void comicsFavorite(@NotNull String page, boolean hasLoading, @NotNull Function1<Object, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(page, "page");
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("page", page);
        this.hotJob = C0917a.m221e(C0917a.f372a, "comics/favorite", String.class, hashMap, success, error, false, false, null, false, 480);
    }

    public final void comicsFilter(final boolean hasLoading) {
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        this.libraryJob = C0917a.m221e(C0917a.f372a, "comics/filter", String.class, new HashMap(), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsFilter$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                JSONArray jSONArray = new JSONArray(String.valueOf(str));
                int length = jSONArray.length();
                if (length > 0) {
                    int i2 = 0;
                    while (true) {
                        int i3 = i2 + 1;
                        JSONArray jSONArray2 = jSONArray.getJSONArray(i2);
                        ArrayList<FilterData> arrayList = new ArrayList<>();
                        int length2 = jSONArray2.length();
                        if (length2 > 0) {
                            int i4 = 0;
                            while (true) {
                                int i5 = i4 + 1;
                                JSONObject jSONObject = jSONArray2.getJSONObject(i4);
                                arrayList.add(new FilterData(jSONObject.getString("code"), jSONObject.getString("name"), jSONObject.getString("value")));
                                if (i5 >= length2) {
                                    break;
                                } else {
                                    i4 = i5;
                                }
                            }
                        }
                        this.getListMap().put(String.valueOf(i2), arrayList);
                        if (i3 >= length) {
                            break;
                        } else {
                            i2 = i3;
                        }
                    }
                }
                this.getFilterData().setValue(this.getListMap());
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsFilter$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    public final void comicsSearch(@NotNull String filter, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(filter, "filter");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        HashMap hashMap2 = new HashMap();
        if (!(filter == null || filter.length() == 0)) {
            try {
                JSONObject jSONObject = new JSONObject(filter);
                Iterator<String> keys = jSONObject.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    String value = jSONObject.getString(key);
                    Intrinsics.checkNotNullExpressionValue(key, "key");
                    Intrinsics.checkNotNullExpressionValue(value, "value");
                    hashMap2.put(key, value);
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        hashMap.putAll(hashMap2);
        this.hotJob = C0917a.m222f(C0917a.f372a, "comics/search", ComicsDetailInfoBean.class, hashMap, new Function1<List<? extends ComicsDetailInfoBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsSearch$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends ComicsDetailInfoBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends ComicsDetailInfoBean> list) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getComicsItemBean().setValue(list == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) list));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$comicsSearch$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    @NotNull
    public final MutableLiveData<ComicsChapterInfoBean> getComicsChapterInfoBean() {
        return (MutableLiveData) this.comicsChapterInfoBean.getValue();
    }

    @NotNull
    public final MutableLiveData<List<ComicsDayInfoBean>> getComicsDayInfoBean() {
        return (MutableLiveData) this.comicsDayInfoBean.getValue();
    }

    @NotNull
    public final MutableLiveData<ComicsDetailInfoBean> getComicsDetailInfo() {
        return (MutableLiveData) this.comicsDetailInfo.getValue();
    }

    @NotNull
    public final MutableLiveData<List<ComicsDetailInfoBean>> getComicsItemBean() {
        return (MutableLiveData) this.comicsItemBean.getValue();
    }

    @NotNull
    public final MutableLiveData<HashMap<String, ArrayList<FilterData>>> getFilterData() {
        return (MutableLiveData) this.filterData.getValue();
    }

    @NotNull
    public final MutableLiveData<HashMap<String, ArrayList<FilterData>>> getLibrary() {
        return (MutableLiveData) this.library.getValue();
    }

    @NotNull
    public final HashMap<String, ArrayList<FilterData>> getListMap() {
        return (HashMap) this.listMap.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getMHasLike() {
        return (MutableLiveData) this.mHasLike.getValue();
    }

    @NotNull
    public final MutableLiveData<NovelChapterInfoBean> getNovelChapterInfoBean() {
        return (MutableLiveData) this.novelChapterInfoBean.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getNovelChapterInfoBeanAudio() {
        return (MutableLiveData) this.novelChapterInfoBeanAudio.getValue();
    }

    @NotNull
    public final MutableLiveData<NovelChapterInfoBean> getNovelChapterInfoBeanTxt() {
        return (MutableLiveData) this.novelChapterInfoBeanTxt.getValue();
    }

    @NotNull
    public final MutableLiveData<String> getNovelChapterInfoBeanTxtShow() {
        return (MutableLiveData) this.novelChapterInfoBeanTxtShow.getValue();
    }

    @NotNull
    public final MutableLiveData<NovelDetailInfoBean> getNovelDetailInfo() {
        return (MutableLiveData) this.novelDetailInfo.getValue();
    }

    @NotNull
    public final MutableLiveData<List<NovelItemsBean>> getNovelItemsBean() {
        return (MutableLiveData) this.novelItemsBean.getValue();
    }

    @NotNull
    public final MutableLiveData<PicVefBean> getPicVefBean() {
        return (MutableLiveData) this.picVefBean.getValue();
    }

    @NotNull
    public final MutableLiveData<Boolean> getPicVerState() {
        return (MutableLiveData) this.picVerState.getValue();
    }

    public final boolean loveIsNum() {
        String str;
        try {
            ComicsDetailInfoBean value = getComicsDetailInfo().getValue();
            if (value != null && (str = value.favorite) != null) {
                Integer.parseInt(str);
                return true;
            }
            return true;
        } catch (Exception e2) {
            e2.printStackTrace();
            return false;
        }
    }

    public final void novelChapterDetail(@NotNull String chapterId, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(chapterId, "chapterId");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("id", chapterId);
        this.hotJob = C0917a.m221e(C0917a.f372a, "novel/chapterDetail", NovelChapterInfoBean.class, hashMap, new Function1<NovelChapterInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelChapterDetail$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(NovelChapterInfoBean novelChapterInfoBean) {
                invoke2(novelChapterInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable NovelChapterInfoBean novelChapterInfoBean) {
                ComicsViewModel.this.getNovelChapterInfoBean().setValue(novelChapterInfoBean);
                if (hasLoading) {
                    ComicsViewModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelChapterDetail$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    public final void novelDetail(@NotNull String idComics, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(idComics, "idComics");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("id", idComics);
        this.hotJob = C0917a.m221e(C0917a.f372a, "novel/detail", NovelDetailInfoBean.class, hashMap, new Function1<NovelDetailInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelDetail$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(NovelDetailInfoBean novelDetailInfoBean) {
                invoke2(novelDetailInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable NovelDetailInfoBean novelDetailInfoBean) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getNovelDetailInfo().setValue(novelDetailInfoBean);
                this.getMHasLike().setValue(Boolean.valueOf(Intrinsics.areEqual(novelDetailInfoBean == null ? null : novelDetailInfoBean.has_favorite, "y")));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelDetail$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    public final void novelDoFavorite(@NotNull String id, boolean hasLoading, @NotNull Function1<Object, Unit> success, @NotNull Function1<? super Exception, Unit> error) {
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(success, "success");
        Intrinsics.checkNotNullParameter(error, "error");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("id", id);
        this.hotJob = C0917a.m221e(C0917a.f372a, "novel/doFavorite", String.class, hashMap, success, error, false, false, null, false, 480);
    }

    public final void novelSearch(@NotNull String filter, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(filter, "filter");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        HashMap hashMap2 = new HashMap();
        if (!(filter == null || filter.length() == 0)) {
            try {
                JSONObject jSONObject = new JSONObject(filter);
                Iterator<String> keys = jSONObject.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    String value = jSONObject.getString(key);
                    Intrinsics.checkNotNullExpressionValue(key, "key");
                    Intrinsics.checkNotNullExpressionValue(value, "value");
                    hashMap2.put(key, value);
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        hashMap.putAll(hashMap2);
        this.hotJob = C0917a.m222f(C0917a.f372a, "novel/search", NovelItemsBean.class, hashMap, new Function1<List<? extends NovelItemsBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelSearch$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends NovelItemsBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends NovelItemsBean> list) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getNovelItemsBean().setValue(list == null ? null : CollectionsKt___CollectionsKt.toMutableList((Collection) list));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$novelSearch$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.hotJob, this.libraryJob);
    }

    public final void postFilter(final boolean hasLoading) {
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        new HashMap().put("position", "normal");
        this.libraryJob = C0917a.m221e(C0917a.f372a, "post/filter", String.class, new HashMap(), new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$postFilter$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                JSONArray jSONArray = new JSONArray(String.valueOf(str));
                int length = jSONArray.length();
                if (length > 0) {
                    int i2 = 0;
                    while (true) {
                        int i3 = i2 + 1;
                        JSONArray jSONArray2 = jSONArray.getJSONArray(i2);
                        ArrayList<FilterData> arrayList = new ArrayList<>();
                        int length2 = jSONArray2.length();
                        if (length2 > 0) {
                            int i4 = 0;
                            while (true) {
                                int i5 = i4 + 1;
                                JSONObject jSONObject = jSONArray2.getJSONObject(i4);
                                arrayList.add(new FilterData(jSONObject.getString("code"), jSONObject.getString("name"), jSONObject.getString("value")));
                                if (i5 >= length2) {
                                    break;
                                } else {
                                    i4 = i5;
                                }
                            }
                        }
                        this.getListMap().put(String.valueOf(i2), arrayList);
                        if (i3 >= length) {
                            break;
                        } else {
                            i2 = i3;
                        }
                    }
                }
                this.getFilterData().setValue(this.getListMap());
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$postFilter$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    public final void systemCaptcha(@NotNull String key, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(key, "key");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("key", key);
        this.hotJob = C0917a.m221e(C0917a.f372a, "system/captcha", PicVefBean.class, hashMap, new Function1<PicVefBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$systemCaptcha$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(PicVefBean picVefBean) {
                invoke2(picVefBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable PicVefBean picVefBean) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getPicVefBean().setValue(picVefBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$systemCaptcha$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }

    public final void systemUnlock(@NotNull String key, @NotNull String codeValue, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(key, "key");
        Intrinsics.checkNotNullParameter(codeValue, "codeValue");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("key", key);
        hashMap.put("value", codeValue);
        this.hotJob = C0917a.m221e(C0917a.f372a, "system/unlock", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$systemUnlock$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getPicVerState().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$systemUnlock$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                this.getPicVerState().setValue(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    public final void updateLikeNum(boolean hasLike) {
        ComicsDetailInfoBean value = getComicsDetailInfo().getValue();
        if (value == null) {
            return;
        }
        if (hasLike) {
            value.has_favorite = "y";
            if (value.likeIsNum()) {
                value.favorite = String.valueOf(value.getLikeNum() + 1);
            }
        } else {
            value.has_favorite = "n";
            if (value.likeIsNum()) {
                value.favorite = String.valueOf(value.getLikeNum() - 1);
            }
        }
        getMHasLike().setValue(Boolean.valueOf(Intrinsics.areEqual(value.has_favorite, "y")));
    }

    public final void updateLikeNumNovel(boolean hasLike) {
        NovelDetailInfoBean value = getNovelDetailInfo().getValue();
        if (value == null) {
            return;
        }
        if (hasLike) {
            value.has_favorite = "y";
            if (value.likeIsNum()) {
                value.favorite = String.valueOf(value.getLikeNum() + 1);
            }
        } else {
            value.has_favorite = "n";
            if (value.likeIsNum()) {
                value.favorite = String.valueOf(value.getLikeNum() - 1);
            }
        }
        getMHasLike().setValue(Boolean.valueOf(Intrinsics.areEqual(value.has_favorite, "y")));
    }

    public final void getLibrary(@NotNull String position, final boolean hasLoading) {
        Intrinsics.checkNotNullParameter(position, "position");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("position", position);
        this.libraryJob = C0917a.m221e(C0917a.f372a, "movie/filter", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$getLibrary$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                JSONArray jSONArray = new JSONArray(String.valueOf(str));
                int length = jSONArray.length();
                if (length > 0) {
                    int i2 = 0;
                    while (true) {
                        int i3 = i2 + 1;
                        JSONArray jSONArray2 = jSONArray.getJSONArray(i2);
                        ArrayList<FilterData> arrayList = new ArrayList<>();
                        int length2 = jSONArray2.length();
                        if (length2 > 0) {
                            int i4 = 0;
                            while (true) {
                                int i5 = i4 + 1;
                                JSONObject jSONObject = jSONArray2.getJSONObject(i4);
                                arrayList.add(new FilterData(jSONObject.getString("code"), jSONObject.getString("name"), jSONObject.getString("value")));
                                if (i5 >= length2) {
                                    break;
                                } else {
                                    i4 = i5;
                                }
                            }
                        }
                        this.getListMap().put(String.valueOf(i2), arrayList);
                        if (i3 >= length) {
                            break;
                        } else {
                            i2 = i3;
                        }
                    }
                }
                this.getLibrary().setValue(this.getListMap());
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.model.ComicsViewModel$getLibrary$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
            }
        }, false, false, null, false, 480);
    }
}
