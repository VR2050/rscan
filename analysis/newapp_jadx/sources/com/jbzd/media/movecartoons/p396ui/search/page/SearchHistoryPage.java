package com.jbzd.media.movecartoons.p396ui.search.page;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.KeyEvent;
import android.view.View;
import android.widget.TextView;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentTransaction;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.alibaba.fastjson.JSON;
import com.google.android.material.appbar.AppBarLayout;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.HotSearch;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelFragment;
import com.jbzd.media.movecartoons.p396ui.search.SearchResultActivity;
import com.jbzd.media.movecartoons.p396ui.search.adapter.HtyAdapter;
import com.jbzd.media.movecartoons.p396ui.search.adapter.WordsAdapter;
import com.jbzd.media.movecartoons.p396ui.search.adapter.WordsPostAdapter;
import com.jbzd.media.movecartoons.p396ui.search.child.SearchBottomVideosFragment;
import com.jbzd.media.movecartoons.p396ui.search.model.SearchInfoModel;
import com.jbzd.media.movecartoons.p396ui.search.page.SearchHistoryPage;
import com.jbzd.media.movecartoons.utils.banner.BannerAdapterImp;
import com.jbzd.media.movecartoons.view.viewgroup.ScaleRelativeLayout;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import com.qunidayede.supportlibrary.widget.ClearEditText;
import com.youth.banner.Banner;
import com.youth.banner.indicator.RectangleIndicator;
import com.youth.banner.listener.OnBannerListener;
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
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import kotlin.jvm.internal.TypeIntrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0841d0;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.C2827a;
import p005b.p327w.p330b.p331b.ApplicationC2828a;
import p005b.p327w.p330b.p337d.C2861e;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\\\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0007\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010!\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 42\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00014B\u0007¢\u0006\u0004\b3\u0010\u0012J/\u0010\t\u001a\u00020\b2\u000e\u0010\u0004\u001a\n\u0012\u0002\b\u0003\u0012\u0002\b\u00030\u00032\u000e\u0010\u0007\u001a\n\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005H\u0002¢\u0006\u0004\b\t\u0010\nJ\u0019\u0010\r\u001a\u00020\b2\b\u0010\f\u001a\u0004\u0018\u00010\u000bH\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\bH\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0014\u001a\u00020\u0013H\u0016¢\u0006\u0004\b\u0014\u0010\u0015R\u001c\u0010\u0017\u001a\b\u0012\u0004\u0012\u00020\u000b0\u00168\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0017\u0010\u0018R\u001d\u0010\u001c\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u0010R\u001d\u0010!\u001a\u00020\u001d8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u001a\u001a\u0004\b\u001f\u0010 R\u001f\u0010%\u001a\u0004\u0018\u00010\u000b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\"\u0010\u001a\u001a\u0004\b#\u0010$R\u0016\u0010'\u001a\u00020&8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b'\u0010(R\u001d\u0010-\u001a\u00020)8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b*\u0010\u001a\u001a\u0004\b+\u0010,R\u001d\u00102\u001a\u00020.8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b/\u0010\u001a\u001a\u0004\b0\u00101¨\u00065"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/page/SearchHistoryPage;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/search/model/SearchInfoModel;", "Lcom/youth/banner/Banner;", "bannerView", "", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "banners", "", "initBannerView", "(Lcom/youth/banner/Banner;Ljava/util/List;)V", "", SearchResultActivity.KEY_WORDS, "searchData", "(Ljava/lang/String;)V", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/model/SearchInfoModel;", "initViews", "()V", "", "getLayout", "()I", "", "historyList", "Ljava/util/List;", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "viewModel", "Lcom/jbzd/media/movecartoons/ui/search/adapter/WordsAdapter;", "wordsAdapter$delegate", "getWordsAdapter", "()Lcom/jbzd/media/movecartoons/ui/search/adapter/WordsAdapter;", "wordsAdapter", "mPosition$delegate", "getMPosition", "()Ljava/lang/String;", "mPosition", "Landroidx/fragment/app/Fragment;", "mFragment", "Landroidx/fragment/app/Fragment;", "Lcom/jbzd/media/movecartoons/ui/search/adapter/WordsPostAdapter;", "wordsPostAdapter$delegate", "getWordsPostAdapter", "()Lcom/jbzd/media/movecartoons/ui/search/adapter/WordsPostAdapter;", "wordsPostAdapter", "Lcom/jbzd/media/movecartoons/ui/search/adapter/HtyAdapter;", "htyAdapter$delegate", "getHtyAdapter", "()Lcom/jbzd/media/movecartoons/ui/search/adapter/HtyAdapter;", "htyAdapter", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchHistoryPage extends MyThemeViewModelFragment<SearchInfoModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String searchType = "searchType";

    @NotNull
    private List<String> historyList;

    /* renamed from: htyAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy htyAdapter;

    @NotNull
    private Fragment mFragment;

    /* renamed from: mPosition$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPosition;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    /* renamed from: wordsAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy wordsAdapter;

    /* renamed from: wordsPostAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy wordsPostAdapter;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\"\u0010\u0007\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0007\u0010\b\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\f¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/page/SearchHistoryPage$Companion;", "", "", "position", "Lcom/jbzd/media/movecartoons/ui/search/page/SearchHistoryPage;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/search/page/SearchHistoryPage;", "searchType", "Ljava/lang/String;", "getSearchType", "()Ljava/lang/String;", "setSearchType", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getSearchType() {
            return SearchHistoryPage.searchType;
        }

        @NotNull
        public final SearchHistoryPage newInstance(@NotNull String position) {
            Intrinsics.checkNotNullParameter(position, "position");
            SearchHistoryPage searchHistoryPage = new SearchHistoryPage();
            Bundle bundle = new Bundle();
            bundle.putString(SearchHistoryPage.INSTANCE.getSearchType(), position);
            Unit unit = Unit.INSTANCE;
            searchHistoryPage.setArguments(bundle);
            return searchHistoryPage;
        }

        public final void setSearchType(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            SearchHistoryPage.searchType = str;
        }
    }

    public SearchHistoryPage() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchHistoryPage$special$$inlined$viewModels$default$1
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
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(SearchInfoModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchHistoryPage$special$$inlined$viewModels$default$2
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
        this.mPosition = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchHistoryPage$mPosition$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @Nullable
            public final String invoke() {
                Bundle arguments = SearchHistoryPage.this.getArguments();
                if (arguments == null) {
                    return null;
                }
                return arguments.getString(SearchHistoryPage.INSTANCE.getSearchType());
            }
        });
        this.historyList = new ArrayList();
        this.htyAdapter = LazyKt__LazyJVMKt.lazy(new SearchHistoryPage$htyAdapter$2(this));
        this.wordsAdapter = LazyKt__LazyJVMKt.lazy(new SearchHistoryPage$wordsAdapter$2(this));
        this.wordsPostAdapter = LazyKt__LazyJVMKt.lazy(new SearchHistoryPage$wordsPostAdapter$2(this));
        this.mFragment = SearchBottomVideosFragment.Companion.newInstance$default(SearchBottomVideosFragment.INSTANCE, null, 1, null);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final HtyAdapter getHtyAdapter() {
        return (HtyAdapter) this.htyAdapter.getValue();
    }

    private final String getMPosition() {
        return (String) this.mPosition.getValue();
    }

    private final WordsAdapter getWordsAdapter() {
        return (WordsAdapter) this.wordsAdapter.getValue();
    }

    private final WordsPostAdapter getWordsPostAdapter() {
        return (WordsPostAdapter) this.wordsPostAdapter.getValue();
    }

    private final void initBannerView(Banner<?, ?> bannerView, final List<? extends AdBean> banners) {
        if (banners == null || !C2354n.m2414N0(banners)) {
            View view = getView();
            ((ScaleRelativeLayout) (view != null ? view.findViewById(R$id.banner_parent_search) : null)).setVisibility(8);
            return;
        }
        View view2 = getView();
        ((ScaleRelativeLayout) (view2 != null ? view2.findViewById(R$id.banner_parent_search) : null)).setVisibility(0);
        bannerView.setIntercept(banners.size() != 1);
        Banner addBannerLifecycleObserver = bannerView.addBannerLifecycleObserver(this);
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(banners, 10));
        Iterator<T> it = banners.iterator();
        while (it.hasNext()) {
            arrayList.add(((AdBean) it.next()).content);
        }
        addBannerLifecycleObserver.setAdapter(new BannerAdapterImp(requireContext, arrayList, 0.0f, 1.0d, null, 16));
        bannerView.setOnBannerListener(new OnBannerListener() { // from class: b.a.a.a.t.m.k.c
            @Override // com.youth.banner.listener.OnBannerListener
            public final void OnBannerClick(Object obj, int i2) {
                SearchHistoryPage.m5987initBannerView$lambda9$lambda8(SearchHistoryPage.this, banners, obj, i2);
            }
        });
        bannerView.setIndicator(new RectangleIndicator(requireContext()));
        bannerView.start();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initBannerView$lambda-9$lambda-8, reason: not valid java name */
    public static final void m5987initBannerView$lambda9$lambda8(SearchHistoryPage this$0, List list, Object obj, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        C0840d.a aVar = C0840d.f235a;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        aVar.m176b(requireContext, (AdBean) list.get(i2));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-0, reason: not valid java name */
    public static final void m5988initViews$lambda0(SearchHistoryPage this$0, HotSearch hotSearch) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        this$0.getWordsAdapter().setNewData(hotSearch.items);
        if (hotSearch.ads != null) {
            View view = this$0.getView();
            View banner_search = view == null ? null : view.findViewById(R$id.banner_search);
            Intrinsics.checkNotNullExpressionValue(banner_search, "banner_search");
            this$0.initBannerView((Banner) banner_search, hotSearch.ads);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-1, reason: not valid java name */
    public static final void m5989initViews$lambda1(SearchHistoryPage this$0, List it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        WordsPostAdapter wordsPostAdapter = this$0.getWordsPostAdapter();
        Intrinsics.checkNotNullExpressionValue(it, "it");
        wordsPostAdapter.setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) it));
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initViews$lambda-5, reason: not valid java name */
    public static final boolean m5990initViews$lambda5(SearchHistoryPage this$0, TextView textView, int i2, KeyEvent keyEvent) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (i2 != 3) {
            return false;
        }
        View view = this$0.getView();
        C2861e.m3306d(view == null ? null : view.findViewById(R$id.cet_input));
        View view2 = this$0.getView();
        if (!C0841d0.m178a(StringsKt__StringsKt.trim((CharSequence) String.valueOf(((ClearEditText) (view2 != null ? view2.findViewById(R$id.cet_input) : null)).getText())).toString())) {
            return false;
        }
        this$0.historyList = C0841d0.m179b();
        return false;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    /* JADX WARN: Removed duplicated region for block: B:25:0x00e9  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void searchData(java.lang.String r8) {
        /*
            Method dump skipped, instructions count: 294
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.search.page.SearchHistoryPage.searchData(java.lang.String):void");
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_search_history;
    }

    @NotNull
    public final SearchInfoModel getViewModel() {
        return (SearchInfoModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        int i2;
        super.initViews();
        if (C0841d0.f236a == null) {
            Intrinsics.checkNotNullParameter("history", "key");
            Intrinsics.checkNotNullParameter("[]", "default");
            ApplicationC2828a applicationC2828a = C2827a.f7670a;
            if (applicationC2828a == null) {
                Intrinsics.throwUninitializedPropertyAccessException("context");
                throw null;
            }
            SharedPreferences sharedPreferences = applicationC2828a.getSharedPreferences("default_storage", 0);
            Intrinsics.checkNotNullExpressionValue(sharedPreferences, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
            String string = sharedPreferences.getString("history", "[]");
            Intrinsics.checkNotNull(string);
            List parseArray = JSON.parseArray(string, String.class);
            Objects.requireNonNull(parseArray, "null cannot be cast to non-null type kotlin.collections.MutableList<kotlin.String>");
            C0841d0.f236a = TypeIntrinsics.asMutableList(parseArray);
        }
        List<String> list = C0841d0.f236a;
        Objects.requireNonNull(list, "null cannot be cast to non-null type kotlin.collections.MutableList<kotlin.String>");
        this.historyList = TypeIntrinsics.asMutableList(list);
        getHtyAdapter().setNewData(this.historyList);
        String mPosition = getMPosition();
        if (Intrinsics.areEqual(mPosition, "comics")) {
            View view = getView();
            ((ClearEditText) (view == null ? null : view.findViewById(R$id.cet_input))).setHint("输入关键字搜索更多漫画");
        } else if (Intrinsics.areEqual(mPosition, "cartoon")) {
            View view2 = getView();
            ((ClearEditText) (view2 == null ? null : view2.findViewById(R$id.cet_input))).setHint("输入关键字搜索更多动漫");
        } else {
            View view3 = getView();
            ((ClearEditText) (view3 == null ? null : view3.findViewById(R$id.cet_input))).setHint("请输入要搜索到的内容");
        }
        getViewModel().getHotKeywords().observe(this, new Observer() { // from class: b.a.a.a.t.m.k.a
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                SearchHistoryPage.m5988initViews$lambda0(SearchHistoryPage.this, (HotSearch) obj);
            }
        });
        getViewModel().getHotTagAndCategor().observe(this, new Observer() { // from class: b.a.a.a.t.m.k.d
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                SearchHistoryPage.m5989initViews$lambda1(SearchHistoryPage.this, (List) obj);
            }
        });
        HashMap hashMap = new HashMap();
        if (StringsKt__StringsJVMKt.equals$default(getMPosition(), "post", false, 2, null)) {
            SearchInfoModel.getPostCategories$default(getViewModel(), "normal", false, 2, null);
            View view4 = getView();
            ((RecyclerView) (view4 == null ? null : view4.findViewById(R$id.rv_hotWords))).setVisibility(8);
            View view5 = getView();
            ((RecyclerView) (view5 == null ? null : view5.findViewById(R$id.rv_hotWords_post))).setVisibility(0);
            View view6 = getView();
            RecyclerView recyclerView = (RecyclerView) (view6 != null ? view6.findViewById(R$id.rv_hotWords_post) : null);
            recyclerView.setAdapter(getWordsPostAdapter());
            recyclerView.setLayoutManager(new GridLayoutManager(getActivity(), 2));
            if (recyclerView.getItemDecorationCount() == 0) {
                GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(recyclerView.getContext());
                c4053a.f10336d = C1499a.m638x(c4053a, R.color.transparent, recyclerView, 16.0d);
                c4053a.f10337e = C2354n.m2437V(recyclerView.getContext(), 24.0d);
                c4053a.f10339g = false;
                c4053a.f10340h = false;
                c4053a.f10338f = false;
                C1499a.m604Z(c4053a, recyclerView);
            }
            i2 = R.color.transparent;
        } else {
            hashMap.put("position", String.valueOf(getMPosition()));
            SearchInfoModel viewModel = getViewModel();
            String valueOf = String.valueOf(getMPosition());
            i2 = R.color.transparent;
            SearchInfoModel.getKeywords$default(viewModel, valueOf, hashMap, false, 4, null);
            View view7 = getView();
            ((RecyclerView) (view7 == null ? null : view7.findViewById(R$id.rv_hotWords))).setVisibility(0);
            View view8 = getView();
            ((RecyclerView) (view8 == null ? null : view8.findViewById(R$id.rv_hotWords_post))).setVisibility(8);
            View view9 = getView();
            RecyclerView recyclerView2 = (RecyclerView) (view9 == null ? null : view9.findViewById(R$id.rv_hotWords));
            recyclerView2.setAdapter(getWordsAdapter());
            recyclerView2.setLayoutManager(new GridLayoutManager(getActivity(), 2));
            if (recyclerView2.getItemDecorationCount() == 0) {
                GridItemDecoration.C4053a c4053a2 = new GridItemDecoration.C4053a(recyclerView2.getContext());
                c4053a2.f10336d = C1499a.m638x(c4053a2, R.color.transparent, recyclerView2, 16.0d);
                c4053a2.f10337e = C2354n.m2437V(recyclerView2.getContext(), 24.0d);
                c4053a2.f10339g = false;
                c4053a2.f10340h = false;
                c4053a2.f10338f = false;
                C1499a.m604Z(c4053a2, recyclerView2);
            }
        }
        View view10 = getView();
        View tv_clear_history = view10 == null ? null : view10.findViewById(R$id.tv_clear_history);
        Intrinsics.checkNotNullExpressionValue(tv_clear_history, "tv_clear_history");
        MyThemeViewModelFragment.fadeWhenTouch$default(this, tv_clear_history, 0.0f, 1, null);
        View view11 = getView();
        C2354n.m2377B(view11 == null ? null : view11.findViewById(R$id.tv_clear_history), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchHistoryPage$initViews$5
            {
                super(1);
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView) {
                HtyAdapter htyAdapter;
                if (C0841d0.f236a == null) {
                    if (C0841d0.f236a == null) {
                        Intrinsics.checkNotNullParameter("history", "key");
                        Intrinsics.checkNotNullParameter("[]", "default");
                        ApplicationC2828a applicationC2828a2 = C2827a.f7670a;
                        if (applicationC2828a2 == null) {
                            Intrinsics.throwUninitializedPropertyAccessException("context");
                            throw null;
                        }
                        SharedPreferences sharedPreferences2 = applicationC2828a2.getSharedPreferences("default_storage", 0);
                        Intrinsics.checkNotNullExpressionValue(sharedPreferences2, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
                        String string2 = sharedPreferences2.getString("history", "[]");
                        Intrinsics.checkNotNull(string2);
                        List parseArray2 = JSON.parseArray(string2, String.class);
                        Objects.requireNonNull(parseArray2, "null cannot be cast to non-null type kotlin.collections.MutableList<kotlin.String>");
                        C0841d0.f236a = TypeIntrinsics.asMutableList(parseArray2);
                    }
                    List<String> list2 = C0841d0.f236a;
                    Objects.requireNonNull(list2, "null cannot be cast to non-null type kotlin.collections.MutableList<kotlin.String>");
                    TypeIntrinsics.asMutableList(list2);
                }
                List<String> list3 = C0841d0.f236a;
                if (list3 != null) {
                    list3.clear();
                }
                String value = JSON.toJSONString(C0841d0.f236a);
                Intrinsics.checkNotNullExpressionValue(value, "toJSONString(historyItems)");
                Intrinsics.checkNotNullParameter("history", "key");
                Intrinsics.checkNotNullParameter(value, "value");
                ApplicationC2828a applicationC2828a3 = C2827a.f7670a;
                if (applicationC2828a3 == null) {
                    Intrinsics.throwUninitializedPropertyAccessException("context");
                    throw null;
                }
                SharedPreferences sharedPreferences3 = applicationC2828a3.getSharedPreferences("default_storage", 0);
                Intrinsics.checkNotNullExpressionValue(sharedPreferences3, "SupportLibraryInstance.context.getSharedPreferences(DEFAULT_STORAGE_NAME,Context.MODE_PRIVATE)");
                SharedPreferences.Editor editor = sharedPreferences3.edit();
                Intrinsics.checkExpressionValueIsNotNull(editor, "editor");
                editor.putString("history", value);
                editor.commit();
                htyAdapter = SearchHistoryPage.this.getHtyAdapter();
                htyAdapter.notifyDataSetChanged();
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }
        }, 1);
        View view12 = getView();
        C2354n.m2377B(view12 == null ? null : view12.findViewById(R$id.tv_doSearch), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchHistoryPage$initViews$6
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TextView textView) {
                invoke2(textView);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(TextView textView) {
                View view13 = SearchHistoryPage.this.getView();
                C2861e.m3306d(view13 == null ? null : view13.findViewById(R$id.cet_input));
                View view14 = SearchHistoryPage.this.getView();
                String obj = StringsKt__StringsKt.trim((CharSequence) String.valueOf(((ClearEditText) (view14 != null ? view14.findViewById(R$id.cet_input) : null)).getText())).toString();
                if ((obj.length() > 0) && C0841d0.m178a(obj)) {
                    SearchHistoryPage.this.historyList = C0841d0.m179b();
                }
                SearchHistoryPage.this.searchData(obj);
            }
        }, 1);
        View view13 = getView();
        View cet_input = view13 == null ? null : view13.findViewById(R$id.cet_input);
        Intrinsics.checkNotNullExpressionValue(cet_input, "cet_input");
        ((TextView) cet_input).addTextChangedListener(new TextWatcher() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchHistoryPage$initViews$$inlined$doAfterTextChanged$1
            @Override // android.text.TextWatcher
            public void afterTextChanged(@Nullable Editable s) {
                Fragment fragment;
                HtyAdapter htyAdapter;
                if (StringsKt__StringsKt.trim((CharSequence) String.valueOf(s)).toString().length() == 0) {
                    View view14 = SearchHistoryPage.this.getView();
                    ((AppBarLayout) (view14 == null ? null : view14.findViewById(R$id.app_bar_layout))).setVisibility(0);
                    FragmentTransaction beginTransaction = SearchHistoryPage.this.requireActivity().getSupportFragmentManager().beginTransaction();
                    fragment = SearchHistoryPage.this.mFragment;
                    beginTransaction.remove(fragment).commit();
                    SearchHistoryPage.this.mFragment = SearchBottomVideosFragment.Companion.newInstance$default(SearchBottomVideosFragment.INSTANCE, null, 1, null);
                    htyAdapter = SearchHistoryPage.this.getHtyAdapter();
                    htyAdapter.notifyDataSetChanged();
                }
            }

            @Override // android.text.TextWatcher
            public void beforeTextChanged(@Nullable CharSequence text, int start, int count, int after) {
            }

            @Override // android.text.TextWatcher
            public void onTextChanged(@Nullable CharSequence text, int start, int before, int count) {
            }
        });
        View view14 = getView();
        ((ClearEditText) (view14 == null ? null : view14.findViewById(R$id.cet_input))).setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: b.a.a.a.t.m.k.b
            @Override // android.widget.TextView.OnEditorActionListener
            public final boolean onEditorAction(TextView textView, int i3, KeyEvent keyEvent) {
                boolean m5990initViews$lambda5;
                m5990initViews$lambda5 = SearchHistoryPage.m5990initViews$lambda5(SearchHistoryPage.this, textView, i3, keyEvent);
                return m5990initViews$lambda5;
            }
        });
        View view15 = getView();
        RecyclerView recyclerView3 = (RecyclerView) (view15 != null ? view15.findViewById(R$id.rv_hty) : null);
        recyclerView3.setAdapter(getHtyAdapter());
        recyclerView3.setLayoutManager(new GridLayoutManager(requireActivity(), 5));
        if (recyclerView3.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a3 = new GridItemDecoration.C4053a(recyclerView3.getContext());
            c4053a3.f10336d = C1499a.m638x(c4053a3, i2, recyclerView3, 10.0d);
            c4053a3.f10337e = C2354n.m2437V(recyclerView3.getContext(), 5.0d);
            c4053a3.f10339g = false;
            c4053a3.f10340h = false;
            c4053a3.f10338f = false;
            C1499a.m604Z(c4053a3, recyclerView3);
        }
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment
    @NotNull
    public SearchInfoModel viewModelInstance() {
        return getViewModel();
    }
}
