package com.jbzd.media.movecartoons.p396ui.search.page;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.view.View;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;
import androidx.fragment.app.FragmentViewModelLazyKt;
import androidx.lifecycle.LifecycleOwner;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelStore;
import androidx.lifecycle.ViewModelStoreOwner;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.FilterData;
import com.jbzd.media.movecartoons.bean.response.LibraryBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelFragment;
import com.jbzd.media.movecartoons.p396ui.search.adapter.CheckChange;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonComicsListFragment;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonNovelListFragment;
import com.jbzd.media.movecartoons.p396ui.search.model.SearchInfoModel;
import com.jbzd.media.movecartoons.p396ui.search.page.SearchComicsLibraryPage;
import com.jbzd.media.movecartoons.p396ui.search.recyclerview.SearchView;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000(\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0002\b\b\u0018\u0000 \u00152\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0002\u0015\u0016B\u0007¢\u0006\u0004\b\u0014\u0010\u0007J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\t\u0010\nR\u001d\u0010\u000e\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\u0004R\u001d\u0010\u0013\u001a\u00020\u000f8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\f\u001a\u0004\b\u0011\u0010\u0012¨\u0006\u0017"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/page/SearchComicsLibraryPage;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelFragment;", "Lcom/jbzd/media/movecartoons/ui/search/model/SearchInfoModel;", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/model/SearchInfoModel;", "", "initViews", "()V", "", "getLayout", "()I", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "viewModel", "", "mPosition$delegate", "getMPosition", "()Ljava/lang/String;", "mPosition", "<init>", "Companion", "SearchCheck", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchComicsLibraryPage extends MyThemeViewModelFragment<SearchInfoModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String searchType = "searchType";

    /* renamed from: mPosition$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mPosition;

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\"\u0010\u0007\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0007\u0010\b\u001a\u0004\b\t\u0010\n\"\u0004\b\u000b\u0010\f¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/page/SearchComicsLibraryPage$Companion;", "", "", "position", "Lcom/jbzd/media/movecartoons/ui/search/page/SearchComicsLibraryPage;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/search/page/SearchComicsLibraryPage;", "searchType", "Ljava/lang/String;", "getSearchType", "()Ljava/lang/String;", "setSearchType", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getSearchType() {
            return SearchComicsLibraryPage.searchType;
        }

        @NotNull
        public final SearchComicsLibraryPage newInstance(@NotNull String position) {
            Intrinsics.checkNotNullParameter(position, "position");
            SearchComicsLibraryPage searchComicsLibraryPage = new SearchComicsLibraryPage();
            Bundle bundle = new Bundle();
            bundle.putString(SearchComicsLibraryPage.INSTANCE.getSearchType(), position);
            Unit unit = Unit.INSTANCE;
            searchComicsLibraryPage.setArguments(bundle);
            return searchComicsLibraryPage;
        }

        public final void setSearchType(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            SearchComicsLibraryPage.searchType = str;
        }
    }

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\r\u0018\u00002\u00020\u0001B\u001f\u0012\u0006\u0010\f\u001a\u00020\u000b\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0013\u001a\u00020\u0012¢\u0006\u0004\b\u001d\u0010\u001eJ\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0007¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\t\u001a\u00020\u00042\u0006\u0010\b\u001a\u00020\u0007H\u0016¢\u0006\u0004\b\t\u0010\nR\"\u0010\f\u001a\u00020\u000b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\f\u0010\r\u001a\u0004\b\u000e\u0010\u000f\"\u0004\b\u0010\u0010\u0011R\"\u0010\u0013\u001a\u00020\u00128\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016\"\u0004\b\u0017\u0010\u0018R\"\u0010\u0003\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0003\u0010\u0019\u001a\u0004\b\u001a\u0010\u001b\"\u0004\b\u001c\u0010\u0006¨\u0006\u001f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/page/SearchComicsLibraryPage$SearchCheck;", "Lcom/jbzd/media/movecartoons/ui/search/adapter/CheckChange;", "Lcom/jbzd/media/movecartoons/bean/response/LibraryBean;", "bean", "", "doSearch", "(Lcom/jbzd/media/movecartoons/bean/response/LibraryBean;)V", "Lcom/jbzd/media/movecartoons/bean/response/FilterData;", "item", "change", "(Lcom/jbzd/media/movecartoons/bean/response/FilterData;)V", "", "mPosition", "Ljava/lang/String;", "getMPosition", "()Ljava/lang/String;", "setMPosition", "(Ljava/lang/String;)V", "Landroidx/fragment/app/FragmentActivity;", "act", "Landroidx/fragment/app/FragmentActivity;", "getAct", "()Landroidx/fragment/app/FragmentActivity;", "setAct", "(Landroidx/fragment/app/FragmentActivity;)V", "Lcom/jbzd/media/movecartoons/bean/response/LibraryBean;", "getBean", "()Lcom/jbzd/media/movecartoons/bean/response/LibraryBean;", "setBean", "<init>", "(Ljava/lang/String;Lcom/jbzd/media/movecartoons/bean/response/LibraryBean;Landroidx/fragment/app/FragmentActivity;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class SearchCheck extends CheckChange {

        @NotNull
        private FragmentActivity act;

        @NotNull
        private LibraryBean bean;

        @NotNull
        private String mPosition;

        public SearchCheck(@NotNull String mPosition, @NotNull LibraryBean bean, @NotNull FragmentActivity act) {
            Intrinsics.checkNotNullParameter(mPosition, "mPosition");
            Intrinsics.checkNotNullParameter(bean, "bean");
            Intrinsics.checkNotNullParameter(act, "act");
            this.mPosition = mPosition;
            this.bean = bean;
            this.act = act;
        }

        @Override // com.jbzd.media.movecartoons.p396ui.search.adapter.CheckChange
        public void change(@NotNull FilterData item) {
            Intrinsics.checkNotNullParameter(item, "item");
            doSearch(this.bean);
        }

        @SuppressLint({"SuspiciousIndentation"})
        public final void doSearch(@NotNull LibraryBean bean) {
            Intrinsics.checkNotNullParameter(bean, "bean");
            HashMap<String, String> hashMap = new HashMap<>();
            List<FilterData> list = bean.one;
            Intrinsics.checkNotNullExpressionValue(list, "bean.one");
            for (FilterData filterData : list) {
                if (filterData.isSelected) {
                    String code = filterData.getCode();
                    Intrinsics.checkNotNullExpressionValue(code, "it.code");
                    String value = filterData.getValue();
                    Intrinsics.checkNotNullExpressionValue(value, "it.value");
                    hashMap.put(code, value);
                }
            }
            List<FilterData> list2 = bean.two;
            Intrinsics.checkNotNullExpressionValue(list2, "bean.two");
            for (FilterData filterData2 : list2) {
                if (filterData2.isSelected) {
                    String code2 = filterData2.getCode();
                    Intrinsics.checkNotNullExpressionValue(code2, "it.code");
                    String value2 = filterData2.getValue();
                    Intrinsics.checkNotNullExpressionValue(value2, "it.value");
                    hashMap.put(code2, value2);
                }
            }
            List<FilterData> list3 = bean.three;
            Intrinsics.checkNotNullExpressionValue(list3, "bean.three");
            for (FilterData filterData3 : list3) {
                if (filterData3.isSelected) {
                    String code3 = filterData3.getCode();
                    Intrinsics.checkNotNullExpressionValue(code3, "it.code");
                    String value3 = filterData3.getValue();
                    Intrinsics.checkNotNullExpressionValue(value3, "it.value");
                    hashMap.put(code3, value3);
                }
            }
            List<FilterData> list4 = bean.four;
            Intrinsics.checkNotNullExpressionValue(list4, "bean.four");
            for (FilterData filterData4 : list4) {
                if (filterData4.isSelected) {
                    String code4 = filterData4.getCode();
                    Intrinsics.checkNotNullExpressionValue(code4, "it.code");
                    String value4 = filterData4.getValue();
                    Intrinsics.checkNotNullExpressionValue(value4, "it.value");
                    hashMap.put(code4, value4);
                }
            }
            String str = this.mPosition;
            if ((str == null ? null : Boolean.valueOf(str.equals("comics"))).booleanValue()) {
                this.act.getSupportFragmentManager().beginTransaction().replace(R.id.fragment_container, CommonComicsListFragment.INSTANCE.newInstance(hashMap)).commit();
            } else {
                this.act.getSupportFragmentManager().beginTransaction().replace(R.id.fragment_container, CommonNovelListFragment.INSTANCE.newInstance(hashMap)).commit();
            }
        }

        @NotNull
        public final FragmentActivity getAct() {
            return this.act;
        }

        @NotNull
        public final LibraryBean getBean() {
            return this.bean;
        }

        @NotNull
        public final String getMPosition() {
            return this.mPosition;
        }

        public final void setAct(@NotNull FragmentActivity fragmentActivity) {
            Intrinsics.checkNotNullParameter(fragmentActivity, "<set-?>");
            this.act = fragmentActivity;
        }

        public final void setBean(@NotNull LibraryBean libraryBean) {
            Intrinsics.checkNotNullParameter(libraryBean, "<set-?>");
            this.bean = libraryBean;
        }

        public final void setMPosition(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            this.mPosition = str;
        }
    }

    public SearchComicsLibraryPage() {
        final Function0<Fragment> function0 = new Function0<Fragment>() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchComicsLibraryPage$special$$inlined$viewModels$default$1
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
        this.viewModel = FragmentViewModelLazyKt.createViewModelLazy(this, Reflection.getOrCreateKotlinClass(SearchInfoModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchComicsLibraryPage$special$$inlined$viewModels$default$2
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
        this.mPosition = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchComicsLibraryPage$mPosition$2
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            @NotNull
            public final String invoke() {
                Bundle arguments = SearchComicsLibraryPage.this.getArguments();
                String string = arguments == null ? null : arguments.getString(SearchComicsLibraryPage.INSTANCE.getSearchType());
                Objects.requireNonNull(string, "null cannot be cast to non-null type kotlin.String");
                return string;
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getMPosition() {
        return (String) this.mPosition.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseViewModelFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public int getLayout() {
        return R.layout.frag_search_videostocks;
    }

    @NotNull
    public final SearchInfoModel getViewModel() {
        return (SearchInfoModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        String mPosition = getMPosition();
        if ((mPosition == null ? null : Boolean.valueOf(mPosition.equals("comics"))).booleanValue()) {
            SearchInfoModel.comicsFilter$default(getViewModel(), false, 1, null);
        } else {
            SearchInfoModel.novelFilter$default(getViewModel(), false, 1, null);
        }
        LiveData filterData = getViewModel().getFilterData();
        LifecycleOwner viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "viewLifecycleOwner");
        filterData.observe(viewLifecycleOwner, new Observer<T>() { // from class: com.jbzd.media.movecartoons.ui.search.page.SearchComicsLibraryPage$initViews$$inlined$observe$1
            /* JADX WARN: Multi-variable type inference failed */
            @Override // androidx.lifecycle.Observer
            public final void onChanged(T t) {
                String mPosition2;
                String mPosition3;
                LibraryBean libraryBean = new LibraryBean();
                Collection<ArrayList<FilterData>> values = SearchComicsLibraryPage.this.getViewModel().getListMap().values();
                Intrinsics.checkNotNullExpressionValue(values, "viewModel.listMap.values");
                ArrayList arrayList = new ArrayList(values);
                if (arrayList.size() == 4) {
                    libraryBean.one = (List) arrayList.get(0);
                    libraryBean.two = (List) arrayList.get(1);
                    libraryBean.three = (List) arrayList.get(2);
                    libraryBean.four = (List) arrayList.get(3);
                    libraryBean.one.get(0).isSelected = true;
                    libraryBean.two.get(0).isSelected = true;
                    libraryBean.three.get(0).isSelected = true;
                    libraryBean.four.get(0).isSelected = true;
                    View view = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view == null ? null : view.findViewById(R$id.rv_type_1))).getAdapter().setNewData(libraryBean.one);
                    View view2 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view2 == null ? null : view2.findViewById(R$id.rv_type_2))).getAdapter().setNewData(libraryBean.two);
                    View view3 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view3 == null ? null : view3.findViewById(R$id.rv_type_3))).getAdapter().setNewData(libraryBean.three);
                    View view4 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view4 == null ? null : view4.findViewById(R$id.rv_type_4))).getAdapter().setNewData(libraryBean.four);
                    mPosition3 = SearchComicsLibraryPage.this.getMPosition();
                    FragmentActivity requireActivity = SearchComicsLibraryPage.this.requireActivity();
                    Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity()");
                    SearchComicsLibraryPage.SearchCheck searchCheck = new SearchComicsLibraryPage.SearchCheck(mPosition3, libraryBean, requireActivity);
                    View view5 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view5 == null ? null : view5.findViewById(R$id.rv_type_1))).getAdapter().setChange(searchCheck);
                    View view6 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view6 == null ? null : view6.findViewById(R$id.rv_type_2))).getAdapter().setChange(searchCheck);
                    View view7 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view7 == null ? null : view7.findViewById(R$id.rv_type_3))).getAdapter().setChange(searchCheck);
                    View view8 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view8 == null ? null : view8.findViewById(R$id.rv_type_4))).getAdapter().setChange(searchCheck);
                    searchCheck.doSearch(libraryBean);
                    View view9 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view9 == null ? null : view9.findViewById(R$id.rv_type_4))).setVisibility(0);
                }
                if (arrayList.size() == 3) {
                    libraryBean.one = (List) arrayList.get(0);
                    libraryBean.two = (List) arrayList.get(1);
                    libraryBean.three = (List) arrayList.get(2);
                    libraryBean.one.get(0).isSelected = true;
                    libraryBean.two.get(0).isSelected = true;
                    libraryBean.three.get(0).isSelected = true;
                    View view10 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view10 == null ? null : view10.findViewById(R$id.rv_type_1))).getAdapter().setNewData(libraryBean.one);
                    View view11 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view11 == null ? null : view11.findViewById(R$id.rv_type_2))).getAdapter().setNewData(libraryBean.two);
                    View view12 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view12 == null ? null : view12.findViewById(R$id.rv_type_3))).getAdapter().setNewData(libraryBean.three);
                    mPosition2 = SearchComicsLibraryPage.this.getMPosition();
                    FragmentActivity requireActivity2 = SearchComicsLibraryPage.this.requireActivity();
                    Intrinsics.checkNotNullExpressionValue(requireActivity2, "requireActivity()");
                    SearchComicsLibraryPage.SearchCheck searchCheck2 = new SearchComicsLibraryPage.SearchCheck(mPosition2, libraryBean, requireActivity2);
                    View view13 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view13 == null ? null : view13.findViewById(R$id.rv_type_1))).getAdapter().setChange(searchCheck2);
                    View view14 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view14 == null ? null : view14.findViewById(R$id.rv_type_2))).getAdapter().setChange(searchCheck2);
                    View view15 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view15 == null ? null : view15.findViewById(R$id.rv_type_3))).getAdapter().setChange(searchCheck2);
                    searchCheck2.doSearch(libraryBean);
                    View view16 = SearchComicsLibraryPage.this.getView();
                    ((SearchView) (view16 != null ? view16.findViewById(R$id.rv_type_4) : null)).setVisibility(8);
                }
            }
        });
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelFragment
    @NotNull
    public SearchInfoModel viewModelInstance() {
        return getViewModel();
    }
}
