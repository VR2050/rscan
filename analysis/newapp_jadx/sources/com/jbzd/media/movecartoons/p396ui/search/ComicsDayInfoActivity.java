package com.jbzd.media.movecartoons.p396ui.search;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.activity.ComponentActivity;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.ComicsDayInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.search.ComicsDayInfoActivity;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonComicsListFragment;
import com.jbzd.media.movecartoons.p396ui.search.model.ComicsViewModel;
import com.qnmd.adnnm.da0yzo.R;
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
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0013\u0018\u0000  2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001 B\u0007¢\u0006\u0004\b\u001f\u0010\u0007J\r\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0006\u001a\u00020\u0005H\u0017¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\t\u0010\nJ\u000f\u0010\f\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\f\u0010\rJ\u0019\u0010\u0010\u001a\u00020\u00052\b\u0010\u000f\u001a\u0004\u0018\u00010\u000eH\u0014¢\u0006\u0004\b\u0010\u0010\u0011R\u001d\u0010\u0015\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0012\u0010\u0013\u001a\u0004\b\u0014\u0010\u0004R\u001f\u0010\u0018\u001a\u0004\u0018\u00010\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0016\u0010\u0013\u001a\u0004\b\u0017\u0010\nR\u001f\u0010\u001b\u001a\u0004\u0018\u00010\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u0013\u001a\u0004\b\u001a\u0010\nR\u001f\u0010\u001e\u001a\u0004\u0018\u00010\b8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0013\u001a\u0004\b\u001d\u0010\n¨\u0006!"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/ComicsDayInfoActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/model/ComicsViewModel;", "", "bindEvent", "()V", "", "getTopBarTitle", "()Ljava/lang/String;", "", "getLayoutId", "()I", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "viewModel$delegate", "Lkotlin/Lazy;", "getViewModel", "viewModel", "filter$delegate", "getFilter", "filter", "name$delegate", "getName", "name", "show_type$delegate", "getShow_type", "show_type", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ComicsDayInfoActivity extends MyThemeActivity<ComicsViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String order = "";

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(ComicsViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.search.ComicsDayInfoActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.search.ComicsDayInfoActivity$special$$inlined$viewModels$default$1
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

    /* renamed from: show_type$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy show_type = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.ComicsDayInfoActivity$show_type$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ComicsDayInfoActivity.this.getIntent().getStringExtra("show_type");
        }
    });

    /* renamed from: filter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy filter = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.ComicsDayInfoActivity$filter$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ComicsDayInfoActivity.this.getIntent().getStringExtra("filter");
        }
    });

    /* renamed from: name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy name = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.ComicsDayInfoActivity$name$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ComicsDayInfoActivity.this.getIntent().getStringExtra("name");
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\bR\"\u0010\t\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\t\u0010\n\u001a\u0004\b\u000b\u0010\f\"\u0004\b\r\u0010\u000e¨\u0006\u0011"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/ComicsDayInfoActivity$Companion;", "", "Landroid/content/Context;", "context", "", "filter", "", "start", "(Landroid/content/Context;Ljava/lang/String;)V", "order", "Ljava/lang/String;", "getOrder", "()Ljava/lang/String;", "setOrder", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getOrder() {
            return ComicsDayInfoActivity.order;
        }

        public final void setOrder(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            ComicsDayInfoActivity.order = str;
        }

        public final void start(@NotNull Context context, @NotNull String filter) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(filter, "filter");
            Intent intent = new Intent(context, (Class<?>) ComicsDayInfoActivity.class);
            intent.putExtra("filter", filter);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-3$lambda-2, reason: not valid java name */
    public static final void m5975bindEvent$lambda3$lambda2(ComicsDayInfoActivity this$0, List it) {
        int i2;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        ArrayList arrayList = new ArrayList();
        ArrayList arrayList2 = new ArrayList();
        Intrinsics.checkNotNullExpressionValue(it, "it");
        int size = CollectionsKt___CollectionsKt.toMutableList((Collection) it).size() - 1;
        if (size >= 0) {
            int i3 = 0;
            int i4 = 0;
            while (true) {
                int i5 = i3 + 1;
                if (((ComicsDayInfoBean) it.get(i3)).is_selected.equals("y")) {
                    i4 = i3;
                }
                arrayList.add(((ComicsDayInfoBean) it.get(i3)).name);
                String str = ((ComicsDayInfoBean) it.get(i3)).filter;
                HashMap<String, String> hashMap = new HashMap<>();
                if (!(str == null || str.length() == 0)) {
                    try {
                        JSONObject jSONObject = new JSONObject(str);
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
                hashMap.put("ad_code", "comic_list_ad");
                arrayList2.add(CommonComicsListFragment.INSTANCE.newInstance(hashMap));
                if (i5 > size) {
                    break;
                } else {
                    i3 = i5;
                }
            }
            i2 = i4;
        } else {
            i2 = 0;
        }
        FragmentManager supportFragmentManager = this$0.getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
        ViewPagerAdapter viewPagerAdapter = new ViewPagerAdapter(supportFragmentManager, arrayList2, 0, 4, null);
        int i6 = R$id.vp_comics_dayinfo;
        ViewPager viewPager = (ViewPager) this$0.findViewById(i6);
        viewPager.setOffscreenPageLimit(arrayList.size());
        viewPager.setAdapter(viewPagerAdapter);
        viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.search.ComicsDayInfoActivity$bindEvent$1$1$1$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
            }
        });
        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) this$0.findViewById(R$id.tab_comics_dayinfo);
        ViewPager viewPager2 = (ViewPager) this$0.findViewById(i6);
        Object[] array = arrayList.toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        slidingTabLayout.m4011e(viewPager2, (String[]) array);
        ((ViewPager) this$0.findViewById(i6)).setCurrentItem(i2);
    }

    private final String getFilter() {
        return (String) this.filter.getValue();
    }

    private final String getName() {
        return (String) this.name.getValue();
    }

    private final String getShow_type() {
        return (String) this.show_type.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    @SuppressLint({"SuspiciousIndentation"})
    public void bindEvent() {
        ComicsViewModel.comicsDayInfo$default(getViewModel(), false, 1, null);
        getViewModel().getComicsDayInfoBean().observe(this, new Observer() { // from class: b.a.a.a.t.m.a
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                ComicsDayInfoActivity.m5975bindEvent$lambda3$lambda2(ComicsDayInfoActivity.this, (List) obj);
            }
        });
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_dayinfo_comics;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return "每日";
    }

    @NotNull
    public final ComicsViewModel getViewModel() {
        return (ComicsViewModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
    }

    @NotNull
    public final ComicsViewModel viewModelInstance() {
        return getViewModel();
    }
}
