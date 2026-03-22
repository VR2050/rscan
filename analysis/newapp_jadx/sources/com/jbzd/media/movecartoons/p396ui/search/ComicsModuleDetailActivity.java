package com.jbzd.media.movecartoons.p396ui.search;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.widget.LinearLayout;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonComicsListFragment;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonNovelListFragment;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;
import p005b.p131d.p132a.p133a.C1499a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000<\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u000f\u0018\u0000 '2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001'B\u0007¢\u0006\u0004\b&\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0017¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u0019\u0010\u000e\u001a\u00020\u00032\b\u0010\r\u001a\u0004\u0018\u00010\fH\u0014¢\u0006\u0004\b\u000e\u0010\u000fR\u001f\u0010\u0013\u001a\u0004\u0018\u00010\u00068B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\bR\u001f\u0010\u0016\u001a\u0004\u0018\u00010\u00068B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\u0011\u001a\u0004\b\u0015\u0010\bR2\u0010\u001a\u001a\u0012\u0012\u0004\u0012\u00020\u00180\u0017j\b\u0012\u0004\u0012\u00020\u0018`\u00198\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001a\u0010\u001b\u001a\u0004\b\u001c\u0010\u001d\"\u0004\b\u001e\u0010\u001fR\u001f\u0010\"\u001a\u0004\u0018\u00010\u00068B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b \u0010\u0011\u001a\u0004\b!\u0010\bR2\u0010#\u001a\u0012\u0012\u0004\u0012\u00020\u00060\u0017j\b\u0012\u0004\u0012\u00020\u0006`\u00198\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b#\u0010\u001b\u001a\u0004\b$\u0010\u001d\"\u0004\b%\u0010\u001f¨\u0006("}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/ComicsModuleDetailActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "", "", "bindEvent", "()V", "", "getTopBarTitle", "()Ljava/lang/String;", "", "getLayoutId", "()I", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "show_type$delegate", "Lkotlin/Lazy;", "getShow_type", "show_type", "name$delegate", "getName", "name", "Ljava/util/ArrayList;", "Landroidx/fragment/app/Fragment;", "Lkotlin/collections/ArrayList;", "fragmentList", "Ljava/util/ArrayList;", "getFragmentList", "()Ljava/util/ArrayList;", "setFragmentList", "(Ljava/util/ArrayList;)V", "filter$delegate", "getFilter", "filter", "titleList", "getTitleList", "setTitleList", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ComicsModuleDetailActivity extends MyThemeActivity<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String order = "";

    /* renamed from: show_type$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy show_type = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.ComicsModuleDetailActivity$show_type$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ComicsModuleDetailActivity.this.getIntent().getStringExtra("show_type");
        }
    });

    /* renamed from: filter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy filter = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.ComicsModuleDetailActivity$filter$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ComicsModuleDetailActivity.this.getIntent().getStringExtra("filter");
        }
    });

    /* renamed from: name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy name = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.ComicsModuleDetailActivity$name$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ComicsModuleDetailActivity.this.getIntent().getStringExtra("name");
        }
    });

    @NotNull
    private ArrayList<String> titleList = new ArrayList<>();

    @NotNull
    private ArrayList<Fragment> fragmentList = new ArrayList<>();

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0011\u0010\u0012J-\u0010\t\u001a\u00020\b2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0006\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0004¢\u0006\u0004\b\t\u0010\nR\"\u0010\u000b\u001a\u00020\u00048\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u000b\u0010\f\u001a\u0004\b\r\u0010\u000e\"\u0004\b\u000f\u0010\u0010¨\u0006\u0013"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/ComicsModuleDetailActivity$Companion;", "", "Landroid/content/Context;", "context", "", "name", "filter", "show_type", "", "start", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V", "order", "Ljava/lang/String;", "getOrder", "()Ljava/lang/String;", "setOrder", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final String getOrder() {
            return ComicsModuleDetailActivity.order;
        }

        public final void setOrder(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            ComicsModuleDetailActivity.order = str;
        }

        public final void start(@NotNull Context context, @NotNull String name, @NotNull String filter, @NotNull String show_type) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(name, "name");
            Intrinsics.checkNotNullParameter(filter, "filter");
            Intrinsics.checkNotNullParameter(show_type, "show_type");
            Intent intent = new Intent(context, (Class<?>) ComicsModuleDetailActivity.class);
            intent.putExtra("name", name);
            intent.putExtra("filter", filter);
            intent.putExtra("show_type", show_type);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
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
        FragmentManager supportFragmentManager = getSupportFragmentManager();
        Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
        ViewPagerAdapter viewPagerAdapter = new ViewPagerAdapter(supportFragmentManager, this.fragmentList, 0, 4, null);
        HashMap<String, String> m595Q = C1499a.m595Q("ad_code", "comic_list_ad");
        String filter = getFilter();
        HashMap hashMap = new HashMap();
        if (!(filter == null || filter.length() == 0)) {
            try {
                JSONObject jSONObject = new JSONObject(filter);
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
        m595Q.putAll(hashMap);
        if (StringsKt__StringsJVMKt.equals$default(getShow_type(), "novel", false, 2, null)) {
            this.titleList.add("小说");
            this.fragmentList.add(CommonNovelListFragment.INSTANCE.newInstance(m595Q));
        } else {
            this.titleList.add("漫画");
            this.fragmentList.add(CommonComicsListFragment.INSTANCE.newInstance(m595Q));
        }
        int i2 = R$id.vp_content;
        ViewPager viewPager = (ViewPager) findViewById(i2);
        viewPager.setOffscreenPageLimit(getTitleList().size());
        viewPager.setAdapter(viewPagerAdapter);
        viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.search.ComicsModuleDetailActivity$bindEvent$1$1
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
        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) findViewById(R$id.sorting_tab_layout);
        ViewPager viewPager2 = (ViewPager) findViewById(i2);
        Object[] array = getTitleList().toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        slidingTabLayout.m4011e(viewPager2, (String[]) array);
        if (StringsKt__StringsJVMKt.equals$default(getShow_type(), "end", false, 2, null)) {
            ((LinearLayout) findViewById(R$id.ll_tablayout)).setVisibility(0);
        } else {
            ((LinearLayout) findViewById(R$id.ll_tablayout)).setVisibility(8);
        }
        if (!this.titleList.isEmpty()) {
            ((ViewPager) findViewById(i2)).setCurrentItem(0);
        }
    }

    @NotNull
    public final ArrayList<Fragment> getFragmentList() {
        return this.fragmentList;
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_module_detail_comics;
    }

    @NotNull
    public final ArrayList<String> getTitleList() {
        return this.titleList;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        String name = getName();
        return name == null ? "合集" : name;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
    }

    public final void setFragmentList(@NotNull ArrayList<Fragment> arrayList) {
        Intrinsics.checkNotNullParameter(arrayList, "<set-?>");
        this.fragmentList = arrayList;
    }

    public final void setTitleList(@NotNull ArrayList<String> arrayList) {
        Intrinsics.checkNotNullParameter(arrayList, "<set-?>");
        this.titleList = arrayList;
    }
}
