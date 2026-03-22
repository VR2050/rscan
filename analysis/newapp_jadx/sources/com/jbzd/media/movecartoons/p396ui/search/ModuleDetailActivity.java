package com.jbzd.media.movecartoons.p396ui.search;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.bean.response.HomeBlockBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListFragment;
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
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.json.JSONObject;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000L\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0012\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u0000 :2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001:B\u0007¢\u0006\u0004\b9\u0010\u0005J\u000f\u0010\u0004\u001a\u00020\u0003H\u0017¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u0019\u0010\u000e\u001a\u00020\u00032\b\u0010\r\u001a\u0004\u0018\u00010\fH\u0014¢\u0006\u0004\b\u000e\u0010\u000fR\u001f\u0010\u0013\u001a\u0004\u0018\u00010\u00068B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\bR\u001f\u0010\u0016\u001a\u0004\u0018\u00010\u00068B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0014\u0010\u0011\u001a\u0004\b\u0015\u0010\bR\u001d\u0010\u001b\u001a\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0018\u0010\u0011\u001a\u0004\b\u0019\u0010\u001aR\u001f\u0010\u001e\u001a\u0004\u0018\u00010\u00068B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001c\u0010\u0011\u001a\u0004\b\u001d\u0010\bR2\u0010\"\u001a\u0012\u0012\u0004\u0012\u00020 0\u001fj\b\u0012\u0004\u0012\u00020 `!8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\"\u0010#\u001a\u0004\b$\u0010%\"\u0004\b&\u0010'R\u001f\u0010*\u001a\u0004\u0018\u00010\u00068B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b(\u0010\u0011\u001a\u0004\b)\u0010\bR\u001f\u0010-\u001a\u0004\u0018\u00010\u00068B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b+\u0010\u0011\u001a\u0004\b,\u0010\bR2\u0010.\u001a\u0012\u0012\u0004\u0012\u00020\u00060\u001fj\b\u0012\u0004\u0012\u00020\u0006`!8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b.\u0010#\u001a\u0004\b/\u0010%\"\u0004\b0\u0010'R\u001f\u00103\u001a\u0004\u0018\u00010\u00068B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b1\u0010\u0011\u001a\u0004\b2\u0010\bR\u001d\u00108\u001a\u0002048F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b5\u0010\u0011\u001a\u0004\b6\u00107¨\u0006;"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/ModuleDetailActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "", "", "bindEvent", "()V", "", "getTopBarTitle", "()Ljava/lang/String;", "", "getLayoutId", "()I", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "mTagId$delegate", "Lkotlin/Lazy;", "getMTagId", "mTagId", "filter$delegate", "getFilter", "filter", "Lcom/flyco/tablayout/SlidingTabLayout;", "sorting_tab_layout$delegate", "getSorting_tab_layout", "()Lcom/flyco/tablayout/SlidingTabLayout;", "sorting_tab_layout", "name$delegate", "getName", "name", "Ljava/util/ArrayList;", "Landroidx/fragment/app/Fragment;", "Lkotlin/collections/ArrayList;", "fragmentList", "Ljava/util/ArrayList;", "getFragmentList", "()Ljava/util/ArrayList;", "setFragmentList", "(Ljava/util/ArrayList;)V", "type$delegate", "getType", "type", "mGroupId$delegate", "getMGroupId", "mGroupId", "titleList", "getTitleList", "setTitleList", "style$delegate", "getStyle", "style", "Landroidx/viewpager/widget/ViewPager;", "vp_content$delegate", "getVp_content", "()Landroidx/viewpager/widget/ViewPager;", "vp_content", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ModuleDetailActivity extends MyThemeActivity<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: type$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy type = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.ModuleDetailActivity$type$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ModuleDetailActivity.this.getIntent().getStringExtra("type");
        }
    });

    /* renamed from: filter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy filter = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.ModuleDetailActivity$filter$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ModuleDetailActivity.this.getIntent().getStringExtra("filter");
        }
    });

    /* renamed from: mTagId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTagId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.ModuleDetailActivity$mTagId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ModuleDetailActivity.this.getIntent().getStringExtra("tagId");
        }
    });

    /* renamed from: mGroupId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mGroupId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.ModuleDetailActivity$mGroupId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ModuleDetailActivity.this.getIntent().getStringExtra("id");
        }
    });

    /* renamed from: name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy name = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.ModuleDetailActivity$name$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ModuleDetailActivity.this.getIntent().getStringExtra("name");
        }
    });

    /* renamed from: style$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy style = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.ModuleDetailActivity$style$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return ModuleDetailActivity.this.getIntent().getStringExtra("style");
        }
    });

    @NotNull
    private ArrayList<String> titleList = new ArrayList<>();

    @NotNull
    private ArrayList<Fragment> fragmentList = new ArrayList<>();

    /* renamed from: vp_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.search.ModuleDetailActivity$vp_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            ViewPager viewPager = (ViewPager) ModuleDetailActivity.this.findViewById(R.id.vp_content);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: sorting_tab_layout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy sorting_tab_layout = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.search.ModuleDetailActivity$sorting_tab_layout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) ModuleDetailActivity.this.findViewById(R.id.sorting_tab_layout);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00006\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0010\u000b\n\u0002\b\u0006\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u001b\u0010\u001cJG\u0010\f\u001a\u00020\u000b2\u0006\u0010\u0003\u001a\u00020\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u00042\n\b\u0002\u0010\u0006\u001a\u0004\u0018\u00010\u00042\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u00042\u0006\u0010\t\u001a\u00020\b2\u0006\u0010\n\u001a\u00020\u0004¢\u0006\u0004\b\f\u0010\rJ\u001d\u0010\f\u001a\u00020\u000b2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u000f\u001a\u00020\u000e¢\u0006\u0004\b\f\u0010\u0010J;\u0010\f\u001a\u00020\u000b2\u0006\u0010\u0003\u001a\u00020\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u00042\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u00042\u0006\u0010\t\u001a\u00020\b2\u0006\u0010\n\u001a\u00020\u0004¢\u0006\u0004\b\f\u0010\u0011J+\u0010\f\u001a\u00020\u000b2\u0006\u0010\u0003\u001a\u00020\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u00042\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u0004¢\u0006\u0004\b\f\u0010\u0012J+\u0010\u0013\u001a\u00020\u000b2\u0006\u0010\u0003\u001a\u00020\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u00042\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u0004¢\u0006\u0004\b\u0013\u0010\u0012J\u001d\u0010\u0015\u001a\u00020\u000b2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0014\u001a\u00020\u0004¢\u0006\u0004\b\u0015\u0010\u0016J1\u0010\u0019\u001a\u00020\u000b2\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0014\u001a\u00020\u00042\n\b\u0002\u0010\u0007\u001a\u0004\u0018\u00010\u00042\u0006\u0010\u0018\u001a\u00020\u0017¢\u0006\u0004\b\u0019\u0010\u001a¨\u0006\u001d"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/ModuleDetailActivity$Companion;", "", "Landroid/content/Context;", "context", "", "id", "tagId", "name", "", "bgResource", "type", "", "start", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V", "Lcom/jbzd/media/movecartoons/bean/response/HomeBlockBean;", "outItem", "(Landroid/content/Context;Lcom/jbzd/media/movecartoons/bean/response/HomeBlockBean;)V", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V", "startTag", "filter", "startItem", "(Landroid/content/Context;Ljava/lang/String;)V", "", "isHot", "startHot", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Z)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ void startHot$default(Companion companion, Context context, String str, String str2, boolean z, int i2, Object obj) {
            if ((i2 & 4) != 0) {
                str2 = null;
            }
            companion.startHot(context, str, str2, z);
        }

        public static /* synthetic */ void startTag$default(Companion companion, Context context, String str, String str2, int i2, Object obj) {
            if ((i2 & 4) != 0) {
                str2 = null;
            }
            companion.startTag(context, str, str2);
        }

        public final void start(@NotNull Context context, @Nullable String id, @Nullable String tagId, @Nullable String name, int bgResource, @NotNull String type) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(type, "type");
            Intent intent = new Intent(context, (Class<?>) ModuleDetailActivity.class);
            if (id == null) {
                id = "";
            }
            intent.putExtra("id", id);
            if (tagId == null) {
                tagId = "";
            }
            intent.putExtra("tagId", tagId);
            intent.putExtra("name", name);
            intent.putExtra("bg", bgResource);
            intent.putExtra("type", type);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }

        public final void startHot(@NotNull Context context, @NotNull String filter, @Nullable String name, boolean isHot) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(filter, "filter");
            Intent intent = new Intent(context, (Class<?>) ModuleDetailActivity.class);
            intent.putExtra("filter", filter);
            intent.putExtra("name", name);
            intent.putExtra("isHot", isHot);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }

        public final void startItem(@NotNull Context context, @NotNull String filter) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(filter, "filter");
            Intent intent = new Intent(context, (Class<?>) ModuleDetailActivity.class);
            intent.putExtra("filter", filter);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }

        public final void startTag(@NotNull Context context, @Nullable String id, @Nullable String name) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intent intent = new Intent(context, (Class<?>) ModuleDetailActivity.class);
            if (id == null) {
                id = "";
            }
            intent.putExtra("tagId", id);
            intent.putExtra("name", name);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }

        public static /* synthetic */ void start$default(Companion companion, Context context, String str, String str2, int i2, String str3, int i3, Object obj) {
            if ((i3 & 4) != 0) {
                str2 = null;
            }
            companion.start(context, str, str2, i2, str3);
        }

        public static /* synthetic */ void start$default(Companion companion, Context context, String str, String str2, int i2, Object obj) {
            if ((i2 & 4) != 0) {
                str2 = null;
            }
            companion.start(context, str, str2);
        }

        public final void start(@NotNull Context context, @NotNull HomeBlockBean outItem) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(outItem, "outItem");
            Intent intent = new Intent(context, (Class<?>) ModuleDetailActivity.class);
            String str = outItem.filter;
            if (str == null) {
                str = "";
            }
            intent.putExtra("filter", str);
            String str2 = outItem.name;
            if (str2 == null) {
                str2 = "";
            }
            intent.putExtra("name", str2);
            String str3 = outItem.f9955id;
            intent.putExtra("id", str3 != null ? str3 : "");
            intent.putExtra("style", String.valueOf(outItem.style));
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }

        public final void start(@NotNull Context context, @Nullable String id, @Nullable String name, int bgResource, @NotNull String type) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(type, "type");
            Intent intent = new Intent(context, (Class<?>) ModuleDetailActivity.class);
            if (id == null) {
                id = "";
            }
            intent.putExtra("id", id);
            intent.putExtra("name", name);
            intent.putExtra("bg", bgResource);
            intent.putExtra("type", type);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }

        public final void start(@NotNull Context context, @Nullable String id, @Nullable String name) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intent intent = new Intent(context, (Class<?>) ModuleDetailActivity.class);
            if (id == null) {
                id = "";
            }
            intent.putExtra("id", id);
            intent.putExtra("name", name);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    private final String getFilter() {
        return (String) this.filter.getValue();
    }

    private final String getMGroupId() {
        return (String) this.mGroupId.getValue();
    }

    private final String getMTagId() {
        return (String) this.mTagId.getValue();
    }

    private final String getName() {
        return (String) this.name.getValue();
    }

    private final String getStyle() {
        return (String) this.style.getValue();
    }

    private final String getType() {
        return (String) this.type.getValue();
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
        HashMap<String, String> hashMap = new HashMap<>();
        String mTagId = getMTagId();
        if (!(mTagId == null || mTagId.length() == 0)) {
            String mTagId2 = getMTagId();
            if (mTagId2 == null) {
                mTagId2 = "";
            }
            hashMap.put("tag_id", mTagId2);
        }
        hashMap.put("ad_code", "video_mix_vertical");
        String style = getStyle();
        if (style != null) {
            hashMap.put("style", style);
        }
        String filter = getFilter();
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
        this.fragmentList.add(CommonLongListFragment.INSTANCE.newInstance(hashMap));
        this.titleList.add("长视频");
        ViewPager vp_content = getVp_content();
        vp_content.setOffscreenPageLimit(getTitleList().size());
        vp_content.setAdapter(viewPagerAdapter);
        vp_content.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.search.ModuleDetailActivity$bindEvent$1$1
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
        SlidingTabLayout sorting_tab_layout = getSorting_tab_layout();
        ViewPager vp_content2 = getVp_content();
        Object[] array = getTitleList().toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        sorting_tab_layout.m4011e(vp_content2, (String[]) array);
        if (!this.titleList.isEmpty()) {
            getVp_content().setCurrentItem(0);
        }
        if (Intrinsics.areEqual(getType(), "short")) {
            getVp_content().setCurrentItem(1);
        }
    }

    @NotNull
    public final ArrayList<Fragment> getFragmentList() {
        return this.fragmentList;
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_module_detail;
    }

    @NotNull
    public final SlidingTabLayout getSorting_tab_layout() {
        return (SlidingTabLayout) this.sorting_tab_layout.getValue();
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

    @NotNull
    public final ViewPager getVp_content() {
        return (ViewPager) this.vp_content.getValue();
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
