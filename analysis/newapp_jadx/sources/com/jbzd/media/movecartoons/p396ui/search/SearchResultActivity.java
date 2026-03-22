package com.jbzd.media.movecartoons.p396ui.search;

import android.content.Context;
import android.content.Intent;
import android.view.KeyEvent;
import android.widget.LinearLayout;
import android.widget.RadioGroup;
import android.widget.RelativeLayout;
import android.widget.TextView;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.event.EventUpdate;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.p396ui.dialog.VideoTypePopup;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.search.SearchResultActivity;
import com.jbzd.media.movecartoons.p396ui.search.SearchResultGroupFragment;
import com.jbzd.media.movecartoons.p396ui.search.SearchResultLongFragment;
import com.jbzd.media.movecartoons.p396ui.search.SearchResultShortFragment;
import com.jbzd.media.movecartoons.view.tab.TabEntity;
import com.jbzd.media.movecartoons.view.text.MyRadioButton;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.widget.ClearEditText;
import com.yalantis.ucrop.view.CropImageView;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0834a;
import p005b.p006a.p007a.p008a.p009a.C0841d0;
import p005b.p006a.p007a.p008a.p009a.CountDownTimerC0861n0;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p337d.C2861e;
import p476m.p496b.p497a.C4909c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000R\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u0000 52\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u00015B\u0007¢\u0006\u0004\b4\u0010\fJ\u001f\u0010\u0006\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u001f\u0010\b\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\b\u0010\u0007J\u001f\u0010\t\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\t\u0010\u0007J\u000f\u0010\u000b\u001a\u00020\nH\u0002¢\u0006\u0004\b\u000b\u0010\fJ\u0019\u0010\u000f\u001a\u00020\n2\b\u0010\u000e\u001a\u0004\u0018\u00010\rH\u0002¢\u0006\u0004\b\u000f\u0010\u0010J\u0019\u0010\u0012\u001a\u00020\n2\b\u0010\u0011\u001a\u0004\u0018\u00010\rH\u0002¢\u0006\u0004\b\u0012\u0010\u0010J\u0017\u0010\u0014\u001a\u00020\n2\u0006\u0010\u0013\u001a\u00020\rH\u0002¢\u0006\u0004\b\u0014\u0010\u0010J\u000f\u0010\u0015\u001a\u00020\nH\u0016¢\u0006\u0004\b\u0015\u0010\fJ\u000f\u0010\u0016\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0016\u0010\u0017R\u001d\u0010\u001d\u001a\u00020\u00188B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR-\u0010$\u001a\u0012\u0012\u0004\u0012\u00020\u001f0\u001ej\b\u0012\u0004\u0012\u00020\u001f` 8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u001a\u001a\u0004\b\"\u0010#R=\u0010'\u001a\"\u0012\f\u0012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u00050\u001ej\u0010\u0012\f\u0012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0005` 8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u001a\u001a\u0004\b&\u0010#R\u0018\u0010)\u001a\u0004\u0018\u00010(8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b)\u0010*R\u0016\u0010+\u001a\u00020\r8\u0002@\u0002X\u0082.¢\u0006\u0006\n\u0004\b+\u0010,R\u001f\u00100\u001a\u0004\u0018\u00010\r8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u001a\u001a\u0004\b.\u0010/R\u0016\u00102\u001a\u0002018\u0002@\u0002X\u0082.¢\u0006\u0006\n\u0004\b2\u00103¨\u00066"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/SearchResultActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "", "", "orderPosition", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "getLongVideoFragment", "(I)Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "getShortVideoFragment", "getGroupVideoFragment", "", "initCanvasTab", "()V", "", "content", "setEditText", "(Ljava/lang/String;)V", "videoType", "updateVideoType", "keyword", "searchData", "bindEvent", "getLayoutId", "()I", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "vpAdapter$delegate", "Lkotlin/Lazy;", "getVpAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "vpAdapter", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/view/tab/TabEntity;", "Lkotlin/collections/ArrayList;", "canvasTabEntities$delegate", "getCanvasTabEntities", "()Ljava/util/ArrayList;", "canvasTabEntities", "sortingFragments$delegate", "getSortingFragments", "sortingFragments", "Lcom/jbzd/media/movecartoons/ui/dialog/VideoTypePopup;", "popup", "Lcom/jbzd/media/movecartoons/ui/dialog/VideoTypePopup;", "mKeywords", "Ljava/lang/String;", "defaultCanvas$delegate", "getDefaultCanvas", "()Ljava/lang/String;", "defaultCanvas", "Lcom/jbzd/media/movecartoons/bean/response/VideoTypeBean;", "curVideoType", "Lcom/jbzd/media/movecartoons/bean/response/VideoTypeBean;", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class SearchResultActivity extends MyThemeActivity<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String KEY_CANVAS = "canvas";

    @NotNull
    public static final String KEY_WORDS = "words";
    private VideoTypeBean curVideoType;
    private String mKeywords;

    @Nullable
    private VideoTypePopup popup;

    /* renamed from: defaultCanvas$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy defaultCanvas = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultActivity$defaultCanvas$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return SearchResultActivity.this.getIntent().getStringExtra("canvas");
        }
    });

    /* renamed from: vpAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vpAdapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultActivity$vpAdapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            ArrayList sortingFragments;
            FragmentManager supportFragmentManager = SearchResultActivity.this.getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
            sortingFragments = SearchResultActivity.this.getSortingFragments();
            return new ViewPagerAdapter(supportFragmentManager, sortingFragments, 0, 4, null);
        }
    });

    /* renamed from: canvasTabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy canvasTabEntities = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<TabEntity>>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultActivity$canvasTabEntities$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<TabEntity> invoke() {
            return CollectionsKt__CollectionsKt.arrayListOf(new TabEntity(SearchResultActivity.this.getString(R.string.canvas_long_video), 0, 0), new TabEntity(SearchResultActivity.this.getString(R.string.canvas_short_video), 0, 0), new TabEntity(SearchResultActivity.this.getString(R.string.canvas_group), 0, 0));
        }
    });

    /* renamed from: sortingFragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy sortingFragments = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<MyThemeFragment<Object>>>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultActivity$sortingFragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<MyThemeFragment<Object>> invoke() {
            String defaultCanvas;
            MyThemeFragment longVideoFragment;
            MyThemeFragment longVideoFragment2;
            MyThemeFragment longVideoFragment3;
            MyThemeFragment longVideoFragment4;
            MyThemeFragment groupVideoFragment;
            MyThemeFragment groupVideoFragment2;
            MyThemeFragment groupVideoFragment3;
            MyThemeFragment groupVideoFragment4;
            MyThemeFragment shortVideoFragment;
            MyThemeFragment shortVideoFragment2;
            MyThemeFragment shortVideoFragment3;
            MyThemeFragment shortVideoFragment4;
            defaultCanvas = SearchResultActivity.this.getDefaultCanvas();
            if (Intrinsics.areEqual(defaultCanvas, "short")) {
                shortVideoFragment = SearchResultActivity.this.getShortVideoFragment(0);
                shortVideoFragment2 = SearchResultActivity.this.getShortVideoFragment(1);
                shortVideoFragment3 = SearchResultActivity.this.getShortVideoFragment(2);
                shortVideoFragment4 = SearchResultActivity.this.getShortVideoFragment(3);
                return CollectionsKt__CollectionsKt.arrayListOf(shortVideoFragment, shortVideoFragment2, shortVideoFragment3, shortVideoFragment4);
            }
            if (Intrinsics.areEqual(defaultCanvas, "group")) {
                groupVideoFragment = SearchResultActivity.this.getGroupVideoFragment(0);
                groupVideoFragment2 = SearchResultActivity.this.getGroupVideoFragment(1);
                groupVideoFragment3 = SearchResultActivity.this.getGroupVideoFragment(2);
                groupVideoFragment4 = SearchResultActivity.this.getGroupVideoFragment(3);
                return CollectionsKt__CollectionsKt.arrayListOf(groupVideoFragment, groupVideoFragment2, groupVideoFragment3, groupVideoFragment4);
            }
            longVideoFragment = SearchResultActivity.this.getLongVideoFragment(0);
            longVideoFragment2 = SearchResultActivity.this.getLongVideoFragment(1);
            longVideoFragment3 = SearchResultActivity.this.getLongVideoFragment(2);
            longVideoFragment4 = SearchResultActivity.this.getLongVideoFragment(3);
            return CollectionsKt__CollectionsKt.arrayListOf(longVideoFragment, longVideoFragment2, longVideoFragment3, longVideoFragment4);
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\r\u0010\u000eJ)\u0010\b\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u00042\b\b\u0002\u0010\u0006\u001a\u00020\u0004¢\u0006\u0004\b\b\u0010\tR\u0016\u0010\n\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\n\u0010\u000bR\u0016\u0010\f\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\f\u0010\u000b¨\u0006\u000f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/SearchResultActivity$Companion;", "", "Landroid/content/Context;", "context", "", SearchResultActivity.KEY_WORDS, "canvas", "", "start", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V", "KEY_CANVAS", "Ljava/lang/String;", "KEY_WORDS", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ void start$default(Companion companion, Context context, String str, String str2, int i2, Object obj) {
            if ((i2 & 4) != 0) {
                str2 = "long";
            }
            companion.start(context, str, str2);
        }

        public final void start(@NotNull Context context, @Nullable String words, @NotNull String canvas) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(canvas, "canvas");
            Intent intent = new Intent(context, (Class<?>) SearchResultActivity.class);
            intent.putExtra(SearchResultActivity.KEY_WORDS, words);
            intent.putExtra("canvas", canvas);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-2, reason: not valid java name */
    public static final boolean m5976bindEvent$lambda2(SearchResultActivity this$0, TextView textView, int i2, KeyEvent keyEvent) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (i2 != 3) {
            return false;
        }
        int i3 = R$id.cet_input;
        C2861e.m3306d((ClearEditText) this$0.findViewById(i3));
        String obj = StringsKt__StringsKt.trim((CharSequence) String.valueOf(((ClearEditText) this$0.findViewById(i3)).getText())).toString();
        C0841d0.m178a(obj);
        this$0.searchData(obj);
        return false;
    }

    private final ArrayList<TabEntity> getCanvasTabEntities() {
        return (ArrayList) this.canvasTabEntities.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getDefaultCanvas() {
        return (String) this.defaultCanvas.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MyThemeFragment<Object> getGroupVideoFragment(int orderPosition) {
        SearchResultGroupFragment.Companion companion = SearchResultGroupFragment.INSTANCE;
        C0834a c0834a = C0834a.f214a;
        String str = C0834a.m173a().get(orderPosition).f222a;
        VideoTypeBean videoTypeBean = this.curVideoType;
        if (videoTypeBean == null) {
            Intrinsics.throwUninitializedPropertyAccessException("curVideoType");
            throw null;
        }
        String str2 = videoTypeBean.key;
        Intrinsics.checkNotNullExpressionValue(str2, "curVideoType.key");
        String str3 = this.mKeywords;
        if (str3 != null) {
            return companion.newInstance(str, str2, str3);
        }
        Intrinsics.throwUninitializedPropertyAccessException("mKeywords");
        throw null;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MyThemeFragment<Object> getLongVideoFragment(int orderPosition) {
        SearchResultLongFragment.Companion companion = SearchResultLongFragment.INSTANCE;
        HashMap<String, String> hashMap = new HashMap<>();
        String str = this.mKeywords;
        if (str == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mKeywords");
            throw null;
        }
        hashMap.put("keywords", str);
        hashMap.put("canvas", "long");
        C0834a c0834a = C0834a.f214a;
        hashMap.put("order", C0834a.m173a().get(orderPosition).f222a);
        VideoTypeBean videoTypeBean = this.curVideoType;
        if (videoTypeBean == null) {
            Intrinsics.throwUninitializedPropertyAccessException("curVideoType");
            throw null;
        }
        hashMap.put("video_type", videoTypeBean.key);
        Unit unit = Unit.INSTANCE;
        return companion.newInstance(hashMap);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MyThemeFragment<Object> getShortVideoFragment(int orderPosition) {
        SearchResultShortFragment.Companion companion = SearchResultShortFragment.INSTANCE;
        HashMap<String, String> hashMap = new HashMap<>();
        String str = this.mKeywords;
        if (str == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mKeywords");
            throw null;
        }
        hashMap.put("keywords", str);
        hashMap.put("canvas", "short");
        C0834a c0834a = C0834a.f214a;
        hashMap.put("order", C0834a.m173a().get(orderPosition).f222a);
        VideoTypeBean videoTypeBean = this.curVideoType;
        if (videoTypeBean == null) {
            Intrinsics.throwUninitializedPropertyAccessException("curVideoType");
            throw null;
        }
        hashMap.put("video_type", videoTypeBean.key);
        Unit unit = Unit.INSTANCE;
        return companion.newInstance(hashMap);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<MyThemeFragment<Object>> getSortingFragments() {
        return (ArrayList) this.sortingFragments.getValue();
    }

    private final ViewPagerAdapter getVpAdapter() {
        return (ViewPagerAdapter) this.vpAdapter.getValue();
    }

    private final void initCanvasTab() {
        String defaultCanvas = getDefaultCanvas();
        if (Intrinsics.areEqual(defaultCanvas, "short")) {
            ((MyRadioButton) findViewById(R$id.rad_canvas_short)).setChecked(true);
        } else if (Intrinsics.areEqual(defaultCanvas, "group")) {
            ((MyRadioButton) findViewById(R$id.rad_canvas_group)).setChecked(true);
        } else {
            ((MyRadioButton) findViewById(R$id.rad_canvas_long)).setChecked(true);
        }
        ((RadioGroup) findViewById(R$id.rg_canvas)).setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() { // from class: b.a.a.a.t.m.c
            @Override // android.widget.RadioGroup.OnCheckedChangeListener
            public final void onCheckedChanged(RadioGroup radioGroup, int i2) {
                SearchResultActivity.m5977initCanvasTab$lambda4(SearchResultActivity.this, radioGroup, i2);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initCanvasTab$lambda-4, reason: not valid java name */
    public static final void m5977initCanvasTab$lambda4(SearchResultActivity this$0, RadioGroup radioGroup, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        int i3 = 0;
        switch (i2) {
            case R.id.rad_canvas_group /* 2131362999 */:
                int size = this$0.getSortingFragments().size() - 1;
                if (size >= 0) {
                    while (true) {
                        int i4 = i3 + 1;
                        this$0.getSortingFragments().set(i3, this$0.getGroupVideoFragment(i3));
                        if (i4 > size) {
                            break;
                        } else {
                            i3 = i4;
                        }
                    }
                }
                break;
            case R.id.rad_canvas_long /* 2131363000 */:
                int size2 = this$0.getSortingFragments().size() - 1;
                if (size2 >= 0) {
                    while (true) {
                        int i5 = i3 + 1;
                        this$0.getSortingFragments().set(i3, this$0.getLongVideoFragment(i3));
                        if (i5 > size2) {
                            break;
                        } else {
                            i3 = i5;
                        }
                    }
                }
                break;
            case R.id.rad_canvas_short /* 2131363001 */:
                int size3 = this$0.getSortingFragments().size() - 1;
                if (size3 >= 0) {
                    while (true) {
                        int i6 = i3 + 1;
                        this$0.getSortingFragments().set(i3, this$0.getShortVideoFragment(i3));
                        if (i6 > size3) {
                            break;
                        } else {
                            i3 = i6;
                        }
                    }
                }
                break;
        }
        this$0.getVpAdapter().notifyDataSetChanged();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void searchData(String keyword) {
        this.mKeywords = keyword;
        C4909c.m5569b().m5574g(new EventUpdate(null, null, keyword, 3, null));
    }

    private final void setEditText(String content) {
        ClearEditText clearEditText = (ClearEditText) findViewById(R$id.cet_input);
        if (content == null) {
            content = "";
        }
        clearEditText.setText(content);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void updateVideoType(String videoType) {
        C4909c.m5569b().m5574g(new EventUpdate(null, videoType, null, 5, null));
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        String stringExtra = getIntent().getStringExtra(KEY_WORDS);
        if (stringExtra == null) {
            stringExtra = "";
        }
        this.mKeywords = stringExtra;
        this.curVideoType = new VideoTypeBean("", getString(R.string.video_type_all));
        ((LinearLayout) findViewById(R$id.ll_top)).setPadding(0, ImmersionBar.getStatusBarHeight(this), 0, 0);
        C2354n.m2377B((RelativeLayout) findViewById(R$id.btn_titleBack), 0L, new Function1<RelativeLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultActivity$bindEvent$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(RelativeLayout relativeLayout) {
                invoke2(relativeLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(RelativeLayout view) {
                Intrinsics.checkNotNullExpressionValue(view, "it");
                int i2 = (2 & 2) != 0 ? 1000 : 0;
                Intrinsics.checkNotNullParameter(view, "view");
                if (i2 < 500) {
                    i2 = CropImageView.DEFAULT_IMAGE_TO_CROP_BOUNDS_ANIM_DURATION;
                }
                view.setEnabled(false);
                new CountDownTimerC0861n0(view, i2).start();
                SearchResultActivity.this.onBackPressed();
            }
        }, 1);
        C2354n.m2377B((TextView) findViewById(R$id.tv_doSearch), 0L, new Function1<TextView, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultActivity$bindEvent$2
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
                SearchResultActivity searchResultActivity = SearchResultActivity.this;
                int i2 = R$id.cet_input;
                C2861e.m3306d((ClearEditText) searchResultActivity.findViewById(i2));
                String obj = StringsKt__StringsKt.trim((CharSequence) String.valueOf(((ClearEditText) SearchResultActivity.this.findViewById(i2)).getText())).toString();
                C0841d0.m178a(obj);
                SearchResultActivity.this.searchData(obj);
            }
        }, 1);
        String str = this.mKeywords;
        if (str == null) {
            Intrinsics.throwUninitializedPropertyAccessException("mKeywords");
            throw null;
        }
        setEditText(str);
        ((ClearEditText) findViewById(R$id.cet_input)).setOnEditorActionListener(new TextView.OnEditorActionListener() { // from class: b.a.a.a.t.m.b
            @Override // android.widget.TextView.OnEditorActionListener
            public final boolean onEditorAction(TextView textView, int i2, KeyEvent keyEvent) {
                boolean m5976bindEvent$lambda2;
                m5976bindEvent$lambda2 = SearchResultActivity.m5976bindEvent$lambda2(SearchResultActivity.this, textView, i2, keyEvent);
                return m5976bindEvent$lambda2;
            }
        });
        int i2 = R$id.vp_content;
        ViewPager viewPager = (ViewPager) findViewById(i2);
        viewPager.setOffscreenPageLimit(getSortingFragments().size());
        viewPager.setAdapter(getVpAdapter());
        viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultActivity$bindEvent$4$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                ((SlidingTabLayout) SearchResultActivity.this.findViewById(R$id.sorting_tab_layout)).setCurrentTab(position);
            }
        });
        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) findViewById(R$id.sorting_tab_layout);
        ViewPager viewPager2 = (ViewPager) findViewById(i2);
        C0834a c0834a = C0834a.f214a;
        Object[] array = ((ArrayList) C0834a.f216c.getValue()).toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        slidingTabLayout.m4011e(viewPager2, (String[]) array);
        initCanvasTab();
        this.popup = new VideoTypePopup(this, new Function1<VideoTypeBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultActivity$bindEvent$5
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(VideoTypeBean videoTypeBean) {
                invoke2(videoTypeBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull VideoTypeBean it) {
                Intrinsics.checkNotNullParameter(it, "it");
                SearchResultActivity.this.curVideoType = it;
                TextView textView = (TextView) SearchResultActivity.this.findViewById(R$id.tv_type);
                if (textView != null) {
                    textView.setText(it.name);
                }
                SearchResultActivity.this.updateVideoType(it.key);
            }
        });
        C2354n.m2377B((LinearLayout) findViewById(R$id.ll_type), 0L, new Function1<LinearLayout, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.SearchResultActivity$bindEvent$6
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(LinearLayout linearLayout) {
                invoke2(linearLayout);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(LinearLayout linearLayout) {
                VideoTypePopup videoTypePopup;
                VideoTypePopup videoTypePopup2;
                VideoTypePopup videoTypePopup3;
                VideoTypeBean videoTypeBean;
                VideoTypePopup videoTypePopup4;
                videoTypePopup = SearchResultActivity.this.popup;
                if (Intrinsics.areEqual(videoTypePopup == null ? null : Boolean.valueOf(videoTypePopup.isShowing()), Boolean.TRUE)) {
                    videoTypePopup4 = SearchResultActivity.this.popup;
                    if (videoTypePopup4 == null) {
                        return;
                    }
                    videoTypePopup4.dismiss();
                    return;
                }
                videoTypePopup2 = SearchResultActivity.this.popup;
                if (videoTypePopup2 != null) {
                    videoTypeBean = SearchResultActivity.this.curVideoType;
                    if (videoTypeBean == null) {
                        Intrinsics.throwUninitializedPropertyAccessException("curVideoType");
                        throw null;
                    }
                    videoTypePopup2.updateCurType(videoTypeBean);
                }
                videoTypePopup3 = SearchResultActivity.this.popup;
                if (videoTypePopup3 == null) {
                    return;
                }
                videoTypePopup3.showAsDropDown((TextView) SearchResultActivity.this.findViewById(R$id.tv_type));
            }
        }, 1);
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_search_result;
    }
}
