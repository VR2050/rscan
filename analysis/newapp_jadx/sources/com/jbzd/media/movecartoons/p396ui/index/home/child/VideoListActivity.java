package com.jbzd.media.movecartoons.p396ui.index.home.child;

import android.content.Context;
import android.content.Intent;
import android.text.TextUtils;
import android.widget.RadioGroup;
import androidx.fragment.app.FragmentManager;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.bean.response.BloggerOrderBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoListActivity;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoLongFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.child.VideoShortFragment;
import com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment;
import com.jbzd.media.movecartoons.view.text.MyRadioButton;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0834a;
import p005b.p006a.p007a.p008a.p009a.C0835a0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000r\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0010\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u000b\n\u0002\b\u0007\u0018\u0000 M2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001MB\u0007¢\u0006\u0004\bL\u0010\u000bJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u0017\u0010\b\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\b\u0010\u0007J\u000f\u0010\n\u001a\u00020\tH\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\f\u001a\u00020\tH\u0016¢\u0006\u0004\b\f\u0010\u000bJ\u000f\u0010\u000e\u001a\u00020\rH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0010\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0010\u0010\u0011R\u001d\u0010\u0017\u001a\u00020\u00128F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0013\u0010\u0014\u001a\u0004\b\u0015\u0010\u0016R\u001d\u0010\u001c\u001a\u00020\u00188B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u0014\u001a\u0004\b\u001a\u0010\u001bR-\u0010\"\u001a\u0012\u0012\u0004\u0012\u00020\u00050\u001dj\b\u0012\u0004\u0012\u00020\u0005`\u001e8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010\u0014\u001a\u0004\b \u0010!R\u001d\u0010'\u001a\u00020#8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u0014\u001a\u0004\b%\u0010&R\u001d\u0010,\u001a\u00020(8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b)\u0010\u0014\u001a\u0004\b*\u0010+R\u001f\u0010/\u001a\u0004\u0018\u00010\r8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b-\u0010\u0014\u001a\u0004\b.\u0010\u000fR\u001d\u00102\u001a\u00020\u00128F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b0\u0010\u0014\u001a\u0004\b1\u0010\u0016R\u001d\u00105\u001a\u00020\u00128F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b3\u0010\u0014\u001a\u0004\b4\u0010\u0016R\u001d\u00108\u001a\u00020\r8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b6\u0010\u0014\u001a\u0004\b7\u0010\u000fR\u001d\u0010=\u001a\u0002098F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b:\u0010\u0014\u001a\u0004\b;\u0010<R\u001f\u0010@\u001a\u0004\u0018\u00010\r8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b>\u0010\u0014\u001a\u0004\b?\u0010\u000fR9\u0010F\u001a\u001e\u0012\u0004\u0012\u00020\r\u0012\u0004\u0012\u00020\r0Aj\u000e\u0012\u0004\u0012\u00020\r\u0012\u0004\u0012\u00020\r`B8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bC\u0010\u0014\u001a\u0004\bD\u0010ER\u001d\u0010K\u001a\u00020G8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\bH\u0010\u0014\u001a\u0004\bI\u0010J¨\u0006N"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/child/VideoListActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "", "", "orderPosition", "Lcom/jbzd/media/movecartoons/ui/search/child/BaseCommonVideoListFragment;", "getLongVideoFragment", "(I)Lcom/jbzd/media/movecartoons/ui/search/child/BaseCommonVideoListFragment;", "getShortVideoFragment", "", "initCanvasTab", "()V", "bindEvent", "", "getTopBarTitle", "()Ljava/lang/String;", "getLayoutId", "()I", "Lcom/jbzd/media/movecartoons/view/text/MyRadioButton;", "rad_canvas_long$delegate", "Lkotlin/Lazy;", "getRad_canvas_long", "()Lcom/jbzd/media/movecartoons/view/text/MyRadioButton;", "rad_canvas_long", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "vpAdapter$delegate", "getVpAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "vpAdapter", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "sortingFragments$delegate", "getSortingFragments", "()Ljava/util/ArrayList;", "sortingFragments", "Lcom/flyco/tablayout/SlidingTabLayout;", "sorting_tab_layout$delegate", "getSorting_tab_layout", "()Lcom/flyco/tablayout/SlidingTabLayout;", "sorting_tab_layout", "Landroidx/viewpager/widget/ViewPager;", "vp_content$delegate", "getVp_content", "()Landroidx/viewpager/widget/ViewPager;", "vp_content", "mDefaultModuleOrderBy$delegate", "getMDefaultModuleOrderBy", "mDefaultModuleOrderBy", "rad_canvas_group$delegate", "getRad_canvas_group", "rad_canvas_group", "rad_canvas_short$delegate", "getRad_canvas_short", "rad_canvas_short", "defaultCanvas$delegate", "getDefaultCanvas", "defaultCanvas", "Landroid/widget/RadioGroup;", "rg_canvas$delegate", "getRg_canvas", "()Landroid/widget/RadioGroup;", "rg_canvas", "mDeTitle$delegate", "getMDeTitle", "mDeTitle", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "mParams$delegate", "getMParams", "()Ljava/util/HashMap;", "mParams", "", "mIsFollow$delegate", "getMIsFollow", "()Z", "mIsFollow", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class VideoListActivity extends MyThemeActivity<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    public static final String KEY_IS_FOLLOW = "is_follow";

    @NotNull
    public static final String KEY_ORDER_BY = "order_by";

    @NotNull
    public static final String KEY_PARAMS = "params";

    @NotNull
    public static final String KEY_TITLE = "title";

    @NotNull
    public static final String SHORT_VIDEO_TYPE = "3";

    /* renamed from: defaultCanvas$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy defaultCanvas = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$defaultCanvas$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            HashMap mParams;
            HashMap mParams2;
            HashMap mParams3;
            mParams = VideoListActivity.this.getMParams();
            CharSequence charSequence = (CharSequence) mParams.get("canvas");
            if (charSequence == null || StringsKt__StringsJVMKt.isBlank(charSequence)) {
                mParams2 = VideoListActivity.this.getMParams();
                if (!Intrinsics.areEqual((String) mParams2.get("type"), "3")) {
                    return "long";
                }
            } else {
                mParams3 = VideoListActivity.this.getMParams();
                if (!Intrinsics.areEqual((String) mParams3.get("canvas"), "short")) {
                    return "long";
                }
            }
            return "short";
        }
    });

    /* renamed from: mDefaultModuleOrderBy$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDefaultModuleOrderBy = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$mDefaultModuleOrderBy$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return VideoListActivity.this.getIntent().getStringExtra("order_by");
        }
    });

    /* renamed from: mDeTitle$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mDeTitle = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$mDeTitle$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return VideoListActivity.this.getIntent().getStringExtra(VideoListActivity.KEY_TITLE);
        }
    });

    /* renamed from: mIsFollow$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mIsFollow = LazyKt__LazyJVMKt.lazy(new Function0<Boolean>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$mIsFollow$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        public /* bridge */ /* synthetic */ Boolean invoke() {
            return Boolean.valueOf(invoke2());
        }

        /* renamed from: invoke, reason: avoid collision after fix types in other method */
        public final boolean invoke2() {
            return VideoListActivity.this.getIntent().getBooleanExtra(VideoListActivity.KEY_IS_FOLLOW, false);
        }
    });

    /* renamed from: mParams$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mParams = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$mParams$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            HashMap<String, String> hashMap = (HashMap) VideoListActivity.this.getIntent().getSerializableExtra(VideoListActivity.KEY_PARAMS);
            return hashMap == null ? new HashMap<>() : hashMap;
        }
    });

    /* renamed from: vpAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vpAdapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$vpAdapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            ArrayList sortingFragments;
            FragmentManager supportFragmentManager = VideoListActivity.this.getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
            sortingFragments = VideoListActivity.this.getSortingFragments();
            return new ViewPagerAdapter(supportFragmentManager, sortingFragments, 0, 4, null);
        }
    });

    /* renamed from: sortingFragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy sortingFragments = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<BaseCommonVideoListFragment>>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$sortingFragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<BaseCommonVideoListFragment> invoke() {
            String defaultCanvas;
            BaseCommonVideoListFragment longVideoFragment;
            BaseCommonVideoListFragment longVideoFragment2;
            BaseCommonVideoListFragment longVideoFragment3;
            BaseCommonVideoListFragment longVideoFragment4;
            BaseCommonVideoListFragment shortVideoFragment;
            BaseCommonVideoListFragment shortVideoFragment2;
            BaseCommonVideoListFragment shortVideoFragment3;
            BaseCommonVideoListFragment shortVideoFragment4;
            defaultCanvas = VideoListActivity.this.getDefaultCanvas();
            if (Intrinsics.areEqual(defaultCanvas, "short")) {
                shortVideoFragment = VideoListActivity.this.getShortVideoFragment(0);
                shortVideoFragment2 = VideoListActivity.this.getShortVideoFragment(1);
                shortVideoFragment3 = VideoListActivity.this.getShortVideoFragment(2);
                shortVideoFragment4 = VideoListActivity.this.getShortVideoFragment(3);
                return CollectionsKt__CollectionsKt.arrayListOf(shortVideoFragment, shortVideoFragment2, shortVideoFragment3, shortVideoFragment4);
            }
            longVideoFragment = VideoListActivity.this.getLongVideoFragment(0);
            longVideoFragment2 = VideoListActivity.this.getLongVideoFragment(1);
            longVideoFragment3 = VideoListActivity.this.getLongVideoFragment(2);
            longVideoFragment4 = VideoListActivity.this.getLongVideoFragment(3);
            return CollectionsKt__CollectionsKt.arrayListOf(longVideoFragment, longVideoFragment2, longVideoFragment3, longVideoFragment4);
        }
    });

    /* renamed from: vp_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content = LazyKt__LazyJVMKt.lazy(new Function0<ViewPager>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$vp_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPager invoke() {
            ViewPager viewPager = (ViewPager) VideoListActivity.this.findViewById(R.id.vp_content);
            Intrinsics.checkNotNull(viewPager);
            return viewPager;
        }
    });

    /* renamed from: sorting_tab_layout$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy sorting_tab_layout = LazyKt__LazyJVMKt.lazy(new Function0<SlidingTabLayout>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$sorting_tab_layout$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final SlidingTabLayout invoke() {
            SlidingTabLayout slidingTabLayout = (SlidingTabLayout) VideoListActivity.this.findViewById(R.id.sorting_tab_layout);
            Intrinsics.checkNotNull(slidingTabLayout);
            return slidingTabLayout;
        }
    });

    /* renamed from: rad_canvas_group$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rad_canvas_group = LazyKt__LazyJVMKt.lazy(new Function0<MyRadioButton>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$rad_canvas_group$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MyRadioButton invoke() {
            MyRadioButton myRadioButton = (MyRadioButton) VideoListActivity.this.findViewById(R.id.rad_canvas_group);
            Intrinsics.checkNotNull(myRadioButton);
            return myRadioButton;
        }
    });

    /* renamed from: rad_canvas_short$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rad_canvas_short = LazyKt__LazyJVMKt.lazy(new Function0<MyRadioButton>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$rad_canvas_short$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MyRadioButton invoke() {
            MyRadioButton myRadioButton = (MyRadioButton) VideoListActivity.this.findViewById(R.id.rad_canvas_short);
            Intrinsics.checkNotNull(myRadioButton);
            return myRadioButton;
        }
    });

    /* renamed from: rg_canvas$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rg_canvas = LazyKt__LazyJVMKt.lazy(new Function0<RadioGroup>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$rg_canvas$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final RadioGroup invoke() {
            RadioGroup radioGroup = (RadioGroup) VideoListActivity.this.findViewById(R.id.rg_canvas);
            Intrinsics.checkNotNull(radioGroup);
            return radioGroup;
        }
    });

    /* renamed from: rad_canvas_long$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy rad_canvas_long = LazyKt__LazyJVMKt.lazy(new Function0<MyRadioButton>() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$rad_canvas_long$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MyRadioButton invoke() {
            MyRadioButton myRadioButton = (MyRadioButton) VideoListActivity.this.findViewById(R.id.rad_canvas_long);
            Intrinsics.checkNotNull(myRadioButton);
            return myRadioButton;
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u000b\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0014\u0010\u0015JU\u0010\f\u001a\u00020\u000b2\u0006\u0010\u0003\u001a\u00020\u00022\n\b\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u00042(\b\u0002\u0010\b\u001a\"\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u0004\u0018\u00010\u0006j\u0010\u0012\u0004\u0012\u00020\u0004\u0012\u0004\u0012\u00020\u0004\u0018\u0001`\u00072\b\b\u0002\u0010\n\u001a\u00020\t¢\u0006\u0004\b\f\u0010\rR\u0016\u0010\u000e\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u000e\u0010\u000fR\u0016\u0010\u0010\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0010\u0010\u000fR\u0016\u0010\u0011\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0011\u0010\u000fR\u0016\u0010\u0012\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0012\u0010\u000fR\u0016\u0010\u0013\u001a\u00020\u00048\u0006@\u0006X\u0086T¢\u0006\u0006\n\u0004\b\u0013\u0010\u000f¨\u0006\u0016"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/home/child/VideoListActivity$Companion;", "", "Landroid/content/Context;", "context", "", "name", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", VideoListActivity.KEY_PARAMS, "", "isFollow", "", "start", "(Landroid/content/Context;Ljava/lang/String;Ljava/util/HashMap;Z)V", "KEY_IS_FOLLOW", "Ljava/lang/String;", "KEY_ORDER_BY", "KEY_PARAMS", "KEY_TITLE", "SHORT_VIDEO_TYPE", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        /* JADX WARN: Multi-variable type inference failed */
        public static /* synthetic */ void start$default(Companion companion, Context context, String str, HashMap hashMap, boolean z, int i2, Object obj) {
            if ((i2 & 2) != 0) {
                str = null;
            }
            if ((i2 & 4) != 0) {
                hashMap = null;
            }
            if ((i2 & 8) != 0) {
                z = false;
            }
            companion.start(context, str, hashMap, z);
        }

        /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
        public final void start(@NotNull Context context, @Nullable String name, @Nullable HashMap<String, String> params, boolean isFollow) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intent intent = new Intent(context, (Class<?>) VideoListActivity.class);
            if (params != null) {
                String str = params.get("tag_id");
                if (!(str == null || str.length() == 0)) {
                    String str2 = params.get("tag_id");
                    if (str2 == null) {
                        str2 = "";
                    }
                    params.put("tags", str2);
                    params.remove("tag_id");
                }
            }
            intent.putExtra(VideoListActivity.KEY_TITLE, name);
            intent.putExtra(VideoListActivity.KEY_IS_FOLLOW, isFollow);
            intent.putExtra(VideoListActivity.KEY_PARAMS, params);
            String str3 = params == null ? null : params.get("order_by");
            if (Intrinsics.areEqual(str3, "published_at")) {
                str3 = BloggerOrderBean.order_new;
            }
            if (!(str3 == null || StringsKt__StringsJVMKt.isBlank(str3))) {
                switch (str3.hashCode()) {
                    case -568218244:
                        if (str3.equals("choice_sort")) {
                            intent.putExtra("order_by", str3);
                            break;
                        }
                        intent.putExtra("order_by", "module_sort");
                        break;
                    case 108960:
                        if (str3.equals(BloggerOrderBean.order_new)) {
                            intent.putExtra("order_by", str3);
                            break;
                        }
                        intent.putExtra("order_by", "module_sort");
                        break;
                    case 3327858:
                        if (str3.equals("love")) {
                            intent.putExtra("order_by", str3);
                            break;
                        }
                        intent.putExtra("order_by", "module_sort");
                        break;
                    case 1625740950:
                        if (str3.equals("recommend_at")) {
                            intent.putExtra("order_by", str3);
                            break;
                        }
                        intent.putExtra("order_by", "module_sort");
                        break;
                    case 1879092219:
                        if (str3.equals("play_num")) {
                            intent.putExtra("order_by", str3);
                            break;
                        }
                        intent.putExtra("order_by", "module_sort");
                        break;
                    default:
                        intent.putExtra("order_by", "module_sort");
                        break;
                }
            }
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getDefaultCanvas() {
        return (String) this.defaultCanvas.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final BaseCommonVideoListFragment getLongVideoFragment(int orderPosition) {
        VideoLongFragment.Companion companion = VideoLongFragment.INSTANCE;
        HashMap<String, String> hashMap = new HashMap<>();
        String mDefaultModuleOrderBy = getMDefaultModuleOrderBy();
        String str = Intrinsics.areEqual(mDefaultModuleOrderBy, "choice_sort") ? "choice_sort" : Intrinsics.areEqual(mDefaultModuleOrderBy, "recommend_at") ? "recommend_at" : "module_sort";
        hashMap.putAll(getMParams());
        hashMap.put("canvas", "long");
        if (orderPosition != 0) {
            C0834a c0834a = C0834a.f214a;
            str = C0834a.m173a().get(orderPosition).f222a;
        }
        hashMap.put("order_by", str);
        Unit unit = Unit.INSTANCE;
        return companion.newInstance(hashMap);
    }

    private final String getMDeTitle() {
        return (String) this.mDeTitle.getValue();
    }

    private final String getMDefaultModuleOrderBy() {
        return (String) this.mDefaultModuleOrderBy.getValue();
    }

    private final boolean getMIsFollow() {
        return ((Boolean) this.mIsFollow.getValue()).booleanValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final HashMap<String, String> getMParams() {
        return (HashMap) this.mParams.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final BaseCommonVideoListFragment getShortVideoFragment(int orderPosition) {
        VideoShortFragment.Companion companion = VideoShortFragment.INSTANCE;
        HashMap<String, String> hashMap = new HashMap<>();
        String mDefaultModuleOrderBy = getMDefaultModuleOrderBy();
        String str = Intrinsics.areEqual(mDefaultModuleOrderBy, "choice_sort") ? "choice_sort" : Intrinsics.areEqual(mDefaultModuleOrderBy, "recommend_at") ? "recommend_at" : "module_sort";
        hashMap.putAll(getMParams());
        hashMap.put("canvas", "short");
        if (getMIsFollow()) {
            hashMap.put("type", "follow");
        }
        if (orderPosition != 0) {
            C0834a c0834a = C0834a.f214a;
            str = C0834a.m173a().get(orderPosition).f222a;
        }
        hashMap.put("order_by", str);
        Unit unit = Unit.INSTANCE;
        return companion.newInstance(hashMap);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<BaseCommonVideoListFragment> getSortingFragments() {
        return (ArrayList) this.sortingFragments.getValue();
    }

    private final ViewPagerAdapter getVpAdapter() {
        return (ViewPagerAdapter) this.vpAdapter.getValue();
    }

    private final void initCanvasTab() {
        getRad_canvas_group().setVisibility(8);
        if (Intrinsics.areEqual(getDefaultCanvas(), "short")) {
            getRad_canvas_short().setChecked(true);
        } else {
            getRad_canvas_long().setChecked(true);
        }
        getRg_canvas().setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() { // from class: b.a.a.a.t.g.k.j.a
            @Override // android.widget.RadioGroup.OnCheckedChangeListener
            public final void onCheckedChanged(RadioGroup radioGroup, int i2) {
                VideoListActivity.m5836initCanvasTab$lambda4(VideoListActivity.this, radioGroup, i2);
            }
        });
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: initCanvasTab$lambda-4, reason: not valid java name */
    public static final void m5836initCanvasTab$lambda4(VideoListActivity this$0, RadioGroup radioGroup, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        int i3 = 0;
        switch (i2) {
            case R.id.rad_canvas_long /* 2131363000 */:
                int size = this$0.getSortingFragments().size() - 1;
                if (size >= 0) {
                    while (true) {
                        int i4 = i3 + 1;
                        this$0.getSortingFragments().set(i3, this$0.getLongVideoFragment(i3));
                        if (i4 > size) {
                            break;
                        } else {
                            i3 = i4;
                        }
                    }
                }
                break;
            case R.id.rad_canvas_short /* 2131363001 */:
                int size2 = this$0.getSortingFragments().size() - 1;
                if (size2 >= 0) {
                    while (true) {
                        int i5 = i3 + 1;
                        this$0.getSortingFragments().set(i3, this$0.getShortVideoFragment(i3));
                        if (i5 > size2) {
                            break;
                        } else {
                            i3 = i5;
                        }
                    }
                }
                break;
        }
        this$0.getVpAdapter().notifyDataSetChanged();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        initCanvasTab();
        ViewPager vp_content = getVp_content();
        vp_content.setOffscreenPageLimit(getSortingFragments().size());
        vp_content.setAdapter(getVpAdapter());
        vp_content.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.index.home.child.VideoListActivity$bindEvent$1$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                VideoListActivity.this.getSorting_tab_layout().setCurrentTab(position);
            }
        });
        SlidingTabLayout sorting_tab_layout = getSorting_tab_layout();
        ViewPager vp_content2 = getVp_content();
        C0834a c0834a = C0834a.f214a;
        int i2 = 0;
        Object[] array = ((ArrayList) C0834a.f216c.getValue()).toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        sorting_tab_layout.m4011e(vp_content2, (String[]) array);
        if (getMDefaultModuleOrderBy() == null) {
            return;
        }
        SlidingTabLayout sorting_tab_layout2 = getSorting_tab_layout();
        String mDefaultModuleOrderBy = getMDefaultModuleOrderBy();
        Iterator<T> it = C0834a.m173a().iterator();
        int i3 = 0;
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            Object next = it.next();
            int i4 = i3 + 1;
            if (i3 < 0) {
                CollectionsKt__CollectionsKt.throwIndexOverflow();
            }
            if (TextUtils.equals(mDefaultModuleOrderBy, ((C0835a0) next).f222a)) {
                i2 = i3;
                break;
            }
            i3 = i4;
        }
        sorting_tab_layout2.setCurrentTab(i2);
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_long_video_list;
    }

    @NotNull
    public final MyRadioButton getRad_canvas_group() {
        return (MyRadioButton) this.rad_canvas_group.getValue();
    }

    @NotNull
    public final MyRadioButton getRad_canvas_long() {
        return (MyRadioButton) this.rad_canvas_long.getValue();
    }

    @NotNull
    public final MyRadioButton getRad_canvas_short() {
        return (MyRadioButton) this.rad_canvas_short.getValue();
    }

    @NotNull
    public final RadioGroup getRg_canvas() {
        return (RadioGroup) this.rg_canvas.getValue();
    }

    @NotNull
    public final SlidingTabLayout getSorting_tab_layout() {
        return (SlidingTabLayout) this.sorting_tab_layout.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        String mDeTitle = getMDeTitle();
        return mDeTitle == null ? "视频" : mDeTitle;
    }

    @NotNull
    public final ViewPager getVp_content() {
        return (ViewPager) this.vp_content.getValue();
    }
}
