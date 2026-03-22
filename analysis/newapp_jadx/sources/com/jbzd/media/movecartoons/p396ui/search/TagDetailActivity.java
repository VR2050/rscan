package com.jbzd.media.movecartoons.p396ui.search;

import android.widget.LinearLayout;
import android.widget.TextView;
import androidx.activity.ComponentActivity;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.viewpager.widget.ViewPager;
import com.flyco.tablayout.SlidingTabLayout;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.event.EventUpdate;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeFragment;
import com.jbzd.media.movecartoons.core.MyThemeViewModelActivity;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.search.TagDetailActivity;
import com.jbzd.media.movecartoons.p396ui.search.TagLongFragment;
import com.jbzd.media.movecartoons.p396ui.search.TagShortFragment;
import com.jbzd.media.movecartoons.view.image.CircleImageView;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.core.view.BaseActivity;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0834a;
import p005b.p143g.p144a.C1558h;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;
import p476m.p496b.p497a.C4909c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000H\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\n\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u0000 02\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00010B\u0007¢\u0006\u0004\b/\u0010\u0010J\u001f\u0010\u0007\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u001f\u0010\t\u001a\n\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\t\u0010\bJ\u0019\u0010\r\u001a\u00020\f2\b\u0010\u000b\u001a\u0004\u0018\u00010\nH\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\fH\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\nH\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0013\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0013\u0010\u0014J\u000f\u0010\u0015\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0015\u0010\u0016R=\u0010\u001d\u001a\"\u0012\f\u0012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u00050\u0017j\u0010\u0012\f\u0012\n\u0012\u0006\u0012\u0004\u0018\u00010\u00060\u0005`\u00188B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR\u001f\u0010 \u001a\u0004\u0018\u00010\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u001a\u001a\u0004\b\u001f\u0010\u0012R\u001f\u0010#\u001a\u0004\u0018\u00010\n8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u001a\u001a\u0004\b\"\u0010\u0012R\u001d\u0010(\u001a\u00020$8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b%\u0010\u001a\u001a\u0004\b&\u0010'R\u001d\u0010+\u001a\u00020\u00028F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b)\u0010\u001a\u001a\u0004\b*\u0010\u0016R\u0016\u0010-\u001a\u00020,8\u0002@\u0002X\u0082.¢\u0006\u0006\n\u0004\b-\u0010.¨\u00061"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/TagDetailActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelActivity;", "Lcom/jbzd/media/movecartoons/ui/search/TagInfoModel;", "", "orderPosition", "Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "", "getLongVideoFragment", "(I)Lcom/jbzd/media/movecartoons/core/MyThemeFragment;", "getShortVideoFragment", "", "videoType", "", "updateVideoType", "(Ljava/lang/String;)V", "bindEvent", "()V", "getTopBarTitle", "()Ljava/lang/String;", "getLayoutId", "()I", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/search/TagInfoModel;", "Ljava/util/ArrayList;", "Lkotlin/collections/ArrayList;", "sortingFragments$delegate", "Lkotlin/Lazy;", "getSortingFragments", "()Ljava/util/ArrayList;", "sortingFragments", "name$delegate", "getName", TagDetailActivity.KEY_NAME, "mTagId$delegate", "getMTagId", "mTagId", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "vpAdapter$delegate", "getVpAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "vpAdapter", "viewModel$delegate", "getViewModel", "viewModel", "Lcom/jbzd/media/movecartoons/bean/response/VideoTypeBean;", "curVideoType", "Lcom/jbzd/media/movecartoons/bean/response/VideoTypeBean;", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class TagDetailActivity extends MyThemeViewModelActivity<TagInfoModel> {

    @NotNull
    private static final String KEY_CANVAS = "canvas";

    @NotNull
    private static final String KEY_ID = "id";

    @NotNull
    private static final String KEY_NAME = "name";
    private VideoTypeBean curVideoType;

    /* renamed from: mTagId$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mTagId = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.TagDetailActivity$mTagId$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return TagDetailActivity.this.getIntent().getStringExtra("id");
        }
    });

    /* renamed from: name$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy name = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.search.TagDetailActivity$name$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return TagDetailActivity.this.getIntent().getStringExtra("name");
        }
    });

    /* renamed from: vpAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vpAdapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.search.TagDetailActivity$vpAdapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            ArrayList sortingFragments;
            FragmentManager supportFragmentManager = TagDetailActivity.this.getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
            sortingFragments = TagDetailActivity.this.getSortingFragments();
            return new ViewPagerAdapter(supportFragmentManager, sortingFragments, 0, 4, null);
        }
    });

    /* renamed from: sortingFragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy sortingFragments = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<MyThemeFragment<Object>>>() { // from class: com.jbzd.media.movecartoons.ui.search.TagDetailActivity$sortingFragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<MyThemeFragment<Object>> invoke() {
            MyThemeFragment longVideoFragment;
            MyThemeFragment shortVideoFragment;
            longVideoFragment = TagDetailActivity.this.getLongVideoFragment(0);
            shortVideoFragment = TagDetailActivity.this.getShortVideoFragment(0);
            return CollectionsKt__CollectionsKt.arrayListOf(longVideoFragment, shortVideoFragment);
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(TagInfoModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.search.TagDetailActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.search.TagDetailActivity$special$$inlined$viewModels$default$1
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

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-5$lambda-2, reason: not valid java name */
    public static final void m5980bindEvent$lambda5$lambda2(TagDetailActivity this$0, C2848a c2848a) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        if (c2848a.f7763a) {
            BaseActivity.showLoadingDialog$default(this$0, "", false, 2, null);
        } else {
            this$0.hideLoadingDialog();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-5$lambda-3, reason: not valid java name */
    public static final void m5981bindEvent$lambda5$lambda3(TagDetailActivity this$0, Integer it) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        LinearLayout linearLayout = (LinearLayout) this$0.findViewById(R$id.ll_bg);
        Intrinsics.checkNotNullExpressionValue(it, "it");
        linearLayout.setBackgroundResource(it.intValue());
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-5$lambda-4, reason: not valid java name */
    public static final void m5982bindEvent$lambda5$lambda4(TagDetailActivity this$0, TagInfoBean tagInfoBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        C2852c m2467d2 = C2354n.m2467d2(this$0);
        String str = tagInfoBean.img;
        if (str == null) {
            str = "";
        }
        C1558h mo770c = m2467d2.mo770c();
        mo770c.mo763X(str);
        ((C2851b) mo770c).m3292f0().m757R((CircleImageView) this$0.findViewById(R$id.civ_head));
        TextView textView = (TextView) this$0.findViewById(R$id.tv_postdetail_nickname);
        String str2 = tagInfoBean.name;
        if (str2 == null) {
            str2 = "";
        }
        textView.setText(str2);
        TextView textView2 = (TextView) this$0.findViewById(R$id.tv_desc);
        String str3 = tagInfoBean.desc;
        textView2.setText(str3 != null ? str3 : "");
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MyThemeFragment<Object> getLongVideoFragment(int orderPosition) {
        TagLongFragment.Companion companion = TagLongFragment.INSTANCE;
        HashMap<String, String> hashMap = new HashMap<>();
        String mTagId = getMTagId();
        if (mTagId == null) {
            mTagId = "";
        }
        hashMap.put("tag_id", mTagId);
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

    private final String getMTagId() {
        return (String) this.mTagId.getValue();
    }

    private final String getName() {
        return (String) this.name.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final MyThemeFragment<Object> getShortVideoFragment(int orderPosition) {
        TagShortFragment.Companion companion = TagShortFragment.INSTANCE;
        HashMap<String, String> hashMap = new HashMap<>();
        String mTagId = getMTagId();
        if (mTagId == null) {
            mTagId = "";
        }
        hashMap.put("tag_id", mTagId);
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

    private final void updateVideoType(String videoType) {
        C4909c.m5569b().m5574g(new EventUpdate(null, videoType, null, 5, null));
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        this.curVideoType = new VideoTypeBean("", getString(R.string.video_type_all));
        TagInfoModel viewModel = getViewModel();
        TagInfoModel.load$default(viewModel, getMTagId(), false, 2, null);
        viewModel.getLoading().observe(this, new Observer() { // from class: b.a.a.a.t.m.h
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                TagDetailActivity.m5980bindEvent$lambda5$lambda2(TagDetailActivity.this, (C2848a) obj);
            }
        });
        viewModel.getTagDetailBg().observe(this, new Observer() { // from class: b.a.a.a.t.m.f
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                TagDetailActivity.m5981bindEvent$lambda5$lambda3(TagDetailActivity.this, (Integer) obj);
            }
        });
        viewModel.getInfoBean().observe(this, new Observer() { // from class: b.a.a.a.t.m.g
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                TagDetailActivity.m5982bindEvent$lambda5$lambda4(TagDetailActivity.this, (TagInfoBean) obj);
            }
        });
        int i2 = R$id.vp_content;
        ViewPager viewPager = (ViewPager) findViewById(i2);
        viewPager.setOffscreenPageLimit(getSortingFragments().size());
        viewPager.setAdapter(getVpAdapter());
        viewPager.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.search.TagDetailActivity$bindEvent$2$1
            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrollStateChanged(int state) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            @Override // androidx.viewpager.widget.ViewPager.OnPageChangeListener
            public void onPageSelected(int position) {
                ((SlidingTabLayout) TagDetailActivity.this.findViewById(R$id.sorting_tab_layout)).setCurrentTab(position);
            }
        });
        SlidingTabLayout slidingTabLayout = (SlidingTabLayout) findViewById(R$id.sorting_tab_layout);
        ViewPager viewPager2 = (ViewPager) findViewById(i2);
        C0834a c0834a = C0834a.f214a;
        Object[] array = ((ArrayList) C0834a.f217d.getValue()).toArray(new String[0]);
        Objects.requireNonNull(array, "null cannot be cast to non-null type kotlin.Array<T of kotlin.collections.ArraysKt__ArraysJVMKt.toTypedArray>");
        slidingTabLayout.m4011e(viewPager2, (String[]) array);
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_tag_detail;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        String name = getName();
        return name == null ? "口味" : name;
    }

    @NotNull
    public final TagInfoModel getViewModel() {
        return (TagInfoModel) this.viewModel.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelActivity
    @NotNull
    public TagInfoModel viewModelInstance() {
        return getViewModel();
    }
}
