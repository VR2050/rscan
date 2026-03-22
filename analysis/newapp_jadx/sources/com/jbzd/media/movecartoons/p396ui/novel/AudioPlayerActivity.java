package com.jbzd.media.movecartoons.p396ui.novel;

import android.content.Context;
import android.content.Intent;
import androidx.activity.ComponentActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.lifecycle.Observer;
import androidx.lifecycle.ViewModelLazy;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStore;
import androidx.viewpager.widget.ViewPager;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapter;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapterInfoBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelDetailInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeViewModelActivity;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.novel.AudioPlayerActivity;
import com.jbzd.media.movecartoons.p396ui.novel.PlayModeFragment;
import com.jbzd.media.movecartoons.service.AudioPlayerService;
import com.jbzd.media.movecartoons.view.page.MyViewPager;
import com.qnmd.adnnm.da0yzo.R;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Reflection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p143g.p144a.C1558h;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;
import p379c.p380a.C3079m0;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000P\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\t\n\u0002\u0010\u000e\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u000e\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u0018\u0000 02\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00010B\u0007¢\u0006\u0004\b/\u0010\tJ\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\r\u0010\b\u001a\u00020\u0005¢\u0006\u0004\b\b\u0010\tJ\u000f\u0010\n\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\n\u0010\tJ\u0015\u0010\r\u001a\u00020\u00052\u0006\u0010\f\u001a\u00020\u000b¢\u0006\u0004\b\r\u0010\u000eJ\u000f\u0010\u000f\u001a\u00020\u000bH\u0016¢\u0006\u0004\b\u000f\u0010\u0010J\u000f\u0010\u0011\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0011\u0010\tJ\u000f\u0010\u0012\u001a\u00020\u0005H\u0014¢\u0006\u0004\b\u0012\u0010\tJ\u000f\u0010\u0013\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0013\u0010\u0014R\"\u0010\u0016\u001a\u00020\u00158\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u0016\u0010\u0017\u001a\u0004\b\u0018\u0010\u0019\"\u0004\b\u001a\u0010\u001bR\u001d\u0010!\u001a\u00020\u001c8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u001e\u001a\u0004\b\u001f\u0010 R$\u0010#\u001a\u0004\u0018\u00010\"8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b#\u0010$\u001a\u0004\b%\u0010&\"\u0004\b'\u0010(R\"\u0010)\u001a\u00020\u00158\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b)\u0010\u0017\u001a\u0004\b*\u0010\u0019\"\u0004\b+\u0010\u001bR\u001d\u0010.\u001a\u00020\u00028V@\u0016X\u0096\u0084\u0002¢\u0006\f\n\u0004\b,\u0010\u001e\u001a\u0004\b-\u0010\u0014¨\u00067²\u0006\u000e\u00102\u001a\u0002018\n@\nX\u008a\u0084\u0002²\u0006\u001e\u00106\u001a\u0012\u0012\u0004\u0012\u00020403j\b\u0012\u0004\u0012\u000204`58\n@\nX\u008a\u0084\u0002"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/novel/AudioPlayerActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeViewModelActivity;", "Lcom/jbzd/media/movecartoons/ui/novel/AudioPlayerViewModel;", "", "check", "", "isBoundCheck", "(Z)V", "init", "()V", "bindEvent", "", "position", "setCurrentItem", "(I)V", "getLayoutId", "()I", "finish", "onDestroy", "viewModelInstance", "()Lcom/jbzd/media/movecartoons/ui/novel/AudioPlayerViewModel;", "", "pageAt", "Ljava/lang/String;", "getPageAt", "()Ljava/lang/String;", "setPageAt", "(Ljava/lang/String;)V", "Lcom/jbzd/media/movecartoons/view/page/MyViewPager;", "vp_content$delegate", "Lkotlin/Lazy;", "getVp_content", "()Lcom/jbzd/media/movecartoons/view/page/MyViewPager;", "vp_content", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "mNovelDetailInfoBean", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "getMNovelDetailInfoBean", "()Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "setMNovelDetailInfoBean", "(Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;)V", "chapterId", "getChapterId", "setChapterId", "viewModel$delegate", "getViewModel", "viewModel", "<init>", "Companion", "Lcom/jbzd/media/movecartoons/ui/novel/PlayModeFragment;", "playModeFragment", "Ljava/util/ArrayList;", "Landroidx/fragment/app/Fragment;", "Lkotlin/collections/ArrayList;", "fragmentList", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class AudioPlayerActivity extends MyThemeViewModelActivity<AudioPlayerViewModel> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @Nullable
    private NovelDetailInfoBean mNovelDetailInfoBean;

    @NotNull
    private String chapterId = "";

    @NotNull
    private String pageAt = "";

    /* renamed from: vp_content$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vp_content = LazyKt__LazyJVMKt.lazy(new Function0<MyViewPager>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerActivity$vp_content$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MyViewPager invoke() {
            MyViewPager myViewPager = (MyViewPager) AudioPlayerActivity.this.findViewById(R.id.vp_content);
            Intrinsics.checkNotNull(myViewPager);
            return myViewPager;
        }
    });

    /* renamed from: viewModel$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy viewModel = new ViewModelLazy(Reflection.getOrCreateKotlinClass(AudioPlayerViewModel.class), new Function0<ViewModelStore>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerActivity$special$$inlined$viewModels$default$2
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
    }, new Function0<ViewModelProvider.Factory>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerActivity$special$$inlined$viewModels$default$1
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

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u000b\u0010\fJ'\u0010\t\u001a\u00020\b2\u0006\u0010\u0003\u001a\u00020\u00022\b\b\u0002\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0006¢\u0006\u0004\b\t\u0010\n¨\u0006\r"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/novel/AudioPlayerActivity$Companion;", "", "Landroid/content/Context;", "context", "", "chapter_id", "Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;", "novelDetailInfoBean", "", "start", "(Landroid/content/Context;Ljava/lang/String;Lcom/jbzd/media/movecartoons/bean/response/novel/NovelDetailInfoBean;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ void start$default(Companion companion, Context context, String str, NovelDetailInfoBean novelDetailInfoBean, int i2, Object obj) {
            if ((i2 & 2) != 0) {
                str = "";
            }
            companion.start(context, str, novelDetailInfoBean);
        }

        public final void start(@NotNull Context context, @NotNull String chapter_id, @NotNull NovelDetailInfoBean novelDetailInfoBean) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(chapter_id, "chapter_id");
            Intrinsics.checkNotNullParameter(novelDetailInfoBean, "novelDetailInfoBean");
            Intent intent = new Intent(context, (Class<?>) AudioPlayerActivity.class);
            intent.putExtra("CHAPTER_ID", chapter_id);
            intent.putExtra("novelDetailInfoBean", novelDetailInfoBean);
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-1, reason: not valid java name */
    public static final PlayModeFragment m5903bindEvent$lambda1(Lazy<PlayModeFragment> lazy) {
        return lazy.getValue();
    }

    /* renamed from: bindEvent$lambda-2, reason: not valid java name */
    private static final ArrayList<Fragment> m5904bindEvent$lambda2(Lazy<? extends ArrayList<Fragment>> lazy) {
        return lazy.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindEvent$lambda-6$lambda-5, reason: not valid java name */
    public static final void m5905bindEvent$lambda6$lambda5(AudioPlayerActivity this$0, AudioPlayerViewModel this_apply, NovelChapterInfoBean novelChapterInfoBean) {
        String str;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        AudioPlayerService service = this_apply.getService();
        C2852c m2467d2 = C2354n.m2467d2(this$0);
        NovelChapter novelChapter = novelChapterInfoBean.chapter;
        if (novelChapter == null || (str = novelChapter.img) == null) {
            str = "";
        }
        C1558h mo770c = m2467d2.mo770c();
        C2851b c2851b = (C2851b) mo770c;
        c2851b.f1865I = str;
        c2851b.f1868L = true;
        ((C2851b) mo770c).m3292f0();
        Objects.requireNonNull(service);
        AudioPlayerService service2 = this_apply.getService();
        NovelChapter novelChapter2 = novelChapterInfoBean.chapter;
        String valueOf = String.valueOf(novelChapter2 == null ? null : novelChapter2.img);
        Objects.requireNonNull(service2);
        Intrinsics.checkNotNullParameter(valueOf, "<set-?>");
        C3079m0 c3079m0 = C3079m0.f8432c;
        C2354n.m2435U0(C2354n.m2456b(C3079m0.f8431b), null, 0, new AudioPlayerActivity$bindEvent$3$1$1$1(this$0, novelChapterInfoBean, this_apply, null), 3, null);
    }

    private final void isBoundCheck(boolean check) {
        getAudioService().m298a().isServiceBound = check;
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseThemeViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseViewModelActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(false);
        with.init();
        init();
        isBoundCheck(true);
        getAudioService().f572c = true;
        if (getIntent() != null) {
            if (getIntent().hasExtra("novelDetailInfoBean")) {
                Serializable serializableExtra = getIntent().getSerializableExtra("novelDetailInfoBean");
                Objects.requireNonNull(serializableExtra, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.novel.NovelDetailInfoBean");
                this.mNovelDetailInfoBean = (NovelDetailInfoBean) serializableExtra;
            }
        } else if (getAudioService().f572c && getAudioService().m298a().isServiceBound && getAudioService().m298a().m4203e() != null && getAudioService().m298a().m4203e() != null) {
            NovelDetailInfoBean value = getAudioService().m298a().m4203e().getValue();
            Intrinsics.checkNotNull(value);
            this.mNovelDetailInfoBean = value;
        }
        if (this.mNovelDetailInfoBean != null) {
            final Lazy lazy = LazyKt__LazyJVMKt.lazy(new Function0<PlayModeFragment>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerActivity$bindEvent$playModeFragment$2
                {
                    super(0);
                }

                /* JADX WARN: Can't rename method to resolve collision */
                @Override // kotlin.jvm.functions.Function0
                @NotNull
                public final PlayModeFragment invoke() {
                    PlayModeFragment.Companion companion = PlayModeFragment.INSTANCE;
                    NovelDetailInfoBean mNovelDetailInfoBean = AudioPlayerActivity.this.getMNovelDetailInfoBean();
                    Intrinsics.checkNotNull(mNovelDetailInfoBean);
                    return companion.newInstance(mNovelDetailInfoBean, AudioPlayerActivity.this.getChapterId());
                }
            });
            Lazy lazy2 = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<Fragment>>() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerActivity$bindEvent$fragmentList$2
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                @NotNull
                public final ArrayList<Fragment> invoke() {
                    PlayModeFragment m5903bindEvent$lambda1;
                    ArrayList<Fragment> arrayList = new ArrayList<>();
                    m5903bindEvent$lambda1 = AudioPlayerActivity.m5903bindEvent$lambda1(lazy);
                    arrayList.add(m5903bindEvent$lambda1);
                    return arrayList;
                }
            });
            FragmentManager supportFragmentManager = getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
            ViewPagerAdapter viewPagerAdapter = new ViewPagerAdapter(supportFragmentManager, m5904bindEvent$lambda2(lazy2), 0, 4, null);
            MyViewPager vp_content = getVp_content();
            vp_content.setScrollble(false);
            vp_content.setOffscreenPageLimit(m5904bindEvent$lambda2(lazy2).size());
            vp_content.setAdapter(viewPagerAdapter);
            vp_content.addOnPageChangeListener(new ViewPager.OnPageChangeListener() { // from class: com.jbzd.media.movecartoons.ui.novel.AudioPlayerActivity$bindEvent$2$1
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
        } else {
            finish();
        }
        final AudioPlayerViewModel viewModel = getViewModel();
        viewModel.getNovelDetailInfoBean().setValue(getMNovelDetailInfoBean());
        AudioPlayerViewModel.novelChapterDetail$default(viewModel, getChapterId(), false, 2, null);
        viewModel.getService().m4202d().observe(this, new Observer() { // from class: b.a.a.a.t.j.a
            @Override // androidx.lifecycle.Observer
            public final void onChanged(Object obj) {
                AudioPlayerActivity.m5905bindEvent$lambda6$lambda5(AudioPlayerActivity.this, viewModel, (NovelChapterInfoBean) obj);
            }
        });
    }

    @Override // android.app.Activity
    public void finish() {
        super.finish();
    }

    @NotNull
    public final String getChapterId() {
        return this.chapterId;
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_audio_page;
    }

    @Nullable
    public final NovelDetailInfoBean getMNovelDetailInfoBean() {
        return this.mNovelDetailInfoBean;
    }

    @NotNull
    public final String getPageAt() {
        return this.pageAt;
    }

    @NotNull
    public AudioPlayerViewModel getViewModel() {
        return (AudioPlayerViewModel) this.viewModel.getValue();
    }

    @NotNull
    public final MyViewPager getVp_content() {
        return (MyViewPager) this.vp_content.getValue();
    }

    public final void init() {
        overridePendingTransition(R.anim.slide_in_from_bottom, R.anim.slide_no_animation);
        String stringExtra = getIntent().getStringExtra("CHAPTER_ID");
        if (stringExtra == null) {
            stringExtra = "";
        }
        this.chapterId = stringExtra;
        String stringExtra2 = getIntent().getStringExtra("PAGE_AT");
        this.pageAt = stringExtra2 != null ? stringExtra2 : "";
    }

    @Override // androidx.appcompat.app.AppCompatActivity, androidx.fragment.app.FragmentActivity, android.app.Activity
    public void onDestroy() {
        super.onDestroy();
        if (getAudioService().m298a().isServiceBound) {
            isBoundCheck(false);
        }
    }

    public final void setChapterId(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.chapterId = str;
    }

    public final void setCurrentItem(int position) {
    }

    public final void setMNovelDetailInfoBean(@Nullable NovelDetailInfoBean novelDetailInfoBean) {
        this.mNovelDetailInfoBean = novelDetailInfoBean;
    }

    public final void setPageAt(@NotNull String str) {
        Intrinsics.checkNotNullParameter(str, "<set-?>");
        this.pageAt = str;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseViewModelActivity
    @NotNull
    public AudioPlayerViewModel viewModelInstance() {
        return getViewModel();
    }
}
