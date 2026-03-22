package com.jbzd.media.movecartoons.p396ui.mine.child;

import android.content.Context;
import android.content.Intent;
import androidx.fragment.app.FragmentManager;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.index.ViewPagerAdapter;
import com.jbzd.media.movecartoons.p396ui.mine.child.ChildLongFragment;
import com.jbzd.media.movecartoons.p396ui.mine.child.ChildShortFragment;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000@\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0010\u0018\u0000 %2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001%B\u0007¢\u0006\u0004\b$\u0010\bJ\u000f\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\t\u0010\u0005J\u000f\u0010\u000b\u001a\u00020\nH\u0016¢\u0006\u0004\b\u000b\u0010\fR\u001d\u0010\u0012\u001a\u00020\r8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u000e\u0010\u000f\u001a\u0004\b\u0010\u0010\u0011R9\u0010\u001a\u001a\u001e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00150\u00140\u0013j\u000e\u0012\n\u0012\b\u0012\u0004\u0012\u00020\u00150\u0014`\u00168B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u0017\u0010\u000f\u001a\u0004\b\u0018\u0010\u0019R\u001d\u0010\u001d\u001a\u00020\u00038B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001b\u0010\u000f\u001a\u0004\b\u001c\u0010\u0005R\u001f\u0010 \u001a\u0004\u0018\u00010\u00038B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u000f\u001a\u0004\b\u001f\u0010\u0005R-\u0010#\u001a\u0012\u0012\u0004\u0012\u00020\u00030\u0013j\b\u0012\u0004\u0012\u00020\u0003`\u00168B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u000f\u001a\u0004\b\"\u0010\u0019¨\u0006&"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/child/MineListMoreActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "", "", "getListTitle", "()Ljava/lang/String;", "", "bindEvent", "()V", "getTopBarTitle", "", "getLayoutId", "()I", "Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "vpAdapter$delegate", "Lkotlin/Lazy;", "getVpAdapter", "()Lcom/jbzd/media/movecartoons/ui/index/ViewPagerAdapter;", "vpAdapter", "Ljava/util/ArrayList;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "Lkotlin/collections/ArrayList;", "fragments$delegate", "getFragments", "()Ljava/util/ArrayList;", "fragments", "mType$delegate", "getMType", "mType", "mCanvas$delegate", "getMCanvas", "mCanvas", "tabEntities$delegate", "getTabEntities", "tabEntities", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MineListMoreActivity extends MyThemeActivity<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: mType$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mType = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.MineListMoreActivity$mType$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final String invoke() {
            String stringExtra = MineListMoreActivity.this.getIntent().getStringExtra("type");
            return stringExtra == null ? "" : stringExtra;
        }
    });

    /* renamed from: mCanvas$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mCanvas = LazyKt__LazyJVMKt.lazy(new Function0<String>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.MineListMoreActivity$mCanvas$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @Nullable
        public final String invoke() {
            return MineListMoreActivity.this.getIntent().getStringExtra("canvas");
        }
    });

    /* renamed from: vpAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy vpAdapter = LazyKt__LazyJVMKt.lazy(new Function0<ViewPagerAdapter>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.MineListMoreActivity$vpAdapter$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ViewPagerAdapter invoke() {
            ArrayList fragments;
            FragmentManager supportFragmentManager = MineListMoreActivity.this.getSupportFragmentManager();
            Intrinsics.checkNotNullExpressionValue(supportFragmentManager, "supportFragmentManager");
            fragments = MineListMoreActivity.this.getFragments();
            return new ViewPagerAdapter(supportFragmentManager, fragments, 0, 4, null);
        }
    });

    /* renamed from: tabEntities$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tabEntities = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<String>>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.MineListMoreActivity$tabEntities$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<String> invoke() {
            return CollectionsKt__CollectionsKt.arrayListOf("长视频", "短视频", "图集");
        }
    });

    /* renamed from: fragments$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy fragments = LazyKt__LazyJVMKt.lazy(new Function0<ArrayList<BaseListFragment<VideoItemBean>>>() { // from class: com.jbzd.media.movecartoons.ui.mine.child.MineListMoreActivity$fragments$2
        {
            super(0);
        }

        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayList<BaseListFragment<VideoItemBean>> invoke() {
            String mType;
            String mType2;
            String mType3;
            ChildLongFragment.Companion companion = ChildLongFragment.Companion;
            mType = MineListMoreActivity.this.getMType();
            ChildShortFragment.Companion companion2 = ChildShortFragment.Companion;
            mType2 = MineListMoreActivity.this.getMType();
            mType3 = MineListMoreActivity.this.getMType();
            return CollectionsKt__CollectionsKt.arrayListOf(companion.newInstance(mType), companion2.newInstance(mType2, "short"), companion2.newInstance(mType3, "image"));
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\n\u0010\u000bJ+\u0010\b\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u00022\b\u0010\u0005\u001a\u0004\u0018\u00010\u00042\n\b\u0002\u0010\u0006\u001a\u0004\u0018\u00010\u0004¢\u0006\u0004\b\b\u0010\t¨\u0006\f"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/child/MineListMoreActivity$Companion;", "", "Landroid/content/Context;", "context", "", "type", "canvas", "", "start", "(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ void start$default(Companion companion, Context context, String str, String str2, int i2, Object obj) {
            if ((i2 & 4) != 0) {
                str2 = null;
            }
            companion.start(context, str, str2);
        }

        public final void start(@NotNull Context context, @Nullable String type, @Nullable String canvas) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intent intent = new Intent(context, (Class<?>) MineListMoreActivity.class);
            intent.putExtra("type", type);
            intent.putExtra("canvas", canvas);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ArrayList<BaseListFragment<VideoItemBean>> getFragments() {
        return (ArrayList) this.fragments.getValue();
    }

    private final String getListTitle() {
        return "最近播放";
    }

    private final String getMCanvas() {
        return (String) this.mCanvas.getValue();
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String getMType() {
        return (String) this.mType.getValue();
    }

    private final ArrayList<String> getTabEntities() {
        return (ArrayList) this.tabEntities.getValue();
    }

    private final ViewPagerAdapter getVpAdapter() {
        return (ViewPagerAdapter) this.vpAdapter.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public void bindEvent() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_tab_pager;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        return getListTitle();
    }
}
