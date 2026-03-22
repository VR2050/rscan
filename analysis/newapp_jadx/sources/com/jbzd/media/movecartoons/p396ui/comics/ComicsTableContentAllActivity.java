package com.jbzd.media.movecartoons.p396ui.comics;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.gyf.immersionbar.ImmersionBar;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.Chapter;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsDetailInfoBean;
import com.jbzd.media.movecartoons.core.MyThemeActivity;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsTableContentAllActivity$tableContentAdapter$2;
import com.qnmd.adnnm.da0yzo.R;
import com.qunidayede.supportlibrary.utils.GridItemDecoration;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.comparisons.ComparisonsKt__ComparisonsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000Q\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0007*\u0001\u001c\u0018\u0000 (2\n\u0012\u0006\u0012\u0004\u0018\u00010\u00020\u0001:\u0001(B\u0007¢\u0006\u0004\b'\u0010\u000fJ<\u0010\f\u001a\u00020\n2\u0006\u0010\u0004\u001a\u00020\u00032#\b\u0002\u0010\u000b\u001a\u001d\u0012\u0013\u0012\u00110\u0006¢\u0006\f\b\u0007\u0012\b\b\b\u0012\u0004\b\b(\t\u0012\u0004\u0012\u00020\n0\u0005H\u0002¢\u0006\u0004\b\f\u0010\rJ\u000f\u0010\u000e\u001a\u00020\nH\u0017¢\u0006\u0004\b\u000e\u0010\u000fJ\u000f\u0010\u0011\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0014\u001a\u00020\u0013H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J\u000f\u0010\u0016\u001a\u00020\u0013H\u0016¢\u0006\u0004\b\u0016\u0010\u0015J\u000f\u0010\u0017\u001a\u00020\nH\u0016¢\u0006\u0004\b\u0017\u0010\u000fJ\u0019\u0010\u001a\u001a\u00020\n2\b\u0010\u0019\u001a\u0004\u0018\u00010\u0018H\u0014¢\u0006\u0004\b\u001a\u0010\u001bR\u001d\u0010!\u001a\u00020\u001c8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001d\u0010\u001e\u001a\u0004\b\u001f\u0010 R\u001d\u0010&\u001a\u00020\"8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b#\u0010\u001e\u001a\u0004\b$\u0010%¨\u0006)"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/comics/ComicsTableContentAllActivity;", "Lcom/jbzd/media/movecartoons/core/MyThemeActivity;", "", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/Chapter;", "mChapter", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "isBalanceEnough", "", "result", "checkMoneyForBuyChapter", "(Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/Chapter;Lkotlin/jvm/functions/Function1;)V", "bindEvent", "()V", "", "getTopBarTitle", "()Ljava/lang/String;", "", "getRightIconRes", "()I", "getLayoutId", "clickRightIcon", "Landroid/os/Bundle;", "savedInstanceState", "onCreate", "(Landroid/os/Bundle;)V", "com/jbzd/media/movecartoons/ui/comics/ComicsTableContentAllActivity$tableContentAdapter$2$1", "tableContentAdapter$delegate", "Lkotlin/Lazy;", "getTableContentAdapter", "()Lcom/jbzd/media/movecartoons/ui/comics/ComicsTableContentAllActivity$tableContentAdapter$2$1;", "tableContentAdapter", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;", "mComicsDetailInfoBean$delegate", "getMComicsDetailInfoBean", "()Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;", "mComicsDetailInfoBean", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ComicsTableContentAllActivity extends MyThemeActivity<Object> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: mComicsDetailInfoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy mComicsDetailInfoBean = LazyKt__LazyJVMKt.lazy(new Function0<ComicsDetailInfoBean>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsTableContentAllActivity$mComicsDetailInfoBean$2
        {
            super(0);
        }

        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ComicsDetailInfoBean invoke() {
            Serializable serializableExtra = ComicsTableContentAllActivity.this.getIntent().getSerializableExtra("comicsDetailInfo");
            Objects.requireNonNull(serializableExtra, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsDetailInfoBean");
            return (ComicsDetailInfoBean) serializableExtra;
        }
    });

    /* renamed from: tableContentAdapter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tableContentAdapter = LazyKt__LazyJVMKt.lazy(new ComicsTableContentAllActivity$tableContentAdapter$2(this));

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u001c\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u001d\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u0004¢\u0006\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/comics/ComicsTableContentAllActivity$Companion;", "", "Landroid/content/Context;", "context", "Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;", "comicsDetailInfoBean", "", "start", "(Landroid/content/Context;Lcom/jbzd/media/movecartoons/bean/response/comicsinfo/ComicsDetailInfoBean;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final void start(@NotNull Context context, @NotNull ComicsDetailInfoBean comicsDetailInfoBean) {
            Intrinsics.checkNotNullParameter(context, "context");
            Intrinsics.checkNotNullParameter(comicsDetailInfoBean, "comicsDetailInfoBean");
            Intent intent = new Intent(context, (Class<?>) ComicsTableContentAllActivity.class);
            intent.putExtra("comicsDetailInfo", comicsDetailInfoBean);
            Unit unit = Unit.INSTANCE;
            context.startActivity(intent);
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Removed duplicated region for block: B:10:0x0013  */
    /* JADX WARN: Removed duplicated region for block: B:12:0x0019  */
    /* JADX WARN: Removed duplicated region for block: B:15:0x0024  */
    /* JADX WARN: Removed duplicated region for block: B:19:0x0026  */
    /* JADX WARN: Removed duplicated region for block: B:20:0x001a A[Catch: Exception -> 0x001f, TRY_LEAVE, TryCatch #0 {Exception -> 0x001f, blocks: (B:8:0x000d, B:20:0x001a, B:22:0x0015), top: B:7:0x000d }] */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0015 A[Catch: Exception -> 0x001f, TryCatch #0 {Exception -> 0x001f, blocks: (B:8:0x000d, B:20:0x001a, B:22:0x0015), top: B:7:0x000d }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void checkMoneyForBuyChapter(com.jbzd.media.movecartoons.bean.response.comicsinfo.Chapter r5, kotlin.jvm.functions.Function1<? super java.lang.Boolean, kotlin.Unit> r6) {
        /*
            r4 = this;
            r0 = 0
            java.lang.String r5 = r5.money     // Catch: java.lang.Exception -> Lc
            if (r5 != 0) goto L7
            goto Lc
        L7:
            double r2 = java.lang.Double.parseDouble(r5)     // Catch: java.lang.Exception -> Lc
            goto Ld
        Lc:
            r2 = r0
        Ld:
            com.jbzd.media.movecartoons.MyApp r5 = com.jbzd.media.movecartoons.MyApp.f9891f     // Catch: java.lang.Exception -> L1f
            com.jbzd.media.movecartoons.bean.response.UserInfoBean r5 = com.jbzd.media.movecartoons.MyApp.f9892g     // Catch: java.lang.Exception -> L1f
            if (r5 != 0) goto L15
            r5 = 0
            goto L17
        L15:
            java.lang.String r5 = r5.balance     // Catch: java.lang.Exception -> L1f
        L17:
            if (r5 != 0) goto L1a
            goto L20
        L1a:
            double r0 = java.lang.Double.parseDouble(r5)     // Catch: java.lang.Exception -> L1f
            goto L20
        L1f:
        L20:
            int r5 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r5 < 0) goto L26
            r5 = 1
            goto L27
        L26:
            r5 = 0
        L27:
            java.lang.Boolean r5 = java.lang.Boolean.valueOf(r5)
            r6.invoke(r5)
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.comics.ComicsTableContentAllActivity.checkMoneyForBuyChapter(com.jbzd.media.movecartoons.bean.response.comicsinfo.Chapter, kotlin.jvm.functions.Function1):void");
    }

    /* JADX WARN: Multi-variable type inference failed */
    public static /* synthetic */ void checkMoneyForBuyChapter$default(ComicsTableContentAllActivity comicsTableContentAllActivity, Chapter chapter, Function1 function1, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            function1 = new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsTableContentAllActivity$checkMoneyForBuyChapter$1
                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                    invoke(bool.booleanValue());
                    return Unit.INSTANCE;
                }

                public final void invoke(boolean z) {
                }
            };
        }
        comicsTableContentAllActivity.checkMoneyForBuyChapter(chapter, function1);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ComicsDetailInfoBean getMComicsDetailInfoBean() {
        return (ComicsDetailInfoBean) this.mComicsDetailInfoBean.getValue();
    }

    private final ComicsTableContentAllActivity$tableContentAdapter$2.C36741 getTableContentAdapter() {
        return (ComicsTableContentAllActivity$tableContentAdapter$2.C36741) this.tableContentAdapter.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.MyThemeActivity, com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity
    public void _$_clearFindViewByIdCache() {
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    @SuppressLint({"SuspiciousIndentation"})
    public void bindEvent() {
        ComicsTableContentAllActivity$tableContentAdapter$2.C36741 tableContentAdapter = getTableContentAdapter();
        ArrayList<Chapter> arrayList = getMComicsDetailInfoBean().chapter;
        Intrinsics.checkNotNullExpressionValue(arrayList, "mComicsDetailInfoBean.chapter");
        tableContentAdapter.setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) arrayList));
        RecyclerView recyclerView = (RecyclerView) findViewById(R$id.rv_comics_chapterall);
        if (recyclerView.getItemDecorationCount() == 0) {
            GridItemDecoration.C4053a c4053a = new GridItemDecoration.C4053a(recyclerView.getContext());
            c4053a.m4576a(R.color.transparent);
            c4053a.f10339g = false;
            c4053a.f10340h = false;
            c4053a.f10338f = false;
            recyclerView.addItemDecoration(new GridItemDecoration(c4053a));
        }
        recyclerView.setAdapter(getTableContentAdapter());
        recyclerView.setLayoutManager(new GridLayoutManager(recyclerView.getContext(), 1));
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public void clickRightIcon() {
        for (Chapter chapter : getTableContentAdapter().getData()) {
        }
        List<Chapter> sortedWith = CollectionsKt___CollectionsKt.sortedWith(getTableContentAdapter().getData(), new Comparator() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsTableContentAllActivity$clickRightIcon$$inlined$compareBy$1
            /* JADX WARN: Multi-variable type inference failed */
            @Override // java.util.Comparator
            public final int compare(T t, T t2) {
                return ComparisonsKt__ComparisonsKt.compareValues(((Chapter) t).name, ((Chapter) t2).name);
            }
        });
        for (Chapter chapter2 : sortedWith) {
        }
        getTableContentAdapter().setNewData(CollectionsKt___CollectionsKt.toMutableList((Collection) sortedWith));
        getTableContentAdapter().notifyDataSetChanged();
    }

    @Override // p005b.p327w.p330b.p331b.p334e.InterfaceC2847j
    public int getLayoutId() {
        return R.layout.act_comics_tablecontentall;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    public int getRightIconRes() {
        return R.drawable.icon_right_order;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseActivity
    @NotNull
    public String getTopBarTitle() {
        String str = getMComicsDetailInfoBean().name;
        Intrinsics.checkNotNullExpressionValue(str, "mComicsDetailInfoBean.name");
        return str;
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseThemeActivity, com.qunidayede.supportlibrary.core.view.BaseActivity, androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ImmersionBar with = ImmersionBar.with(this);
        Intrinsics.checkExpressionValueIsNotNull(with, "this");
        with.statusBarDarkFont(true);
        with.init();
    }
}
