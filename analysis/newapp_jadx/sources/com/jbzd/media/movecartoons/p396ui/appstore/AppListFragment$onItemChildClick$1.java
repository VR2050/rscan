package com.jbzd.media.movecartoons.p396ui.appstore;

import android.app.DownloadManager;
import android.net.Uri;
import android.os.Environment;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.AppItemNew;
import java.io.File;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0869q;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p325v.p326a.C2818e;
import p379c.p380a.AbstractC3077l1;
import p379c.p380a.C3079m0;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p381a.C2964m;
import p426f.p427a.p428a.C4325a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
@DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.appstore.AppListFragment$onItemChildClick$1", m5320f = "AppStoreActivity.kt", m5321i = {}, m5322l = {220, 221}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
/* loaded from: classes2.dex */
public final class AppListFragment$onItemChildClick$1 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
    public final /* synthetic */ BaseQuickAdapter<AppItemNew, BaseViewHolder> $adapter;
    public final /* synthetic */ AppItemNew $item;
    public final /* synthetic */ int $position;
    public int label;
    public final /* synthetic */ AppListFragment this$0;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
    @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.appstore.AppListFragment$onItemChildClick$1$1", m5320f = "AppStoreActivity.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
    /* renamed from: com.jbzd.media.movecartoons.ui.appstore.AppListFragment$onItemChildClick$1$1 */
    public static final class C36521 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
        public final /* synthetic */ BaseQuickAdapter<AppItemNew, BaseViewHolder> $adapter;
        public final /* synthetic */ AppItemNew $item;
        public final /* synthetic */ int $position;
        public int label;
        public final /* synthetic */ AppListFragment this$0;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public C36521(AppListFragment appListFragment, AppItemNew appItemNew, BaseQuickAdapter<AppItemNew, BaseViewHolder> baseQuickAdapter, int i2, Continuation<? super C36521> continuation) {
            super(2, continuation);
            this.this$0 = appListFragment;
            this.$item = appItemNew;
            this.$adapter = baseQuickAdapter;
            this.$position = i2;
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @NotNull
        public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
            return new C36521(this.this$0, this.$item, this.$adapter, this.$position, continuation);
        }

        @Override // kotlin.jvm.functions.Function2
        @Nullable
        public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
            return ((C36521) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
        }

        @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
        @Nullable
        public final Object invokeSuspend(@NotNull Object obj) {
            IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
            if (this.label != 0) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            ResultKt.throwOnFailure(obj);
            final AppListFragment appListFragment = this.this$0;
            final AppItemNew appItemNew = this.$item;
            final BaseQuickAdapter<AppItemNew, BaseViewHolder> baseQuickAdapter = this.$adapter;
            final int i2 = this.$position;
            appListFragment.permissionCheck(new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.appstore.AppListFragment.onItemChildClick.1.1.1
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                    invoke(bool.booleanValue());
                    return Unit.INSTANCE;
                }

                public final void invoke(boolean z) {
                    C0869q downloadUtils;
                    if (!z) {
                        C4325a.m4899b(appListFragment.requireContext(), "没有权限").show();
                        return;
                    }
                    C2354n.m2409L1("正在下载…");
                    AppItemNew appItemNew2 = AppItemNew.this;
                    downloadUtils = appListFragment.getDownloadUtils();
                    String url = AppItemNew.this.android_url;
                    Intrinsics.checkNotNullExpressionValue(url, "item.android_url");
                    String title = AppItemNew.this.name;
                    Intrinsics.checkNotNullExpressionValue(title, "item.name");
                    Objects.requireNonNull(downloadUtils);
                    Intrinsics.checkNotNullParameter(url, "url");
                    Intrinsics.checkNotNullParameter(title, "title");
                    DownloadManager.Request request = new DownloadManager.Request(Uri.parse(url));
                    request.setAllowedOverRoaming(true);
                    request.setNotificationVisibility(1);
                    request.setTitle(title);
                    request.setDescription(Intrinsics.stringPlus(title, "下载中..."));
                    request.setVisibleInDownloadsUi(true);
                    request.setMimeType("application/vnd.android.package-archive");
                    File file = new File(Environment.getExternalStorageDirectory(), Intrinsics.stringPlus(title, ".apk"));
                    if (file.exists()) {
                        file.delete();
                    }
                    C2818e.f7655a.m3277c(6, null, file.getAbsoluteFile().toString(), new Object[0]);
                    request.setDestinationUri(Uri.fromFile(file));
                    if (downloadUtils.f308b == null) {
                        Object systemService = downloadUtils.f307a.getSystemService("download");
                        Objects.requireNonNull(systemService, "null cannot be cast to non-null type android.app.DownloadManager");
                        downloadUtils.f308b = (DownloadManager) systemService;
                    }
                    DownloadManager downloadManager = downloadUtils.f308b;
                    Intrinsics.checkNotNull(downloadManager);
                    appItemNew2.downloadId = downloadManager.enqueue(request);
                    baseQuickAdapter.setData(i2, AppItemNew.this);
                }
            });
            this.this$0.hideLoadingDialog();
            return Unit.INSTANCE;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AppListFragment$onItemChildClick$1(AppListFragment appListFragment, AppItemNew appItemNew, BaseQuickAdapter<AppItemNew, BaseViewHolder> baseQuickAdapter, int i2, Continuation<? super AppListFragment$onItemChildClick$1> continuation) {
        super(2, continuation);
        this.this$0 = appListFragment;
        this.$item = appItemNew;
        this.$adapter = baseQuickAdapter;
        this.$position = i2;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @NotNull
    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
        return new AppListFragment$onItemChildClick$1(this.this$0, this.$item, this.$adapter, this.$position, continuation);
    }

    @Override // kotlin.jvm.functions.Function2
    @Nullable
    public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
        return ((AppListFragment$onItemChildClick$1) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    @Nullable
    public final Object invokeSuspend(@NotNull Object obj) {
        Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
        int i2 = this.label;
        if (i2 == 0) {
            ResultKt.throwOnFailure(obj);
            this.label = 1;
            if (C2354n.m2422Q(1000L, this) == coroutine_suspended) {
                return coroutine_suspended;
            }
        } else {
            if (i2 != 1) {
                if (i2 != 2) {
                    throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                }
                ResultKt.throwOnFailure(obj);
                return Unit.INSTANCE;
            }
            ResultKt.throwOnFailure(obj);
        }
        C3079m0 c3079m0 = C3079m0.f8432c;
        AbstractC3077l1 abstractC3077l1 = C2964m.f8127b;
        C36521 c36521 = new C36521(this.this$0, this.$item, this.$adapter, this.$position, null);
        this.label = 2;
        if (C2354n.m2471e2(abstractC3077l1, c36521, this) == coroutine_suspended) {
            return coroutine_suspended;
        }
        return Unit.INSTANCE;
    }
}
