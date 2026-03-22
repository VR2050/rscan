package com.jbzd.media.movecartoons.p396ui.search.child;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.response.tag.TagInfoBean;
import com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel;
import java.util.HashMap;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p327w.p330b.p331b.p335f.C2848a;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0004\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b\u0016\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J!\u0010\n\u001a\u00020\u00022\b\u0010\u0007\u001a\u0004\u0018\u00010\u00062\b\b\u0002\u0010\t\u001a\u00020\b¢\u0006\u0004\b\n\u0010\u000bR#\u0010\u0012\u001a\b\u0012\u0004\u0012\u00020\r0\f8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u000e\u0010\u000f\u001a\u0004\b\u0010\u0010\u0011R\u0018\u0010\u0014\u001a\u0004\u0018\u00010\u00138\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0014\u0010\u0015¨\u0006\u0017"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/child/InfoModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "onDestroy", "", "id", "", "hasLoading", "load", "(Ljava/lang/String;Z)V", "Landroidx/lifecycle/MutableLiveData;", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagInfoBean;", "infoBean$delegate", "Lkotlin/Lazy;", "getInfoBean", "()Landroidx/lifecycle/MutableLiveData;", "infoBean", "Lc/a/d1;", "job", "Lc/a/d1;", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class InfoModel extends BaseViewModel {

    /* renamed from: infoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy infoBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<TagInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.search.child.InfoModel$infoBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<TagInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    @Nullable
    private InterfaceC3053d1 job;

    public static /* synthetic */ void load$default(InfoModel infoModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        infoModel.load(str, z);
    }

    @NotNull
    public final MutableLiveData<TagInfoBean> getInfoBean() {
        return (MutableLiveData) this.infoBean.getValue();
    }

    public final void load(@Nullable String id, boolean hasLoading) {
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("id", id == null ? "" : id);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(C0917a.f372a, "tag/info", TagInfoBean.class, hashMap, new Function1<TagInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.InfoModel$load$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(TagInfoBean tagInfoBean) {
                invoke2(tagInfoBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable TagInfoBean tagInfoBean) {
                InfoModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                InfoModel.this.getInfoBean().setValue(tagInfoBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.child.InfoModel$load$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                InfoModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 480);
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.job);
    }
}
