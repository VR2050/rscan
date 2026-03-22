package com.jbzd.media.movecartoons.p396ui.search;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.response.FindBean;
import com.jbzd.media.movecartoons.bean.response.tag.TagInfoBean;
import com.jbzd.media.movecartoons.p396ui.index.home.HomeDataHelper;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u000b\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0005\n\u0002\u0018\u0002\n\u0002\b\u0010\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b-\u0010\bJ\u0015\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u000f\u0010\u0007\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\t\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\t\u0010\bJ!\u0010\u000e\u001a\u00020\u00042\b\u0010\u000b\u001a\u0004\u0018\u00010\n2\b\b\u0002\u0010\r\u001a\u00020\f¢\u0006\u0004\b\u000e\u0010\u000fJD\u0010\u0015\u001a\u00020\u00042\b\u0010\u000b\u001a\u0004\u0018\u00010\n2\b\b\u0002\u0010\r\u001a\u00020\f2!\u0010\u0014\u001a\u001d\u0012\u0013\u0012\u00110\n¢\u0006\f\b\u0011\u0012\b\b\u0012\u0012\u0004\b\b(\u0013\u0012\u0004\u0012\u00020\u00040\u0010¢\u0006\u0004\b\u0015\u0010\u0016R#\u0010\u001d\u001a\b\u0012\u0004\u0012\u00020\u00180\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u0019\u0010\u001a\u001a\u0004\b\u001b\u0010\u001cR\u0018\u0010\u001f\u001a\u0004\u0018\u00010\u001e8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001f\u0010 R#\u0010#\u001a\b\u0012\u0004\u0012\u00020\u00020\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b!\u0010\u001a\u001a\u0004\b\"\u0010\u001cR#\u0010&\u001a\b\u0012\u0004\u0012\u00020\f0\u00178F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b$\u0010\u001a\u001a\u0004\b%\u0010\u001cR\"\u0010'\u001a\u00020\f8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b'\u0010(\u001a\u0004\b)\u0010*\"\u0004\b+\u0010,¨\u0006."}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/search/TagInfoModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "bg", "", "setBg", "(I)V", "onCreate", "()V", "onDestroy", "", "id", "", "hasLoading", "load", "(Ljava/lang/String;Z)V", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "result", "response", "doCollect", "(Ljava/lang/String;ZLkotlin/jvm/functions/Function1;)V", "Landroidx/lifecycle/MutableLiveData;", "Lcom/jbzd/media/movecartoons/bean/response/tag/TagInfoBean;", "infoBean$delegate", "Lkotlin/Lazy;", "getInfoBean", "()Landroidx/lifecycle/MutableLiveData;", "infoBean", "Lc/a/d1;", "job", "Lc/a/d1;", "tagDetailBg$delegate", "getTagDetailBg", "tagDetailBg", "collect$delegate", "getCollect", "collect", "tagDetailBgHasChange", "Z", "getTagDetailBgHasChange", "()Z", "setTagDetailBgHasChange", "(Z)V", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class TagInfoModel extends BaseViewModel {

    @Nullable
    private InterfaceC3053d1 job;
    private boolean tagDetailBgHasChange;

    /* renamed from: tagDetailBg$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy tagDetailBg = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Integer>>() { // from class: com.jbzd.media.movecartoons.ui.search.TagInfoModel$tagDetailBg$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Integer> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: infoBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy infoBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<TagInfoBean>>() { // from class: com.jbzd.media.movecartoons.ui.search.TagInfoModel$infoBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<TagInfoBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    /* renamed from: collect$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy collect = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<Boolean>>() { // from class: com.jbzd.media.movecartoons.ui.search.TagInfoModel$collect$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<Boolean> invoke() {
            return new MutableLiveData<>();
        }
    });

    public static /* synthetic */ void doCollect$default(TagInfoModel tagInfoModel, String str, boolean z, Function1 function1, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        tagInfoModel.doCollect(str, z, function1);
    }

    public static /* synthetic */ void load$default(TagInfoModel tagInfoModel, String str, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = true;
        }
        tagInfoModel.load(str, z);
    }

    public final void doCollect(@Nullable String id, final boolean hasLoading, @NotNull final Function1<? super String, Unit> response) {
        Intrinsics.checkNotNullParameter(response, "response");
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HomeDataHelper.doLove$default(HomeDataHelper.INSTANCE, id, HomeDataHelper.type_tag, null, new Function1<Object, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.TagInfoModel$doCollect$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Object obj) {
                invoke2(obj);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable Object obj) {
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                response.invoke(FindBean.status_success);
                this.getCollect().setValue(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.TagInfoModel$doCollect$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
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
                if (hasLoading) {
                    this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                }
                response.invoke("error");
                this.getCollect().setValue(Boolean.FALSE);
            }
        }, 4, null);
    }

    @NotNull
    public final MutableLiveData<Boolean> getCollect() {
        return (MutableLiveData) this.collect.getValue();
    }

    @NotNull
    public final MutableLiveData<TagInfoBean> getInfoBean() {
        return (MutableLiveData) this.infoBean.getValue();
    }

    @NotNull
    public final MutableLiveData<Integer> getTagDetailBg() {
        return (MutableLiveData) this.tagDetailBg.getValue();
    }

    public final boolean getTagDetailBgHasChange() {
        return this.tagDetailBgHasChange;
    }

    public final void load(@Nullable String id, boolean hasLoading) {
        if (hasLoading) {
            getLoading().setValue(new C2848a(true, null, false, false, 14));
        }
        HashMap hashMap = new HashMap();
        hashMap.put("id", id == null ? "" : id);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(C0917a.f372a, "tag/info", TagInfoBean.class, hashMap, new Function1<TagInfoBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.TagInfoModel$load$2
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
                TagInfoModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
                TagInfoModel.this.getInfoBean().setValue(tagInfoBean);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.search.TagInfoModel$load$3
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
                TagInfoModel.this.getLoading().setValue(new C2848a(false, null, false, false, 14));
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

    public final void setBg(int bg) {
        if (this.tagDetailBgHasChange) {
            return;
        }
        this.tagDetailBgHasChange = true;
        getTagDetailBg().setValue(Integer.valueOf(bg));
    }

    public final void setTagDetailBgHasChange(boolean z) {
        this.tagDetailBgHasChange = z;
    }
}
