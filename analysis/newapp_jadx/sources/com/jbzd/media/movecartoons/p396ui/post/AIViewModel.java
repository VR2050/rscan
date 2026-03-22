package com.jbzd.media.movecartoons.p396ui.post;

import androidx.lifecycle.MutableLiveData;
import com.jbzd.media.movecartoons.bean.response.AIPostConfigsBean;
import com.jbzd.media.movecartoons.bean.response.FindBean;
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
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p331b.p335f.C2848a;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00004\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0010\u000b\n\u0002\u0018\u0002\n\u0002\b\u000f\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\u0018\u00002\u00020\u0001B\u0007¢\u0006\u0004\b$\u0010\u0004J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u000f\u0010\u0005\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0005\u0010\u0004J\r\u0010\u0006\u001a\u00020\u0002¢\u0006\u0004\b\u0006\u0010\u0004JH\u0010\u0011\u001a\u00020\u00022\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\u00072\u0006\u0010\n\u001a\u00020\u00072!\u0010\u0010\u001a\u001d\u0012\u0013\u0012\u00110\f¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u000f\u0012\u0004\u0012\u00020\u00020\u000b¢\u0006\u0004\b\u0011\u0010\u0012JP\u0010\u0015\u001a\u00020\u00022\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\u00072\u0006\u0010\u0013\u001a\u00020\u00072\u0006\u0010\n\u001a\u00020\u00072!\u0010\u0014\u001a\u001d\u0012\u0013\u0012\u00110\f¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u0010\u0012\u0004\u0012\u00020\u00020\u000b¢\u0006\u0004\b\u0015\u0010\u0016JX\u0010\u0019\u001a\u00020\u00022\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\u00072\u0006\u0010\u0017\u001a\u00020\u00072\u0006\u0010\u0018\u001a\u00020\u00072\u0006\u0010\n\u001a\u00020\u00072!\u0010\u0014\u001a\u001d\u0012\u0013\u0012\u00110\f¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u0010\u0012\u0004\u0012\u00020\u00020\u000b¢\u0006\u0004\b\u0019\u0010\u001aJP\u0010\u001c\u001a\u00020\u00022\u0006\u0010\b\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\u00072\u0006\u0010\u001b\u001a\u00020\u00072\u0006\u0010\n\u001a\u00020\u00072!\u0010\u0014\u001a\u001d\u0012\u0013\u0012\u00110\f¢\u0006\f\b\r\u0012\b\b\u000e\u0012\u0004\b\b(\u0010\u0012\u0004\u0012\u00020\u00020\u000b¢\u0006\u0004\b\u001c\u0010\u0016R#\u0010#\u001a\b\u0012\u0004\u0012\u00020\u001e0\u001d8F@\u0006X\u0086\u0084\u0002¢\u0006\f\n\u0004\b\u001f\u0010 \u001a\u0004\b!\u0010\"¨\u0006%"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/post/AIViewModel;", "Lcom/qunidayede/supportlibrary/core/viewmodel/BaseViewModel;", "", "onCreate", "()V", "onDestroy", "postAiConfigs", "", "content", "images", "is_public", "Lkotlin/Function1;", "", "Lkotlin/ParameterName;", "name", "bool", FindBean.status_success, "postDoQuyi", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function1;)V", "source_images", "resultCallback", "postDoChange", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function1;)V", "video_image", "video_value", "postDoChangeVideo", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lkotlin/jvm/functions/Function1;)V", "num", "postDoHuihua", "Landroidx/lifecycle/MutableLiveData;", "Lcom/jbzd/media/movecartoons/bean/response/AIPostConfigsBean;", "aIPostConfigsBean$delegate", "Lkotlin/Lazy;", "getAIPostConfigsBean", "()Landroidx/lifecycle/MutableLiveData;", "aIPostConfigsBean", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class AIViewModel extends BaseViewModel {

    /* renamed from: aIPostConfigsBean$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy aIPostConfigsBean = LazyKt__LazyJVMKt.lazy(new Function0<MutableLiveData<AIPostConfigsBean>>() { // from class: com.jbzd.media.movecartoons.ui.post.AIViewModel$aIPostConfigsBean$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final MutableLiveData<AIPostConfigsBean> invoke() {
            return new MutableLiveData<>();
        }
    });

    @NotNull
    public final MutableLiveData<AIPostConfigsBean> getAIPostConfigsBean() {
        return (MutableLiveData) this.aIPostConfigsBean.getValue();
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onCreate() {
    }

    @Override // com.qunidayede.supportlibrary.core.viewmodel.BaseViewModel
    public void onDestroy() {
        super.onDestroy();
    }

    public final void postAiConfigs() {
        C0917a.m221e(C0917a.f372a, "post/aiConfigs", AIPostConfigsBean.class, new HashMap(), new Function1<AIPostConfigsBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.AIViewModel$postAiConfigs$1
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(AIPostConfigsBean aIPostConfigsBean) {
                invoke2(aIPostConfigsBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable AIPostConfigsBean aIPostConfigsBean) {
                if (aIPostConfigsBean != null) {
                    AIViewModel.this.getAIPostConfigsBean().setValue(aIPostConfigsBean);
                }
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.AIViewModel$postAiConfigs$2
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 480);
    }

    public final void postDoChange(@NotNull String content, @NotNull String images, @NotNull String source_images, @NotNull String is_public, @NotNull final Function1<? super Boolean, Unit> resultCallback) {
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(images, "images");
        Intrinsics.checkNotNullParameter(source_images, "source_images");
        Intrinsics.checkNotNullParameter(is_public, "is_public");
        Intrinsics.checkNotNullParameter(resultCallback, "resultCallback");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("content", content, "images", images);
        m596R.put("source_images", source_images);
        m596R.put("is_public", is_public);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "post/doChange", String.class, m596R, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.AIViewModel$postDoChange$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                resultCallback.invoke(Boolean.TRUE);
                C2354n.m2409L1("发布成功");
                this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.AIViewModel$postDoChange$3
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
                resultCallback.invoke(Boolean.FALSE);
                C2354n.m2379B1("发布失败");
                this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 480);
    }

    public final void postDoChangeVideo(@NotNull String content, @NotNull String images, @NotNull String video_image, @NotNull String video_value, @NotNull String is_public, @NotNull final Function1<? super Boolean, Unit> resultCallback) {
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(images, "images");
        Intrinsics.checkNotNullParameter(video_image, "video_image");
        Intrinsics.checkNotNullParameter(video_value, "video_value");
        Intrinsics.checkNotNullParameter(is_public, "is_public");
        Intrinsics.checkNotNullParameter(resultCallback, "resultCallback");
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("content", content, "images", images);
        m596R.put("video_image", video_image);
        m596R.put("video_value", video_value);
        m596R.put("is_public", is_public);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "post/doChangeVideo", String.class, m596R, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.AIViewModel$postDoChangeVideo$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                C2354n.m2409L1("发布成功");
                resultCallback.invoke(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.AIViewModel$postDoChangeVideo$3
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
                resultCallback.invoke(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    public final void postDoHuihua(@NotNull String content, @NotNull String images, @NotNull String num, @NotNull String is_public, @NotNull final Function1<? super Boolean, Unit> resultCallback) {
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(images, "images");
        Intrinsics.checkNotNullParameter(num, "num");
        Intrinsics.checkNotNullParameter(is_public, "is_public");
        Intrinsics.checkNotNullParameter(resultCallback, "resultCallback");
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("content", content, "images", images);
        m596R.put("num", num);
        m596R.put("is_public", is_public);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "post/doHuihua", String.class, m596R, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.AIViewModel$postDoHuihua$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                C2354n.m2409L1("发布成功");
                resultCallback.invoke(Boolean.TRUE);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.AIViewModel$postDoHuihua$3
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
                resultCallback.invoke(Boolean.FALSE);
            }
        }, false, false, null, false, 480);
    }

    public final void postDoQuyi(@NotNull String content, @NotNull String images, @NotNull String is_public, @NotNull final Function1<? super Boolean, Unit> success) {
        Intrinsics.checkNotNullParameter(content, "content");
        Intrinsics.checkNotNullParameter(images, "images");
        Intrinsics.checkNotNullParameter(is_public, "is_public");
        Intrinsics.checkNotNullParameter(success, "success");
        getLoading().setValue(new C2848a(true, null, false, false, 14));
        C0917a c0917a = C0917a.f372a;
        HashMap m596R = C1499a.m596R("content", content, "images", images);
        m596R.put("is_public", is_public);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "post/doQuyi", String.class, m596R, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.AIViewModel$postDoQuyi$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            /* JADX WARN: Multi-variable type inference failed */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                success.invoke(Boolean.TRUE);
                C2354n.m2409L1("发布成功");
                this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.post.AIViewModel$postDoQuyi$3
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
                success.invoke(Boolean.FALSE);
                C2354n.m2449Z("发布失败");
                this.getLoading().setValue(new C2848a(false, null, false, false, 14));
            }
        }, false, false, null, false, 480);
    }
}
